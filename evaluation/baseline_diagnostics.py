"""Read-only artifact lineage diagnostics and durable experiment-attempt logging."""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import ValidationError

SECRET_PATTERNS = (
    (re.compile(r"(?i)(bearer\s+)[A-Za-z0-9._~+/=-]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(token\s*[=:]\s*)[^\s,;]+"), r"\1[REDACTED]"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b"), "[REDACTED]"),
)

STAGE_NAMES = (
    "raw_finding",
    "normalized_finding",
    "source_endpoint_binding",
    "action_proposal",
    "validation",
    "execution",
    "persisted_evidence",
    "final_report",
)

# A stage name becomes an output file name inside the attempt directory. Only a
# plain token is allowed so stdout/stderr can never be written outside it.
_SAFE_STAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_CREDENTIAL_KEY_SUFFIXES = (
    "apikey",
    "authorization",
    "clientsecret",
    "credential",
    "credentials",
    "key",
    "passwd",
    "password",
    "secret",
    "token",
)


def redact_text(value: str) -> str:
    """Remove common credential-shaped substrings without changing other text."""
    for pattern, replacement in SECRET_PATTERNS:
        value = pattern.sub(replacement, value)
    return value


def _is_credential_key(name: str) -> bool:
    joined = re.sub(r"[^a-z0-9]", "", name.lower())
    return any(joined.endswith(suffix) for suffix in _CREDENTIAL_KEY_SUFFIXES)


def redact_value(value: Any) -> Any:
    """Redact credential-shaped text and credential-named string fields in metadata."""
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, child in value.items():
            name = redact_text(str(key))
            if _is_credential_key(name) and isinstance(child, str) and child:
                result[name] = "[REDACTED]"
            else:
                result[name] = redact_value(child)
        return result
    if isinstance(value, (list, tuple, set)):
        return [redact_value(item) for item in value]
    return value


def validate_stage_name(stage: str) -> str:
    """Accept only a safe file-name token so stage output stays inside the attempt."""
    if not isinstance(stage, str) or not _SAFE_STAGE.fullmatch(stage) or ".." in stage:
        raise ValueError(
            "stage must be a safe name without path separators, '..' or absolute paths"
        )
    return stage


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def create_attempt(
    directory: Path,
    *,
    kind: str,
    target: str,
    configuration: dict[str, Any],
    command: Iterable[str],
) -> dict[str, Any]:
    """Create attempt identity and durable metadata before any preflight starts."""
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    if (directory / "attempt.json").exists() or any(
        item.name not in {"juice-shop"} for item in directory.iterdir()
    ):
        raise FileExistsError(f"attempt directory is not empty: {directory.name}")
    attempt = {
        "attempt_id": directory.name,
        "kind": kind,
        "target": target,
        "created_at": datetime.now(UTC).isoformat(),
        "status": "CREATED",
        "configuration": redact_value(configuration),
        "command": [redact_text(str(part)) for part in command],
        "events": [],
    }
    _write_json(directory / "attempt.json", attempt)
    return attempt


def run_attempt_stage(
    directory: Path,
    *,
    stage: str,
    command: Iterable[str],
    timeout_seconds: float = 3600,
    cwd: Path | None = None,
) -> dict[str, Any]:
    """Run an existing project entrypoint and preserve every stage outcome."""
    directory = directory.resolve()
    validate_stage_name(stage)
    metadata_path = directory / "attempt.json"
    if not metadata_path.is_file():
        raise FileNotFoundError("attempt.json is required before running a stage")
    attempt = json.loads(metadata_path.read_text(encoding="utf-8"))
    if any(event.get("stage") == stage for event in attempt.get("events", [])):
        raise FileExistsError(f"stage already recorded for attempt: {stage}")
    argv = [str(part) for part in command]
    if not argv:
        raise ValueError("command must not be empty")
    event = {
        "event_id": str(uuid4()),
        "stage": stage,
        "status": "RUNNING",
        "started_at": datetime.now(UTC).isoformat(),
        "command": [redact_text(part) for part in argv],
    }
    attempt["events"].append(event)
    attempt["status"] = "RUNNING"
    _write_json(metadata_path, attempt)
    start = time.monotonic()
    launch_failure = False
    try:
        try:
            process = subprocess.Popen(
                argv,
                cwd=str(cwd) if cwd else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False,
                env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                start_new_session=(os.name == "posix"),
            )
        except OSError as exc:
            # The child never started: keep the failure as an explicit launch
            # failure with no exit code instead of a timeout or scored result.
            launch_failure = True
            stdout = ""
            stderr = f"Launch failed before process creation: {type(exc).__name__}: {redact_text(str(exc))}"
            exit_code = None
            status = "PREFLIGHT_FAILED" if stage == "preflight" else "FAILED"
            timed_out = False
        else:
            try:
                raw_stdout, raw_stderr = process.communicate(timeout=timeout_seconds)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        raw_stdout, raw_stderr = process.communicate(timeout=5)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        raw_stdout, raw_stderr = process.communicate()
                else:
                    process.kill()
                    raw_stdout, raw_stderr = process.communicate()
                raise subprocess.TimeoutExpired(argv, timeout_seconds, output=raw_stdout, stderr=raw_stderr)
            stdout = redact_text(raw_stdout)
            stderr = redact_text(raw_stderr)
            exit_code = process.returncode
            status = "COMPLETED" if exit_code == 0 else "PREFLIGHT_FAILED" if stage == "preflight" else "FAILED"
            timed_out = False
    except subprocess.TimeoutExpired as exc:
        stdout = redact_text(exc.stdout.decode(errors="replace") if isinstance(exc.stdout, bytes) else exc.stdout or "")
        stderr = redact_text(exc.stderr.decode(errors="replace") if isinstance(exc.stderr, bytes) else exc.stderr or "")
        exit_code = None
        status = "PREFLIGHT_FAILED" if stage == "preflight" else "FAILED"
        timed_out = True
        stderr = (stderr + "\nTimed out after configured wall-clock budget.").strip()
    duration = round(time.monotonic() - start, 3)
    (directory / f"{stage}.stdout.txt").write_text(stdout, encoding="utf-8")
    (directory / f"{stage}.stderr.txt").write_text(stderr, encoding="utf-8")
    event.update(
        {
            "status": status,
            "finished_at": datetime.now(UTC).isoformat(),
            "duration_seconds": duration,
            "exit_code": exit_code,
            "timed_out": timed_out,
            "launch_failure": launch_failure,
            "stdout_file": f"{stage}.stdout.txt",
            "stderr_file": f"{stage}.stderr.txt",
        }
    )
    attempt["status"] = status
    _write_json(metadata_path, attempt)
    return event


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return f"external-artifact/{path.name}"


def _stage_for_path(path: Path) -> str | None:
    text = path.as_posix().lower()
    name = path.name.lower()
    if name == "semgrep.json" or "sast-raw" in name:
        return "raw_finding"
    if name == "raw-findings.json" and (path.parent / "pipeline").is_dir():
        return "normalized_finding"
    if "raw-finding" in name or "raw_findings" in name or "sast-raw" in name:
        return "raw_finding"
    if name in {"findings.json", "matches.json"} or "/normalized/" in text:
        return "normalized_finding"
    if "runtime-service-map" in name or "source-map" in name or "binding" in name:
        return "source_endpoint_binding"
    if name == "fix-verification.json":
        return "persisted_evidence"
    if name.startswith("confirmed-report"):
        return "final_report"
    if "proposal" in name or "action" in name and "audit" not in text:
        return "action_proposal"
    if "executor.jsonl" in name or name == "audit.jsonl" or "validation" in name or "validator" in name:
        return "validation"
    if "/evidence/" in text:
        return "execution" if name.startswith("execution-") else "persisted_evidence"
    if "/reports/" in text or name in {"report.json", "final-report.json", "final_report.json"}:
        return "final_report"
    if "execution" in name or "executor" in name:
        return "execution"
    return None


def _walk_records(value: Any, location: str = "$") -> Iterable[tuple[str, dict[str, Any]]]:
    if isinstance(value, dict):
        yield location, value
        for key, child in value.items():
            yield from _walk_records(child, f"{location}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_records(child, f"{location}[{index}]")


def _identity(record: dict[str, Any]) -> str | None:
    for key in ("finding_id", "canonical_id"):
        value = record.get(key)
        if isinstance(value, str) and value:
            return value
    value = record.get("id")
    if (
        isinstance(value, str)
        and value
        and (isinstance(record.get("file"), str) or isinstance(record.get("artifact"), str))
        and (record.get("rule_id") or record.get("source") or record.get("family"))
    ):
        return value
    finding = record.get("finding")
    if isinstance(finding, dict):
        value = finding.get("id") or finding.get("finding_id")
        return value if isinstance(value, str) else None
    original_finding = record.get("original_finding")
    if isinstance(original_finding, dict) and isinstance(original_finding.get("id"), str):
        return original_finding["id"]
    return None


def diagnose_artifacts(artifact_root: Path, *, target: str) -> dict[str, Any]:
    """Build a conservative lineage journal from files already on disk."""
    root = artifact_root.resolve()
    observations: list[dict[str, Any]] = []
    unreadable: list[dict[str, str]] = []
    schema_issues: list[dict[str, str]] = []
    missing_references: list[dict[str, str]] = []
    action_to_finding: dict[str, str] = {}
    paths = [p for p in root.rglob("*") if p.is_file()]
    canonical_locations: dict[tuple[str, int], set[str]] = {}
    for source_path in paths:
        if _stage_for_path(source_path) not in {"normalized_finding", "final_report"} or source_path.suffix.lower() != ".json":
            continue
        try:
            source_values = [json.loads(source_path.read_text(encoding="utf-8"))]
        except (OSError, json.JSONDecodeError):
            continue
        for source_value in source_values:
            for _, source_record in _walk_records(source_value):
                identity = _identity(source_record)
                file_name = source_record.get("file")
                line = source_record.get("line_start")
                if identity and isinstance(file_name, str) and isinstance(line, int):
                    canonical_locations.setdefault((Path(file_name).as_posix(), line), set()).add(identity)
    for path in sorted(
        paths,
        key=lambda item: (
            0
            if "/reports/" in item.as_posix().lower()
            or item.name.lower() in {"confirmed-report.json", "fix-verification.json"}
            else 1,
            item.as_posix(),
        ),
    ):
        stage = _stage_for_path(path)
        if stage is None or path.suffix.lower() not in {".json", ".jsonl"}:
            continue
        try:
            if path.suffix.lower() == ".jsonl":
                values = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
            else:
                values = [json.loads(path.read_text(encoding="utf-8"))]
        except (OSError, json.JSONDecodeError) as exc:
            unreadable.append({"artifact": _relative(path, root), "error": redact_text(str(exc)), "status": "unresolved"})
            continue
        for value in values:
            if not isinstance(value, (dict, list)):
                continue
            records = list(_walk_records(value))
            for _, record in records:
                finding_id = _identity(record)
                if not isinstance(finding_id, str):
                    continue
                verification = record.get("verification")
                if isinstance(verification, dict) and isinstance(verification.get("action_id"), str):
                    action_to_finding[verification["action_id"]] = finding_id
                for evidence_key in ("before_evidence", "after_evidence"):
                    evidence_item = record.get(evidence_key)
                    if isinstance(evidence_item, dict) and isinstance(evidence_item.get("action_id"), str):
                        action_to_finding[evidence_item["action_id"]] = finding_id
                for evidence in record.get("evidence", []) if isinstance(record.get("evidence"), list) else []:
                    if isinstance(evidence, dict) and isinstance(evidence.get("action_id"), str):
                        action_to_finding[evidence["action_id"]] = finding_id
            for location, record in records:
                if {"action_id", "type"}.issubset(record) and (
                    _stage_for_path(path) == "final_report"
                    or "summary" in record
                    or "reliability" in record
                    or "artifact_refs" in record
                ):
                    try:
                        from schemas.evidence import Evidence

                        Evidence.model_validate(record)
                    except (ValidationError, ValueError) as exc:
                        schema_issues.append(
                            {
                                "artifact": _relative(path, root),
                                "record_path": location,
                                "error": redact_text(str(exc)),
                                "status": "unresolved",
                            }
                        )
                refs = record.get("artifact_refs")
                if isinstance(refs, list):
                    for ref in refs:
                        if not isinstance(ref, str) or not ref or ":" in ref and not ref.startswith("/"):
                            continue
                        if not (ref.startswith("/") or "/" in ref or ref.endswith((".json", ".jsonl"))):
                            continue
                        candidate = Path(ref)
                        if not candidate.is_absolute():
                            candidate = root / candidate
                        if not candidate.is_file():
                            missing_references.append(
                                {
                                    "artifact": _relative(path, root),
                                    "reference": redact_text(ref),
                                    "status": "unresolved",
                                }
                            )
                identity = _identity(record)
                raw_anchor = None
                if identity is None and isinstance(record.get("check_id"), str) and isinstance(record.get("path"), str):
                    start_data = record.get("start")
                    line = start_data.get("line") if isinstance(start_data, dict) else None
                    if isinstance(line, int):
                        raw_path = Path(record["path"]).as_posix()
                        compatible = {
                            candidate
                            for (source_file, source_line), candidates in canonical_locations.items()
                            if source_line == line
                            and (raw_path.endswith("/" + source_file) or raw_path == source_file)
                            for candidate in candidates
                        }
                        if len(compatible) == 1:
                            identity = next(iter(compatible))
                            raw_anchor = f"{record['check_id']}:{raw_path}:{line}"
                action_id = record.get("action_id")
                if identity is None and isinstance(action_id, str):
                    identity = action_to_finding.get(action_id)
                if not identity:
                    continue
                record_stage = stage
                if stage == "final_report" and ".evidence[" in location and {"action_id", "type"}.issubset(record):
                    record_stage = "persisted_evidence"
                elif (
                    stage == "final_report"
                    and ".finding" in location
                    and isinstance(record.get("file"), str)
                    and (record.get("rule_id") or record.get("source"))
                ):
                    record_stage = "normalized_finding"
                observations.append(
                    {
                        "finding_id": identity,
                        "aliases": (
                            record.get("aliases", []) if isinstance(record.get("aliases", []), list) else []
                        )
                        + (
                            record.get("provenance", {}).get("aliases", [])
                            if isinstance(record.get("provenance"), dict)
                            and isinstance(record.get("provenance", {}).get("aliases", []), list)
                            else []
                        )
                        + ([raw_anchor] if raw_anchor else []),
                        "stage": record_stage,
                        "artifact": _relative(path, root),
                        "record_path": location,
                        "action_id": action_id,
                        "run_id": record.get("run_id"),
                        "session_id": record.get("session_id") or record.get("sandbox_session_id"),
                        "status": record.get("status") or record.get("verdict") or "observed",
                    }
                )
                trusted_binding = record.get("trusted_binding")
                if isinstance(trusted_binding, dict):
                    observations.append(
                        {
                            "finding_id": identity,
                            "aliases": [],
                            "stage": "source_endpoint_binding",
                            "artifact": _relative(path, root),
                            "record_path": location + ".trusted_binding",
                            "action_id": None,
                            "run_id": record.get("run_id"),
                            "session_id": None,
                            "status": "observed",
                            "binding": trusted_binding,
                        }
                    )
                observation = record.get("observation")
                if record_stage == "persisted_evidence" and isinstance(observation, dict):
                    facts = observation.get("facts")
                    fact_records = [fact for _, fact in _walk_records(facts)] if isinstance(facts, (dict, list)) else []
                    endpoint = next((fact.get("endpoint") for fact in fact_records if isinstance(fact.get("endpoint"), str)), None)
                    source_file = next((fact.get("file") for fact in fact_records if isinstance(fact.get("file"), str)), None)
                    source_digest = next((fact.get("source_sha256") for fact in fact_records if isinstance(fact.get("source_sha256"), str)), None)
                    if endpoint or source_file and source_digest:
                        observations.append(
                            {
                                "finding_id": identity,
                                "aliases": [],
                                "stage": "source_endpoint_binding",
                                "artifact": _relative(path, root),
                                "record_path": location + ".observation",
                                "action_id": action_id,
                                "run_id": record.get("run_id"),
                                "session_id": record.get("sandbox_session_id"),
                                "status": "observed",
                                "binding": {"endpoint": endpoint, "file": source_file, "source_sha256": source_digest},
                            }
                        )

    groups: dict[str, list[dict[str, Any]]] = {}
    for item in observations:
        groups.setdefault(item["finding_id"], []).append(item)
    findings = []
    for finding_id, rows in sorted(groups.items()):
        stages = {row["stage"] for row in rows}
        aliases = sorted({alias for row in rows for alias in row["aliases"] if isinstance(alias, str)})
        chain = []
        for stage in STAGE_NAMES:
            matches = [row for row in rows if row["stage"] == stage]
            chain.append(
                {
                    "stage": stage,
                    "status": "observed" if matches else "missing",
                    "observations": matches,
                }
            )
        reasons = []
        for row in rows:
            text = str(row.get("status", "")).lower()
            if "deny" in text or "deni" in text or "blocked" in text:
                reasons.append({"category": "permission", "evidence": row["status"], "status": "explained"})
            elif "timeout" in text or "time out" in text:
                reasons.append({"category": "timeout", "evidence": row["status"], "status": "explained"})
        if "source_endpoint_binding" not in stages and "raw_finding" in stages:
            reasons.append({"category": "binding", "evidence": "No binding artifact observed for this finding.", "status": "unresolved"})
        if "raw_finding" not in stages and "normalized_finding" in stages:
            reasons.append(
                {
                    "category": "source path",
                    "evidence": "A normalized Finding is present, but no raw scanner/candidate record is linked to it.",
                    "status": "unresolved",
                }
            )
        if "action_proposal" not in stages and "validation" in stages:
            reasons.append(
                {
                    "category": "binding",
                    "evidence": "Downstream records expose action_id, but no serialized canonical ActionProposal was found.",
                    "status": "unresolved",
                }
            )
        if "persisted_evidence" not in stages and "final_report" in stages:
            reasons.append({"category": "Evidence schema/interpretation", "evidence": "Report exists without a matching persisted-evidence observation.", "status": "unresolved"})
        if not any(reason["category"] == "unresolved" for reason in reasons):
            reasons.append({"category": "unresolved", "evidence": "Artifact presence alone does not establish a causal failure.", "status": "unresolved"})
        findings.append({"finding_id": finding_id, "aliases": aliases, "chain": chain, "reasons": reasons})

    return {
        "schema_version": "k02-baseline-diagnostics-v1",
        "target": target,
        "artifact_root": str(root),
        "classification": "artifact_diagnostic_not_a_run",
        "findings": findings,
        "unreadable_artifacts": unreadable,
        "evidence_schema_issues": schema_issues,
        "missing_artifact_references": missing_references,
        "observation_count": len(observations),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    diagnose_parser = subparsers.add_parser("diagnose", help="read-only artifact lineage scan")
    diagnose_parser.add_argument("--artifacts", required=True, type=Path)
    diagnose_parser.add_argument("--target", required=True)
    diagnose_parser.add_argument("--output", type=Path)
    begin_parser = subparsers.add_parser("begin", help="create durable attempt ID before preflight")
    begin_parser.add_argument("--attempt-dir", required=True, type=Path)
    begin_parser.add_argument("--kind", required=True, choices=("stage2-v1", "stage1"))
    begin_parser.add_argument("--target", required=True)
    begin_parser.add_argument("--configuration", required=True, type=Path)
    begin_parser.add_argument("command", nargs=argparse.REMAINDER)
    run_parser = subparsers.add_parser("run", help="record a command outcome under an existing attempt")
    run_parser.add_argument("--attempt-dir", required=True, type=Path)
    run_parser.add_argument("--stage", required=True)
    run_parser.add_argument("--timeout-seconds", type=float, default=3600)
    run_parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.operation == "diagnose":
        report = diagnose_artifacts(args.artifacts, target=args.target)
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    elif args.operation == "begin":
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        attempt = create_attempt(
            args.attempt_dir,
            kind=args.kind,
            target=args.target,
            configuration=json.loads(args.configuration.read_text(encoding="utf-8")),
            command=command,
        )
        print(json.dumps({"attempt_id": attempt["attempt_id"], "status": attempt["status"]}))
    else:
        command = args.command[1:] if args.command[:1] == ["--"] else args.command
        event = run_attempt_stage(
            args.attempt_dir,
            stage=args.stage,
            command=command,
            timeout_seconds=args.timeout_seconds,
            cwd=Path.cwd(),
        )
        print(json.dumps(event, sort_keys=True))
        return 2 if event["exit_code"] is None else int(event["exit_code"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
