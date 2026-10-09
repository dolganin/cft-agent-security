"""Artifact adapter and frozen, resumable orchestration around the canonical CI flow."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path

import yaml
from pydantic import BaseModel

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.config import settings
from evaluation.benchmark import aggregate, family, normalize_path, score
from executor.sandbox_audit import calculate_sha256_digest
from schemas.benchmark import BenchmarkDataset, BenchmarkObservation, BenchmarkRunResult
from schemas.finding import Finding
from schemas.report import FinalReport
from schemas.target import TargetProfile
from security.error_redaction import redact_error_message

ROOT = Path(__file__).resolve().parents[1]
SETTING_NAMES = (
    "agent_mode",
    "llm_routes",
    "llm_reasoning_effort",
    "llm_max_output_tokens",
    "llm_timeout_seconds",
    "scout_max_turns",
    "scout_max_candidates",
    "scout_max_source_chars",
    "scout_wall_clock_seconds",
    "agent_wall_clock_seconds",
    "executor_timeout_seconds",
    "executor_cpu_time_seconds",
    "executor_memory_mb",
    "executor_max_file_bytes",
    "executor_max_processes",
    "executor_max_output_bytes",
    "executor_max_runs_per_action",
    "executor_max_concurrent_runs",
    "llm_allow_external_fallbacks",
    "sandbox_image",
)


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def json_digest(value) -> str:
    return digest(json.dumps(value, sort_keys=True, ensure_ascii=False).encode())


def write_json(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = value.model_dump(mode="json") if isinstance(value, BaseModel) else value
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def command(argv: list[str]) -> str:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("Infrastructure command timed out after 30 seconds: " + argv[0]) from exc
    if completed.returncode:
        raise RuntimeError(redact_error_message(completed.stderr.strip())[:1000])
    return completed.stdout.strip()


def load_dataset(path: Path) -> BenchmarkDataset:
    return BenchmarkDataset.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def validate_dataset_lock(config_path: Path, dataset: BenchmarkDataset, target: Path):
    """A reviewed corpus cannot silently change within a dataset version."""
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    lock = read_json(config_path.parent / "dataset.lock.json", {})
    expected = {
        "dataset": dataset.id,
        "version": dataset.version,
        "target_commit": dataset.target_commit,
        "ground_truth_digest": digest((config_path.parent / config["ground_truth"]).read_bytes()),
        "configuration_digest": digest(config_path.read_bytes()),
    }
    if any(lock.get(key) != value for key, value in expected.items()):
        raise ValueError("Dataset lock mismatch; ground truth/config changes require a new version")
    for case in dataset.cases:
        path = target / normalize_path(case.artifact)
        if lock.get("artifact_digests", {}).get(case.artifact) != digest(path.read_bytes()):
            raise ValueError("Pinned ground truth source digest mismatch: " + case.artifact)


def validate_target(dataset: BenchmarkDataset, target: Path, profile: TargetProfile) -> dict:
    commit = command(["git", "-C", str(target), "rev-parse", "HEAD"])
    if commit != dataset.target_commit:
        raise ValueError("Target commit does not match the frozen dataset")
    if command(["git", "-C", str(target), "status", "--porcelain", "--untracked-files=all"]):
        raise ValueError("Target must be clean, including nonignored untracked files")
    manifest = {}
    tracked = command(["git", "-C", str(target), "ls-files", "-z"]).split("\0")
    for name in filter(None, tracked):
        path = target / normalize_path(name)
        if not path.resolve().is_relative_to(target.resolve()) or path.is_symlink():
            raise ValueError("Linked source paths are not supported")
        raw = path.read_bytes()
        manifest[name] = digest(raw)
    # Upstream includes a few native CRLF blobs. Reject checkout conversion of LF
    # blobs rather than rewriting upstream files or pretending they were all LF.
    for row in command(["git", "-C", str(target), "ls-files", "--eol"]).splitlines():
        if row.startswith("i/lf") and "w/crlf" in row:
            raise ValueError(
                "Target requires LF checkout without CRLF conversion: " + row.split("\t")[-1]
            )
    server = (target / "server.ts").read_text(encoding="utf-8")
    for case in dataset.cases:
        path = (target / normalize_path(case.artifact)).resolve()
        if not path.is_relative_to(target.resolve()) or not path.is_file():
            raise ValueError("Missing/outside ground truth artifact: " + case.artifact)
        if case.line_end > len(path.read_text(encoding="utf-8").splitlines()):
            raise ValueError("Ground truth range exceeds source file")
        if case.service and (
            case.service not in profile.services
            or profile.resolve_service(case.artifact) != case.service
        ):
            raise ValueError("Case service is inconsistent with the production profile")
        if case.endpoint and (not case.endpoint.startswith("/") or case.endpoint not in server):
            raise ValueError("Case endpoint is absent from pinned server registrations")
        for provenance in case.provenance:
            source = (target / normalize_path(provenance)).resolve()
            if not source.is_relative_to(target.resolve()) or not source.exists():
                raise ValueError("Invalid provenance: " + provenance)
    return {"commit": commit, "files": manifest, "digest": json_digest(manifest)}


class ProviderProbe(BaseModel):
    ready: bool


def preflight(config: dict, dataset: BenchmarkDataset, target: Path) -> tuple[dict, list[str]]:
    """Probe real infrastructure without exposing credentials or dataset to the model."""
    errors, details = [], {}
    profile_path = ROOT / config["profile"]
    try:
        profile = TargetProfile.from_yaml(profile_path, repository_path_override=target)
        details["target_manifest"] = validate_target(dataset, target, profile)
        compose = target / profile.runtime.compose_file
        if not compose.is_file():
            raise ValueError("Required operator compose file missing; see benchmark README")
        expected_compose = ROOT / "docs/demo/compose.yaml"
        if compose.read_bytes() != expected_compose.read_bytes():
            raise ValueError("Compose must equal the pinned network-isolated demo compose")
        details["compose_digest"] = digest(compose.read_bytes())
    except (OSError, ValueError, RuntimeError, TypeError) as exc:
        errors.append("target: " + redact_error_message(str(exc)))
    try:
        details["docker_version"] = command(["docker", "info", "--format", "{{.ServerVersion}}"])
        images = {}
        for image in [*config["required_images"], config["worker_image"]]:
            raw = json.loads(command(["docker", "image", "inspect", image]))[0]
            refs = raw.get("RepoDigests") or []
            if not refs:
                raise ValueError("Image lacks repository digest: " + image)
            images[image] = {"id": raw["Id"], "repo_digests": sorted(refs)}
        details["images"] = images
        worker = images[config["worker_image"]]["repo_digests"][0]
        details["worker_image"] = worker
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append("docker: " + redact_error_message(str(exc)))
    try:
        executable = shutil.which("semgrep")
        if not executable:
            raise ValueError("Semgrep CLI missing; install the project's [sast] extra")
        details["sast_version"] = command([executable, "--version"])
    except (OSError, RuntimeError, ValueError) as exc:
        errors.append("sast: " + redact_error_message(str(exc)))
    client = None
    try:
        routes = parse_route_specs(config["settings"]["llm_routes"])
        credentials = settings.llm_provider_credentials()
        if any(route.key_env not in credentials for route in routes):
            raise ValueError("Configured LLM route has no credential in the local environment/.env")
        client = ProviderFailoverClient(
            routes=routes,
            credentials=credentials,
            timeout_seconds=config["settings"]["llm_timeout_seconds"],
            max_output_tokens=config["settings"]["llm_max_output_tokens"],
            reasoning_effort=config["settings"]["llm_reasoning_effort"],
        )
        probe = client.complete_model(
            output_model=ProviderProbe,
            system_prompt='Return JSON {"ready": true}. This is a connectivity check.',
            user_payload={"task": "provider readiness check"},
            operation="benchmark_preflight",
        )
        if not probe.ready:
            raise ValueError("Provider returned not ready")
        details["provider_probe"] = {"ready": True, "route": client.last_selected_route.label}
    except Exception as exc:  # noqa: BLE001 - record infrastructure blocker at CLI boundary
        errors.append("model: " + type(exc).__name__ + ": " + redact_error_message(str(exc)))
    if client is not None:
        details["provider_attempts"] = [
            {
                "route": attempt.route,
                "status": attempt.status,
                "latency_ms": attempt.latency_ms,
                "http_status": (
                    int(match.group(1))
                    if (
                        match := re.search(
                            r"\bHTTP\s+(\d{3})\b", attempt.error or "", re.IGNORECASE
                        )
                    )
                    else None
                ),
            }
            for attempt in client.last_attempts
        ]
    return details, errors


def production_arguments(config: dict, target: Path, output: Path) -> argparse.Namespace:
    """Explicit allowlist: no truth, case IDs, labels or expected locations can cross."""
    return argparse.Namespace(
        target=str(target),
        target_repository=None,
        profile=str(ROOT / config["profile"]),
        architecture=None,
        architecture_overrides=None,
        sast_config=str(ROOT / config["rules"]),
        findings=None,
        output_dir=str(output),
        agent_mode="llm",
        max_iterations=config["max_iterations"],
        full_reports=False,
        base_ref=None,
        head_ref="HEAD",
        base_findings=None,
        base_architecture=None,
    )


def observe(
    finding: Finding,
    dataset: BenchmarkDataset,
    report: FinalReport | None,
    *,
    full: bool,
    pipeline_root: Path | None = None,
) -> BenchmarkObservation:
    status, backed, evidence = "not_run", False, []
    sources = []
    if full:
        status = "technical_error" if report is None else report.status
        if report:
            if report.stop_reason in {"execution_timeout", "wall_clock_budget_exhausted"}:
                status = "timeout"
            elif report.stop_reason in {"execution_failed", "build_failure"}:
                status = "technical_error"
            elif report.stop_reason == "unsupported_runtime" or not report.verification.capability:
                status = "unsupported"
            supported = [
                e
                for e in report.evidence
                if e.verdict == "confirmed"
                and e.reliability in {"high", "medium"}
                and pipeline_root is not None
                and persisted_evidence_matches(e, pipeline_root)
            ]
            backed = bool(supported) and report.status == "confirmed"
            sources = sorted({e.source for e in supported}) if backed else []
            evidence = [ref for e in report.evidence for ref in e.artifact_refs]
            if report.status == "confirmed" and not backed:
                status = "technical_error"
    return BenchmarkObservation(
        id=finding.id,
        source=finding.source,
        artifact=normalize_path(finding.file),
        line_start=finding.line_start,
        line_end=finding.line_end,
        family=family(finding.rule_id, dataset),
        service=finding.service,
        verification=status,
        reported_verdict=report.status if report else None,
        evidence_backed=backed,
        confirmation_sources=sources,
        evidence=evidence,
        capability=report.verification.capability if report else None,
    )


def persisted_evidence_matches(evidence, root: Path) -> bool:
    """Bind confirmation to this run's persisted successful execution and audit digests."""
    refs = [a.ref for a in evidence.artifacts if a.role == "execution"]
    for ref in refs:
        if not re.fullmatch(r"execution-[a-f0-9]{32}", ref):
            continue
        record = read_json(root / "evidence" / (ref + ".json"), {})
        if (
            record.get("action_id") != evidence.action_id
            or record.get("run_id") != evidence.action.run_id
            or record.get("tool") != evidence.action.tool
            or record.get("status") != "completed"
            or record.get("exit_code") != 0
            or record.get("target") != evidence.scope.target
            or record.get("session_id") != evidence.sandbox_session_id
        ):
            continue
        payload = {k: v for k, v in record.items() if k not in {"id", "type", "created_at"}}
        for audit in read_jsonl(root / "audit/executor.jsonl"):
            if (
                audit.get("evidence_ref") == ref
                and audit.get("action_id") == evidence.action_id
                and audit.get("run_id") == evidence.action.run_id
                and audit.get("status") == "completed"
                and audit.get("exit_code") == 0
                and audit.get("proposal_digest") == record.get("action_digest")
                and audit.get("evidence_digest") == calculate_sha256_digest(payload)
                and "audit:" + str(audit.get("run_id")) in evidence.artifact_refs
            ):
                return True
    return False


def read_json(path: Path, default=None):
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else default


def read_jsonl(path: Path):
    return (
        [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if path.is_file()
        else []
    )


def evaluate_artifacts(dataset, directory, run_id, config_digest, exit_code, duration):
    pipeline = directory / "pipeline"
    reports = [
        FinalReport.model_validate_json(p.read_text(encoding="utf-8"))
        for p in sorted((pipeline / "reports").glob("*.json"))
    ]
    reports_by_id = {r.finding_id: r for r in reports}
    sast_path = pipeline / "sast/findings.json"
    merged_path = pipeline / "scout/merged-findings.json"
    sast = [Finding.model_validate(item) for item in read_json(sast_path, [])]
    merged = [Finding.model_validate(item) for item in read_json(merged_path, [])]
    llm = read_jsonl(pipeline / "audit/llm-attempts.jsonl")
    scout = read_json(pipeline / "scout/summary.json", {})
    gate = read_json(pipeline / "gate.json", {})
    diagnostics = []
    if exit_code == 2 or not sast_path.exists() or not merged_path.exists():
        diagnostics.append("Canonical pipeline or detection stage did not complete")
    if not any(item.get("status") == "ok" for item in llm):
        diagnostics.append("No successful real LLM response recorded; degraded run is not scored")
    if scout.get("stop_reason") in {"model_unavailable", "model_error"}:
        diagnostics.append("Scout model unavailable; degraded detection is not scored")
    if gate.get("technical_errors") or gate.get("stage_errors"):
        diagnostics.append("Gate records technical errors; run excluded from primary aggregate")
    base = [observe(f, dataset, None, full=False) for f in sast]
    full = [
        observe(f, dataset, reports_by_id.get(f.id), full=True, pipeline_root=pipeline)
        for f in merged
    ]
    write_json(
        directory / "raw-findings.json",
        {"sast": [o.model_dump() for o in base], "detection": [o.model_dump() for o in full]},
    )
    events = read_jsonl(pipeline / "progress.jsonl")
    stages = {}
    for stage in ("discovery", "sast", "scout", "verification"):
        selected = [e for e in events if e.get("stage") == stage]
        start = next((e["ts"] for e in selected if e.get("status") == "running"), None)
        end = next((e["ts"] for e in reversed(selected) if e.get("status") == "done"), None)
        stages[stage + "_seconds"] = (
            (datetime.fromisoformat(end) - datetime.fromisoformat(start)).total_seconds()
            if start and end
            else None
        )
    actions = [a for r in reports for a in r.sandbox_actions]
    performance = {
        "total_seconds": duration,
        **stages,
        "findings": len(merged),
        "tool_actions": len(actions),
        "llm_calls": len(llm),
        "llm_successes": sum(a.get("status") == "ok" for a in llm),
        "docker_actions": sum(
            a.get("runtime_backend") == "docker"
            for a in read_jsonl(pipeline / "audit/executor.jsonl")
        ),
        "docker_lifecycle_actions": None,
        "token_usage": None,
        "merge_duplicates": scout.get("duplicates", 0),
    }
    result = BenchmarkRunResult(
        run_id=run_id,
        configuration_digest=config_digest,
        status="technical_failure" if diagnostics else "completed",
        baseline=score(dataset, base, verification_measured=False) if sast_path.exists() else None,
        detection=score(dataset, full) if merged_path.exists() else None,
        performance=performance,
        diagnostics=diagnostics,
    )
    # Partial stage results are diagnostic only. A startup failure never becomes all FN.
    write_json(
        directory / "matches.json",
        [m.model_dump() for m in result.detection.matches] if result.detection else [],
    )
    write_json(directory / "metrics.json", result)
    (directory / "report.md").write_text(render_run(result), encoding="utf-8")
    return result


def render_run(result):
    lines = [
        f"# {result.run_id}",
        "",
        f"Status: {result.status}",
        "Recall relative to benchmark-v1 scope; precision over adjudicated cases only.",
        "",
    ]
    for name in ("baseline", "detection"):
        view = getattr(result, name)
        if view:
            lines.extend(
                [
                    f"## {name}",
                    "",
                    "```json",
                    view.detection.model_dump_json(indent=2),
                    view.verification.model_dump_json(indent=2),
                    "```",
                    "",
                ]
            )
    if result.detection:
        lines.extend(
            [
                "| Case | Expected | Detected | Source | Finding | Verification | Evidence confirmed | Evidence |",
                "|---|---|---|---|---|---|---|---|",
            ]
        )
        for c in result.detection.cases:
            lines.append(
                f"| {c.case_id} | {c.expected} | {c.detected} | {c.detection_source} | "
                f"{c.finding_id} | {c.verification} | {c.confirmation_supported} | {', '.join(c.evidence)} |"
            )
    lines.extend(
        [
            "",
            "Diagnostics: " + "; ".join(result.diagnostics),
            "",
            "Performance: " + json.dumps(result.performance),
            "",
        ]
    )
    return "\n".join(lines)


def render_aggregate(value):
    lines = [
        "# Stage 2 benchmark aggregate",
        "",
        (
            f"Attempted: {value.attempted_runs}; completed: {value.completed_runs}; "
            f"technical failure rate: {value.technical_failure_rate}"
        ),
        "",
        "Recall relative to benchmark-v1 scope. Null metrics are N/A, not zero.",
        "",
        "| Metric | Mean | Min | Max | Standard deviation |",
        "|---|---|---|---|---|",
    ]
    for key, v in value.numeric.items():
        lines.append(f"| {key} | {v['mean']} | {v['min']} | {v['max']} | {v['stddev']} |")
    lines.extend(
        [
            "",
            "| Case | Found / completed | Confirmed / completed | Verdicts | Unstable |",
            "|---|---|---|---|---|",
        ]
    )
    for key, v in value.stability.items():
        lines.append(
            f"| {key} | {v['detected_runs']}/{value.completed_runs} | "
            f"{v['confirmed_runs']}/{value.completed_runs} | {v['verdicts']} | {v['unstable_verdict']} |"
        )
    lines.extend(["", "Positive case stability: " + json.dumps(value.stability_summary)])
    return "\n".join(lines) + "\n"


def run_benchmark(args):
    config_path = (
        ROOT / "benchmarks/juice-shop-v20.2.0/benchmark.yaml"
        if args.dataset == "juice-shop-v20.2.0-v1"
        else Path(args.dataset).resolve()
    )
    config = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    allowed_config = {
        "id",
        "profile",
        "rules",
        "policy",
        "ground_truth",
        "settings",
        "max_iterations",
        "required_images",
        "worker_image",
    }
    if set(config) - allowed_config:
        raise ValueError(
            "Unknown configuration fields; credentials do not belong in benchmark YAML"
        )
    truth_path = config_path.parent / config["ground_truth"]
    dataset = load_dataset(truth_path)
    if config["id"] != dataset.id:
        raise ValueError("Dataset/config ID mismatch")
    # Only this allowlist may enter the production settings singleton.
    if set(config["settings"]) - set(SETTING_NAMES):
        raise ValueError("Unknown or sensitive benchmark settings")
    profile = TargetProfile.from_yaml(ROOT / config["profile"])
    target = Path(args.target or profile.repository_path).resolve()
    output = Path(args.output).resolve()
    if output.is_relative_to(target) or target.is_relative_to(ROOT / "benchmarks"):
        raise ValueError("Evaluator artifacts must be separate from target source")
    output.mkdir(parents=True, exist_ok=True)
    details, errors = preflight(config, dataset, target)
    try:
        validate_dataset_lock(config_path, dataset, target)
    except (OSError, ValueError) as exc:
        errors.append("dataset: " + redact_error_message(str(exc)))
    write_json(
        output / "preflight.json",
        {
            "at": datetime.now(UTC).isoformat(),
            "dataset": dataset.id,
            "ground_truth_digest": digest(truth_path.read_bytes()),
            "requested_runs": args.runs,
            "passed": not errors,
            "errors": errors,
            "details": details,
        },
    )
    if errors:
        (output / "preflight.md").write_text(
            "# Benchmark blocked before scored runs\n\n"
            + "\n".join("- " + error for error in errors)
            + "\n",
            encoding="utf-8",
        )
        print("Benchmark preflight failed:\n" + "\n".join(errors))
        return 2
    if getattr(args, "preflight_only", False):
        print("Preflight passed; no scored run started")
        return 0
    snapshot = {
        "dataset": dataset.model_dump(),
        "config": config,
        "ground_truth_digest": digest(truth_path.read_bytes()),
        "dataset_config_digest": digest(config_path.read_bytes()),
        "pentester_commit": command(["git", "rev-parse", "HEAD"]),
        "pentester_worktree_digest": source_digest(ROOT),
        "profile_digest": digest((ROOT / config["profile"]).read_bytes()),
        "policy_digest": digest((ROOT / config["policy"]).read_bytes()),
        "rules_digest": digest((ROOT / config["rules"]).read_bytes()),
        "architecture_digest": digest(Path(profile.architecture.file).read_bytes()),
        "settings": {
            name: config["settings"].get(name, getattr(settings, name)) for name in SETTING_NAMES
        },
        "platform": platform.platform(),
        "python": sys.version,
        "preflight": {
            k: v for k, v in details.items() if k not in {"provider_probe", "provider_attempts"}
        },
    }
    snapshot["settings"]["sandbox_image"] = details["worker_image"]
    fingerprint = json_digest(snapshot)
    frozen = output / "configuration.json"
    if frozen.exists():
        if not args.resume or read_json(frozen)["configuration_digest"] != fingerprint:
            raise ValueError(
                "Output already frozen; use matching --resume or a new output directory"
            )
    else:
        write_json(frozen, {"configuration_digest": fingerprint, "snapshot": snapshot})
        (output / "ground_truth.yaml").write_bytes(truth_path.read_bytes())
        (output / "benchmark.yaml").write_bytes(config_path.read_bytes())
    from app.ci_pipeline import run_ci_pipeline

    saved = {key: getattr(settings, key) for key in SETTING_NAMES}
    saved_policy = settings.policy_file
    runs = []
    try:
        for key, value in snapshot["settings"].items():
            setattr(settings, key, value)
        settings.policy_file = ROOT / config["policy"]
        for index in range(1, args.runs + 1):
            directory = output / f"run-{index:03d}"
            result_path = directory / "metrics.json"
            if directory.exists():
                if not args.resume or not result_path.exists():
                    raise ValueError("Incomplete run preserved; choose a new output directory")
                result = BenchmarkRunResult.model_validate(read_json(result_path))
                if result.configuration_digest != fingerprint:
                    raise ValueError("Resume configuration mismatch")
                seal = read_json(directory / "seal.json")
                if seal != artifact_hashes(directory):
                    raise ValueError("Run artifacts changed after completion")
                runs.append(result)
                continue
            directory.mkdir()
            # Revalidate integrity before every iteration; no ground truth goes to CI.
            manifest = validate_target(dataset, target, profile)
            if manifest["digest"] != details["target_manifest"]["digest"]:
                raise ValueError("Source changed after configuration freeze")
            started = datetime.now(UTC).isoformat()
            clock = time.monotonic()
            with measure_stages() as durations:
                from app.pipeline_run import run_pipeline

                exit_code = run_ci_pipeline(
                    production_arguments(config, target, directory / "pipeline"),
                    pipeline_runner=run_pipeline,
                )
            elapsed = time.monotonic() - clock
            if validate_target(dataset, target, profile)["digest"] != manifest["digest"]:
                raise ValueError("Target integrity changed during benchmark")
            result = evaluate_artifacts(
                dataset, directory, directory.name, fingerprint, exit_code, elapsed
            )
            result.performance.update(durations)
            write_json(directory / "metrics.json", result)
            (directory / "report.md").write_text(render_run(result), encoding="utf-8")
            write_json(
                directory / "manifest.json",
                {
                    "configuration_digest": fingerprint,
                    "dataset_id": dataset.id,
                    "dataset_version": dataset.version,
                    "ground_truth_digest": snapshot["ground_truth_digest"],
                    "run_id": directory.name,
                    "target_commit": dataset.target_commit,
                    "pentester_commit": snapshot["pentester_commit"],
                    "started_at": started,
                    "finished_at": datetime.now(UTC).isoformat(),
                    "exit_code": exit_code,
                    "snapshot": snapshot,
                },
            )
            write_json(directory / "seal.json", artifact_hashes(directory))
            runs.append(result)
            value = aggregate(runs)
            write_json(output / "aggregate.json", value)
            (output / "aggregate.md").write_text(render_aggregate(value), encoding="utf-8")
    finally:
        for key, value in saved.items():
            setattr(settings, key, value)
        settings.policy_file = saved_policy
    # Resume-only invocation also regenerates aggregate from validated immutable runs.
    value = aggregate(runs)
    write_json(output / "aggregate.json", value)
    (output / "aggregate.md").write_text(render_aggregate(value), encoding="utf-8")
    return 0 if all(r.status == "completed" for r in runs) else 2


def artifact_hashes(directory: Path) -> dict:
    return {
        p.relative_to(directory).as_posix(): digest(p.read_bytes())
        for p in sorted(directory.rglob("*"))
        if p.is_file() and p.name != "seal.json"
    }


def source_digest(root: Path) -> str:
    """Capture dirty implementation too; commit alone cannot identify uncommitted code."""
    files = {}
    for folder in (
        "agent",
        "app",
        "architecture",
        "discovery",
        "evidence",
        "evaluation",
        "executor",
        "pipeline",
        "reporting",
        "sast",
        "schemas",
        "scoring",
        "security",
        "tools",
        "validator",
    ):
        for path in sorted((root / folder).rglob("*.py")):
            files[path.relative_to(root).as_posix()] = digest(path.read_bytes())
    files["pyproject.toml"] = digest((root / "pyproject.toml").read_bytes())
    return json_digest(files)


@contextmanager
def measure_stages():
    """Time the unchanged real calls from outside; restore functions even on failures.

    Sequential harness only. No return values, inputs or exception semantics change.
    Verification timing includes graph orchestration and per-finding context/report work.
    """
    import app.pipeline_run as pipeline
    from discovery.service import ProjectDiscovery

    totals = {}
    bindings = [
        (ProjectDiscovery, "discover", "discovery_seconds"),
        (pipeline, "_resolve_findings", "sast_seconds"),
        (pipeline, "_append_scout_findings", "scout_seconds"),
        (pipeline, "run_pipeline", "pipeline_seconds"),
    ]
    originals = []

    def timed(original, name):
        @wraps(original)
        def invoke(*args, **kwargs):
            clock = time.monotonic()
            try:
                return original(*args, **kwargs)
            finally:
                totals[name] = totals.get(name, 0.0) + time.monotonic() - clock

        return invoke

    try:
        for owner, attr, name in bindings:
            original = getattr(owner, attr)
            originals.append((owner, attr, original))
            setattr(owner, attr, timed(original, name))
        yield totals
    finally:
        for owner, attr, original in reversed(originals):
            setattr(owner, attr, original)
        if "pipeline_seconds" in totals:
            totals["agent_verification_seconds"] = max(
                0,
                totals.pop("pipeline_seconds")
                - totals.get("sast_seconds", 0)
                - totals.get("scout_seconds", 0),
            )
