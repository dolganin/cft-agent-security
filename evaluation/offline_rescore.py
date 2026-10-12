"""Deterministic A05 rescoring from saved artifacts only."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import yaml

from evaluation.benchmark_v2 import score_v2
from evaluation.artifact_history import sanitize
from evaluation.benchmark_harness import persisted_evidence_matches
from evaluation.catalog_adapter import load_catalog_dataset
from schemas.benchmark_v2 import (
    BenchmarkArtifactHistoryV2,
    BenchmarkDatasetV2,
    BenchmarkObservationV2,
)
from schemas.finding import Finding
from schemas.report import FinalReport


def _json(path: Path, default=None):
    if not path.is_file():
        return default
    return json.loads(path.read_text(encoding="utf-8"))


def _read_jsonl(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _load_dataset(path: Path) -> BenchmarkDatasetV2:
    return BenchmarkDatasetV2.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _report_index(root: Path) -> dict[str, FinalReport]:
    reports = {}
    for path in sorted((root / "reports").glob("*.json")):
        report = FinalReport.model_validate(_json(path))
        reports[report.finding_id] = report
    return reports


def _trace_index(root: Path) -> dict[str, dict]:
    result = {}
    for path in sorted((root / "traces").glob("*.json")):
        trace = _json(path, {})
        if trace.get("finding_id"):
            result[trace["finding_id"]] = trace
    return result


def _http_context(trace: dict) -> tuple[str | None, str | None, str | None]:
    for record in trace.get("actions", []):
        action = record.get("action", {})
        parameters = action.get("parameters", {})
        endpoint = parameters.get("endpoint") or parameters.get("path")
        method = parameters.get("method")
        parameter = parameters.get("parameter")
        if isinstance(endpoint, str) and endpoint.startswith("/"):
            method = method.upper() if isinstance(method, str) else None
            return method, endpoint, parameter if isinstance(parameter, str) else None
    return None, None, None


def observations_from_artifacts(root: Path) -> list[BenchmarkObservationV2]:
    normalized = root / "observations-v2.json"
    if normalized.is_file():
        return [BenchmarkObservationV2.model_validate(item) for item in _json(normalized, [])]
    raw = _json(root / "scout" / "merged-findings.json")
    if raw is None:
        raw = _json(root / "sast" / "findings.json", [])
    reports = _report_index(root)
    traces = _trace_index(root)
    observations = []
    for item in raw:
        finding = Finding.model_validate(item)
        report = reports.get(finding.id)
        status = "not_run"
        backed = False
        evidence_refs = []
        if report is not None:
            status = report.status
            if report.stop_reason in {"policy_blocked", "isolation_or_policy_blocked"}:
                status = "policy_blocked"
            elif report.stop_reason in {"execution_timeout", "wall_clock_budget_exhausted"}:
                status = "timeout"
            elif report.stop_reason in {"execution_failed", "build_failure"}:
                status = "technical_error"
            elif report.stop_reason == "unsupported_runtime" or (
                report.status == "inconclusive" and not report.verification.capability
            ):
                status = "unsupported"
            supported = [
                evidence for evidence in report.evidence
                if evidence.verdict == report.status
                and evidence.reliability in {"high", "medium"}
                and persisted_evidence_matches(evidence, root)
            ]
            backed = report.status in {"confirmed", "rejected"} and bool(supported)
            evidence_refs = sorted({ref for evidence in report.evidence for ref in evidence.artifact_refs})
        method, endpoint, parameter = _http_context(traces.get(finding.id, {}))
        observations.append(BenchmarkObservationV2(
            id=finding.id,
            source=finding.source,
            family=finding.rule_id,
            service=finding.service,
            source_file=finding.file,
            line_start=finding.line_start,
            line_end=finding.line_end,
            http_method=method,
            http_endpoint=endpoint,
            http_parameter=parameter,
            verification=status,
            reported_verdict=report.status if report else None,
            evidence_backed=backed,
            evidence=evidence_refs,
            capability=report.verification.capability if report else None,
            severity=report.cvss.severity if report and report.cvss else None,
            context_priority=(
                report.context_priority.level if report and report.context_priority else None
            ),
        ))
    return observations


def artifact_history(root: Path, *, run_id: str, attempt_id: str, retry_of: str | None):
    pipeline = root / "pipeline" if (root / "pipeline").is_dir() else root
    reports = [_json(path) for path in sorted((pipeline / "reports").glob("*.json"))]
    traces = [_json(path) for path in sorted((pipeline / "traces").glob("*.json"))]
    actions = [action for trace in traces for action in trace.get("actions", [])]
    evidence = [_json(path) for path in sorted((pipeline / "evidence").glob("*.json"))]
    gate = _json(pipeline / "gate.json", {})
    configuration = {
        path.name: _json(path)
        for path in (root / "configuration.json", root / "preflight.json")
        if path.is_file()
    }
    versions = _json(root / "manifest.json", {}) or {}
    hashes = {}
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root).as_posix()
        hashes[relative] = hashlib.sha256(path.read_bytes()).hexdigest()
    return BenchmarkArtifactHistoryV2(
        run_id=run_id,
        attempt_id=attempt_id,
        retry_of=retry_of,
        configurations=sanitize(configuration),
        versions=sanitize(versions),
        reports=sanitize(reports),
        plans=sanitize([entry for trace in traces for entry in trace.get("plans", [])]),
        validator_decisions=sanitize([
            action.get("validation", {}) for action in actions if action.get("validation")
        ]),
        action_proposals=sanitize([
            action.get("action", {}) for action in actions if action.get("action")
        ]),
        executions=sanitize([
            action.get("execution", {}) for action in actions if action.get("execution")
        ]),
        evidence=sanitize(
            evidence + [entry for trace in traces for entry in trace.get("evidence", [])]
        ),
        agent_decisions=sanitize([
            entry for trace in traces for entry in trace.get("decisions", [])
        ]),
        errors=sanitize(list(gate.get("errors", [])) + [
            {"message": message} for message in gate.get("stage_errors", [])
        ]),
        retries=sanitize(_read_jsonl(pipeline / "audit" / "llm-attempts.jsonl")),
        artifact_sha256=hashes,
    )


def render_report(score) -> str:
    if not score.technically_valid:
        return "# Benchmark v2\n\nTECHNICALLY_INVALID; security metrics are N/A.\n"
    detection = score.detection
    verification = score.verification
    return (
        "# Benchmark v2\n\n"
        f"Detection: TP={detection.tp}, FP={detection.fp}, FN={detection.fn}, TN={detection.tn}.\n\n"
        f"Confirmed precision: {verification.confirmed_precision!r}; "
        f"supported verified recall: {verification.supported_verified_recall!r}; "
        f"FPR: {verification.false_confirmation_rate!r}; "
        f"coverage: {verification.decision_coverage!r}; "
        f"abstention: {verification.abstention_rate!r}.\n"
    )


def rescore(
    dataset: BenchmarkDatasetV2,
    artifacts: Path,
    output: Path,
    *,
    run_id: str = "offline",
    attempt_id: str | None = None,
    retry_of: str | None = None,
):
    if output.resolve() == artifacts.resolve() or output.resolve().is_relative_to(artifacts.resolve()):
        raise ValueError("Offline score output must be outside the immutable artifact directory")
    pipeline = artifacts / "pipeline" if (artifacts / "pipeline").is_dir() else artifacts
    gate = _json(pipeline / "gate.json", {})
    errors = list(gate.get("stage_errors", []))
    errors.extend(item.get("message", "technical error") for item in gate.get("errors", []))
    if gate.get("technical_errors") and not errors:
        errors.append(f"technical_errors={gate['technical_errors']}")
    observations = observations_from_artifacts(pipeline)
    score = score_v2(
        dataset,
        observations,
        technically_valid=not bool(errors),
        technical_errors=errors,
    )
    manifest = _json(artifacts / "manifest.json", {}) or {}
    history = artifact_history(
        artifacts,
        run_id=run_id,
        attempt_id=attempt_id or manifest.get("attempt_id") or artifacts.name,
        retry_of=retry_of if retry_of is not None else manifest.get("retry_of"),
    )
    output.mkdir(parents=True, exist_ok=True)
    payloads = {
        "scorecard-v2.json": score.model_dump(mode="json"),
        "history-v2.json": history.model_dump(mode="json"),
        "observations-v2.json": [item.model_dump(mode="json") for item in observations],
    }
    for name, payload in payloads.items():
        (output / name).write_text(
            json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    (output / "scorecard-v2.md").write_text(render_report(score), encoding="utf-8")
    return score


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path)
    parser.add_argument("--positive-catalog", type=Path)
    parser.add_argument("--control-catalog", type=Path)
    parser.add_argument("--expanded-control-catalog", type=Path)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run-id", default="offline")
    parser.add_argument("--attempt-id")
    parser.add_argument("--retry-of")
    args = parser.parse_args(argv)
    if args.dataset:
        dataset = _load_dataset(args.dataset)
    elif args.positive_catalog and args.control_catalog:
        dataset = load_catalog_dataset(
            args.positive_catalog,
            args.control_catalog,
            args.expanded_control_catalog,
        )
    else:
        parser.error("provide --dataset or both A02/A03 catalog paths")
    rescore(
        dataset,
        args.artifacts,
        args.output,
        run_id=args.run_id,
        attempt_id=args.attempt_id,
        retry_of=args.retry_of,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
