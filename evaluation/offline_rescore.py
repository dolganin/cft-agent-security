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
    BenchmarkScoreCollectionV2,
)
from schemas.finding import Finding
from schemas.pipeline import GateResult
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


def _trace_binds_evidence(trace: dict, evidence) -> bool:
    for record in trace.get("actions", []):
        action = record.get("action") or {}
        validation = record.get("validation") or {}
        execution = record.get("execution") or {}
        if (
            action.get("id") == evidence.action_id
            and validation.get("approved") is True
            and validation.get("action_id") == evidence.action_id
            and execution.get("action_id") == evidence.action_id
            and execution.get("run_id") == evidence.action.run_id
            and execution.get("status") == "completed"
            and execution.get("exit_code") == 0
        ):
            return True
    return False


def _http_context(trace: dict) -> tuple[str | None, str | None, str | None]:
    for record in trace.get("actions", []):
        action = record.get("action", {})
        parameters = action.get("parameters", {})
        endpoint = action.get("endpoint") or parameters.get("endpoint") or parameters.get("path")
        method = action.get("method") or parameters.get("method")
        parameter = action.get("parameter") or parameters.get("parameter")
        if isinstance(endpoint, str) and endpoint.startswith("/"):
            method = method.upper() if isinstance(method, str) else None
            return method, endpoint, parameter if isinstance(parameter, str) else None
    return None, None, None


def observations_from_artifacts(root: Path) -> list[BenchmarkObservationV2]:
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
                and _trace_binds_evidence(traces.get(finding.id, {}), evidence)
            ]
            backed = report.status in {"confirmed", "rejected"} and bool(supported)
            evidence_refs = sorted({ref for evidence in report.evidence for ref in evidence.artifact_refs})
        method, endpoint, parameter = _http_context(traces.get(finding.id, {}))
        observations.append(BenchmarkObservationV2(
            id=finding.id,
            source=finding.source,
            family=(
                finding.provenance.family
                if finding.provenance is not None
                else finding.rule_id
            ),
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


def _run_root(artifacts: Path) -> Path:
    return artifacts.parent if artifacts.name == "pipeline" else artifacts


def _artifact_errors(run_root: Path, pipeline: Path, dataset: BenchmarkDatasetV2) -> list[str]:
    """Fail closed unless this is a complete, internally sealed benchmark attempt."""
    required = [
        pipeline / "gate.json",
        pipeline / "ci-summary.json",
        pipeline / "sast/findings.json",
        pipeline / "sast/summary.json",
        pipeline / "scout/merged-findings.json",
        pipeline / "scout/summary.json",
        pipeline / "reports-index.json",
        pipeline / "audit/llm-attempts.jsonl",
        run_root / "configuration.json",
        run_root / "manifest.json",
        run_root / "metrics.json",
        run_root / "seal.json",
    ]
    errors = [f"missing required artifact: {path.relative_to(run_root)}" for path in required if not path.is_file()]
    if errors:
        return sorted(errors)
    try:
        gate = GateResult.model_validate(_json(pipeline / "gate.json"))
        ci_summary = _json(pipeline / "ci-summary.json")
        sast_findings = _json(pipeline / "sast/findings.json")
        sast_summary = _json(pipeline / "sast/summary.json")
        scout_findings = _json(pipeline / "scout/merged-findings.json")
        scout_summary = _json(pipeline / "scout/summary.json")
        report_index = _json(pipeline / "reports-index.json")
        configuration = _json(run_root / "configuration.json")
        manifest = _json(run_root / "manifest.json")
        metrics = _json(run_root / "metrics.json")
        seal = _json(run_root / "seal.json")
        attempts = _read_jsonl(pipeline / "audit/llm-attempts.jsonl")
        if not isinstance(sast_findings, list) or not isinstance(scout_findings, list):
            raise ValueError("finding artifacts must be JSON arrays")
        if not isinstance(report_index, list):
            raise ValueError("reports-index.json must be a JSON array")
        if not isinstance(sast_summary, dict) or not isinstance(scout_summary, dict):
            raise ValueError("SAST and Scout summaries must be JSON objects")
        if not isinstance(ci_summary, dict):
            raise ValueError("gate and CI summary must be JSON objects")
        if not isinstance(configuration, dict) or not isinstance(manifest, dict):
            raise ValueError("configuration and manifest must be JSON objects")
        if not isinstance(metrics, dict) or not isinstance(seal, dict):
            raise ValueError("metrics and seal must be JSON objects")
        if not isinstance(attempts, list):
            raise ValueError("LLM attempt log must contain JSON objects")
        if any(not isinstance(item, dict) for item in attempts):
            raise ValueError("LLM attempt log contains a non-object record")
        if gate.exit_code == 2 or gate.technical_errors:
            errors.append("gate reports technical failure")
        if gate.decision_basis == "technical_pipeline_error" or gate.errors or gate.stage_errors:
            errors.append("gate contains stage errors")
        if ci_summary.get("status") != "completed" or ci_summary.get("exit_code") == 2:
            errors.append("CI pipeline did not complete successfully")
        if int(sast_summary.get("semgrep_errors", sast_summary.get("errors", 0)) or 0) > 0:
            errors.append("SAST summary reports errors")
        if scout_summary.get("stop_reason") in {"model_unavailable", "model_error"}:
            errors.append("Scout required model stage unavailable")
        if any(
            str(item.get("status", "")).lower() in {"error", "unavailable", "failed"}
            for item in attempts
        ) and not any(item.get("status") == "ok" for item in attempts):
            errors.append("required model stage has no successful response")
        if dataset.status != "synthetic" and not any(item.get("status") == "ok" for item in attempts):
            errors.append("no successful real model response recorded")
        if metrics.get("status") != "completed":
            errors.append("saved benchmark metrics record is not completed")
        if metrics.get("diagnostics"):
            errors.append("saved benchmark metrics contain technical diagnostics")
        config_digest = configuration.get("configuration_digest")
        if not config_digest or manifest.get("configuration_digest") != config_digest:
            errors.append("configuration digest does not match run manifest")
        if manifest.get("dataset_id") != dataset.id:
            errors.append("run dataset id does not match scorer dataset")
        if manifest.get("target_commit") != dataset.target_commit:
            errors.append("run target commit does not match scorer dataset")
        snapshot_dataset = (manifest.get("snapshot") or {}).get("dataset")
        if isinstance(snapshot_dataset, dict) and snapshot_dataset.get("id") != dataset.id:
            errors.append("run snapshot dataset does not match scorer dataset")
        current = {
            path.relative_to(run_root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(run_root.rglob("*"))
            if path.is_file() and path != run_root / "seal.json"
        }
        if seal != current:
            errors.append("artifact seal mismatch; saved run was modified or incomplete")
        report_id_list = [item.get("finding_id") for item in report_index if isinstance(item, dict)]
        report_ids = set(report_id_list)
        raw_ids = {item.get("id") for item in scout_findings if isinstance(item, dict)}
        if (
            None in report_ids or None in raw_ids or len(report_ids) != len(report_id_list)
            or len(raw_ids) != len(scout_findings) or not raw_ids.issubset(report_ids)
        ):
            errors.append("reports-index does not cover every Scout finding")
        loaded_report_ids = set(_report_index(pipeline))
        if loaded_report_ids != report_ids:
            errors.append("report files do not match reports-index")
        trace_ids = set(_trace_index(pipeline))
        if None in raw_ids or not raw_ids.issubset(trace_ids):
            errors.append("saved action traces do not cover every Scout finding")
        for row in report_index:
            report_path = row.get("report_path")
            resolved_report_path = pipeline / report_path if isinstance(report_path, str) else None
            if (
                resolved_report_path is None
                or not resolved_report_path.resolve().is_relative_to(pipeline.resolve())
                or not resolved_report_path.is_file()
            ):
                errors.append("reports-index references a missing report")
                break
        return sorted(set(errors))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        return ["malformed required artifact: " + str(exc)]


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
    if isinstance(score, BenchmarkScoreCollectionV2):
        if any(not item.technically_valid for item in score.slices):
            return "# Benchmark v2\n\nTECHNICALLY_INVALID; security metrics are N/A.\n"
        prefix = "# Benchmark v2\n\n"
        if score.dataset_status != "frozen_a04":
            prefix += "PROVISIONAL DATASET; diagnostic values only, not formal benchmark metrics.\n\n"
        return prefix + "\n".join(
            f"## {item.split.upper()} / {item.sample_kind}\n\n"
            f"Detection: TP={item.detection.tp}, FP={item.detection.fp}, "
            f"FN={item.detection.fn}, TN={item.detection.tn}.\n"
            f"Supported verified recall: {item.verification.supported_verified_recall!r}; "
            f"FPR: {item.verification.false_confirmation_rate!r}; "
            f"coverage: {item.verification.decision_coverage!r}; "
            f"abstention: {item.verification.abstention_rate!r}.\n"
            for item in score.slices
        )
    if not score.technically_valid:
        return "# Benchmark v2\n\nTECHNICALLY_INVALID; security metrics are N/A.\n"
    detection = score.detection
    verification = score.verification
    provisional = (
        "PROVISIONAL DATASET; diagnostic values only, not formal benchmark metrics.\n\n"
        if score.dataset_status != "frozen_a04" else ""
    )
    return (
        "# Benchmark v2\n\n" + provisional
        + f"Detection: TP={detection.tp}, FP={detection.fp}, FN={detection.fn}, TN={detection.tn}.\n\n"
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
    run_root = _run_root(artifacts.resolve())
    if output.resolve() == run_root or output.resolve().is_relative_to(run_root):
        raise ValueError("Offline score output must be outside the immutable artifact directory")
    pipeline = artifacts / "pipeline" if (artifacts / "pipeline").is_dir() else artifacts
    errors = _artifact_errors(run_root, pipeline.resolve(), dataset)
    observations = observations_from_artifacts(pipeline)
    partitions = sorted({(case.split, case.sample_kind) for case in dataset.cases})
    scores = [
        score_v2(
            dataset,
            observations,
            technically_valid=not bool(errors),
            technical_errors=errors,
            split=split,
            sample_kind=sample_kind,
        )
        for split, sample_kind in partitions
    ]
    score = scores[0] if len(scores) == 1 else BenchmarkScoreCollectionV2(
        dataset_id=dataset.id,
        dataset_status=dataset.status,
        slices=scores,
    )
    manifest = _json(run_root / "manifest.json", {}) or {}
    history = artifact_history(
        run_root,
        run_id=run_id,
        attempt_id=attempt_id or manifest.get("attempt_id") or manifest.get("run_id") or artifacts.name,
        retry_of=retry_of if retry_of is not None else manifest.get("retry_of"),
    )
    output.mkdir(parents=True, exist_ok=True)
    slice_payloads = {
        f"scorecard-v2-{item.split}-{item.sample_kind}.json": item.model_dump(mode="json")
        for item in scores
    }
    payloads = {
        "scorecard-v2.json": score.model_dump(mode="json"),
        "history-v2.json": history.model_dump(mode="json"),
        "observations-v2.json": [item.model_dump(mode="json") for item in observations],
        **slice_payloads,
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
