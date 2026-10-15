"""Offline frozen-A04 scoring of a bounded research campaign; no model calls."""
from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path

import yaml

from evaluation.b02_baseline_adapter import observations_semgrep_b02
from evaluation.benchmark_v2 import score_v2
from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from pipeline.research_verification import read_protocol_execution
from schemas.action import ActionProposal
from schemas.benchmark_v2 import BenchmarkDatasetV2, BenchmarkObservationV2
from schemas.execution import ExecutionResult
from schemas.finding import Finding
from schemas.validation import ValidationResult


def read(path):
    return json.loads(path.read_text())


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")


def validate_seal(root):
    seal = read(root / "seal.json")
    for name, expected in seal.items():
        path = (root / name).resolve(strict=True)
        if not path.is_relative_to(root.resolve()) or sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Research input seal mismatch: " + name)
    return len(seal)


def replay_runtime(root):
    """Recompute protocol Evidence using its approved action, execution and audit."""
    dispositions = []
    for path in sorted((root / "campaign/canonical-verification").glob("*/result.json")):
        row = read(path)
        action = ActionProposal.model_validate(row["action"])
        execution = ExecutionResult.model_validate(row["execution"])
        validation = ValidationResult.model_validate(row["validation"])
        evidence = row["evidence"]
        report = row["report"]
        if (not validation.approved or validation.action_id != action.id
                or not row.get("worker_cleanup_verified")
                or report["finding_id"] != row["finding_id"]
                or action.verification_binding.finding_id != row["finding_id"]):
            raise ValueError("Runtime review approval/finding/cleanup mismatch")
        record = read_protocol_execution(JsonExecutionEvidenceStore(path.parent / "execution"),
            JsonlAuditLog(path.parent / "audit.jsonl"), action, execution, evidence["sandbox_session_id"])
        # B06 replay reads its audit artifact. Resolve the already verified local
        # audit beside this result instead of following archived host paths. This
        # is an evaluator-only view; sealed execution/action bytes stay unchanged.
        replay_execution = execution.model_copy(update={"artifacts": [str(path.parent / "audit.jsonl")]})
        rebuilt = build_evidence(action=action, execution=replay_execution, record=record,
            evidence_loaded=True, artifact_refs=execution.artifacts,
            hypothesis_id=row["finding_id"], sandbox_session_id=evidence["sandbox_session_id"])
        if (rebuilt.verdict != row["status"] or rebuilt.verdict != evidence["verdict"]
                or rebuilt.source != "runtime" or rebuilt.reliability not in {"high", "medium"}):
            raise ValueError("Persisted runtime verdict failed independent replay")
        dispositions.append({"finding_id": row["finding_id"], "status": rebuilt.verdict,
            "route_id": action.verification_binding.route_id, "action_id": action.id,
            "capability": action.tool, "service": action.service, "endpoint": action.endpoint,
            "method": action.verification_binding.method,
            "evidence": str(path.relative_to(root)), "approval_execution_audit_replayed": True})
    return dispositions


def observation(finding, *, report=None, runtime=None):
    status = "not_run" if report is None else "inconclusive"
    if report and report["stop_reason"] in {"model_failure", "workflow_failure", "proposal_corrections_exhausted"}:
        status = "technical_error"
    if runtime:
        status = runtime["status"]
    return BenchmarkObservationV2(id=finding.id, source=finding.source,
        family=finding.provenance.family if finding.provenance else finding.rule_id,
        service=finding.service, source_file=finding.file,
        line_start=finding.line_start, line_end=finding.line_end,
        reported_verdict=report["status"] if report else None, verification=status,
        evidence_backed=bool(runtime and status in {"confirmed", "rejected"}),
        evidence=[runtime["evidence"]] if runtime else [],
        capability=runtime["capability"] if runtime else None,
        http_endpoint=runtime["endpoint"] if runtime else None,
        http_method=runtime["method"] if runtime else None)


def score_research(root, dataset_path, output):
    root, output = root.resolve(), output.resolve()
    if output.exists() or output.is_relative_to(root):
        raise ValueError("Use a fresh output directory outside the sealed run")
    sealed = validate_seal(root)
    result, manifest = read(root / "run-result.json"), read(root / "run-manifest.json")
    dataset = BenchmarkDatasetV2.model_validate(yaml.safe_load(dataset_path.read_text()))
    lock = read(dataset_path.parent / "dataset.lock.json")
    expected_truth = next((digest for name, digest in lock["input_sha256"].items()
                           if name.endswith("/ground_truth.yaml")), None)
    if (sha256(dataset_path.read_bytes()).hexdigest() != expected_truth
            or lock["target_commit"] != dataset.target_commit or lock["dataset_id"] != dataset.id):
        raise ValueError("Frozen ground truth lock mismatch")
    if (not result.get("completed") or not result.get("source_unchanged")
            or not result.get("target_cleanup_verified") or not result["campaign"]["cleanup_verified"]
            or manifest["target"]["commit"] != dataset.target_commit):
        raise ValueError("Incomplete research run or target identity/integrity/cleanup mismatch")
    findings = [Finding.model_validate(f) for f in read(root / "campaign/findings.json")]
    reports = {r["report"]["finding_id"]: r["report"] for r in read(root / "campaign/reports.json")
               if r["is_candidate"]}
    runtime_reviews = replay_runtime(root)
    runtime = {row["finding_id"]: row for row in runtime_reviews}
    if not set(runtime) <= {f.id for f in findings}:
        raise ValueError("Runtime verdict belongs to absent finding")
    observed = [observation(f, report=reports.get(f.id), runtime=runtime.get(f.id)) for f in findings]
    baseline = [BenchmarkObservationV2.model_validate(row) for row in
                observations_semgrep_b02(read(root / "sast/raw-redacted.json"))]
    summary = {"measurement": "bounded_research_diagnostic", "repetitions": 1,
        "input_seal_verified_files": sealed, "elapsed_seconds": result["elapsed_seconds"],
        "research_degraded": result["campaign"]["degraded"],
        "stop_reason": result["campaign"]["stop_reason"], "metrics": {},
        "scope": "Frozen original A04 cases; runtime confirmations only; source proofs separate",
        "mttr": None, "reproducibility": None, "severity_accuracy": None,
        "context_priority_accuracy": None, "negative_decision_fpr": None,
        "limitations": ["Research queue stopped at budget; pending findings remain in denominator.",
            "Independent source-condition MD5 proofs are not counted as runtime confirmations.",
            "Unmatched findings are not automatically false positives.",
            "Historical HOLDOUT has already informed development.",
            "Per-question model/proposal failures make this a degraded diagnostic, not clean acceptance."]}
    output.mkdir(parents=True)
    write(output / "observations.json", [o.model_dump(mode="json") for o in observed])
    write(output / "runtime-review.json", runtime_reviews)
    write(output / "source-reviews.json", read(root / "campaign/reviews.json"))
    losses, families = [], {}
    for split in ("development", "holdout"):
        scored = score_v2(dataset, observed, split=split, sample_kind="original")
        sast = score_v2(dataset, baseline, split=split, sample_kind="original")
        write(output / f"{split}-agent.json", scored.model_dump(mode="json"))
        write(output / f"{split}-sast.json", sast.model_dump(mode="json"))
        summary["metrics"][split] = {"detection": scored.detection.model_dump(),
            "verification": scored.verification.model_dump(), "sast_detection": sast.detection.model_dump()}
        groups = {}
        for case in scored.cases:
            group = groups.setdefault(case.family, {"positive": 0, "safe": 0, "detected_positive": 0,
                                                    "confirmed_positive": 0})
            group["positive" if case.expected == "vulnerable" else "safe"] += 1
            if case.expected == "vulnerable":
                group["detected_positive"] += int(case.detected)
                group["confirmed_positive"] += int(case.confirmation_supported)
                if not case.confirmation_supported:
                    losses.append({"split": split, "case_id": case.case_id, "family": case.family,
                                   "detected": case.detected, "verification": case.verification})
        families[split] = groups
    write(output / "case-losses.json", losses)
    write(output / "family-metrics.json", families)
    write(output / "summary.json", summary)
    write(output / "seal.json", {p.name: sha256(p.read_bytes()).hexdigest() for p in sorted(output.iterdir())})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--dataset", type=Path,
                        default=Path("benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml"))
    args = parser.parse_args()
    print(json.dumps(score_research(args.run, args.dataset, args.output), indent=2))


if __name__ == "__main__":
    main()
