"""Offline B09 scoring, preserving frozen A04 matching and raw artifacts."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from collections import Counter
from pathlib import Path

import yaml

from app.b09_run import write_json
from evaluation.b02_baseline_adapter import observations_semgrep_b02
from evaluation.benchmark_v2 import score_v2
from evaluation.offline_rescore import observations_from_artifacts
from evaluation.scoring_b08 import evaluate_scoring
from sast.profiles import classify_diagnostics
from schemas.benchmark_v2 import BenchmarkDatasetV2, BenchmarkObservationV2
from schemas.report import FinalReport


def read(path):
    return json.loads(path.read_text())


def normalize_fixture_evidence(pipeline):
    """Copy exact B06 records, retaining originals and recording provenance."""
    evidence = pipeline / "evidence"
    evidence.mkdir(exist_ok=True)
    inventory = []
    for source in sorted((pipeline / "b06-runtime").glob("*/execution/execution-*.json")):
        destination = evidence / source.name
        raw = source.read_bytes()
        if destination.exists() and destination.read_bytes() != raw:
            raise ValueError("Execution reference collision")
        if not destination.exists():
            shutil.copyfile(source, destination)
        inventory.append({"source": str(source.relative_to(pipeline)),
            "destination": str(destination.relative_to(pipeline)),
            "sha256": hashlib.sha256(raw).hexdigest()})
    audit = pipeline / "audit/executor.jsonl"
    audit.parent.mkdir(exist_ok=True)
    lines = audit.read_text().splitlines() if audit.exists() else []
    for source in sorted((pipeline / "b06-runtime").glob("*/audit.jsonl")):
        for line in source.read_text().splitlines():
            if line and line not in lines:
                lines.append(line)
    if lines:
        audit.write_text("\n".join(lines) + "\n")
    return inventory


def score(root, dataset_path):
    pipeline = root / "pipeline"
    destination = root / "evaluation"
    destination.mkdir(exist_ok=True)
    dataset = BenchmarkDatasetV2.model_validate(yaml.safe_load(dataset_path.read_text()))
    normalization = normalize_fixture_evidence(pipeline)
    raw = read(pipeline / "sast/semgrep.json")
    warnings, fatal = classify_diagnostics(raw)
    result = read(root / "run-result.json")
    ci = read(pipeline / "ci-summary.json")
    errors = []
    disposition = root / "attempt-disposition.json"
    if disposition.exists() and read(disposition).get("valid_measurement") is False:
        errors.append(read(disposition)["reason"])
    if result.get("target_snapshot_after", {}).get("commit") != dataset.target_commit:
        errors.append("Benchmark and target commits differ")
    if not result.get("source_unchanged"):
        errors.append("Target source changed")
    if fatal:
        errors.append("Fatal or unclassified SAST diagnostics")
    observations = observations_from_artifacts(pipeline)
    reports = [FinalReport.model_validate(read(p)) for p in sorted((pipeline / "reports").glob("*.json"))]
    traces = [read(p) for p in (pipeline / "traces").glob("*.json")]
    ids = {item.id for item in observations}
    if (not ids or ids != {item.finding_id for item in reports}
            or ids != {item.get("finding_id") for item in traces}
            or len(ids) != len(reports) or len(ids) != len(traces)):
        errors.append("Incomplete or duplicate finding/report/trace queue")
    if ci.get("status") != "completed":
        errors.append("Canonical CI pipeline did not complete successfully")
    attempts_path = pipeline / "audit/llm-attempts.jsonl"
    attempts = [json.loads(line) for line in attempts_path.read_text().splitlines()
                if line] if attempts_path.exists() else []
    if not any(item.get("status") == "ok" for item in attempts):
        errors.append("No successful real model calls")
    report_by_id = {item.finding_id: item for item in reports}
    for item in observations:
        report = report_by_id.get(item.id)
        if report and report.stop_reason in {"model_failure", "workflow_failure"}:
            item.verification = "technical_error"
            item.evidence_backed = False
    baseline = [BenchmarkObservationV2.model_validate(item) for item in observations_semgrep_b02(raw)]
    write_json(destination / "observations.json", [item.model_dump(mode="json") for item in observations])
    scores = {}
    for split in ("development", "holdout"):
        agent = score_v2(dataset, observations, split=split, sample_kind="original",
                         technically_valid=not errors, technical_errors=errors)
        sast = score_v2(dataset, baseline, split=split, sample_kind="original",
                        technically_valid=not errors, technical_errors=errors)
        write_json(destination / f"{split}-agent.json", agent.model_dump(mode="json"))
        write_json(destination / f"{split}-sast.json", sast.model_dump(mode="json"))
        scores[split] = {"detection": agent.detection.model_dump() if agent.detection else None,
                        "verification": agent.verification.model_dump() if agent.verification else None,
                        "sast_detection": sast.detection.model_dump() if sast.detection else None}
        selected = dataset.model_copy(update={"cases": [c for c in dataset.cases
                           if c.split == split and c.sample_kind == "original"]})
        mapping = {}
        for case_result in agent.cases:
            identifier = case_result.primary_observation_id
            if not identifier:
                continue
            finding = report_by_id[identifier].finding
            case = next(case for case in selected.cases if case.id == case_result.case_id)
            if any(anchor.file == finding.file and finding.line_start is not None
                   and anchor.line_start <= (finding.line_end or finding.line_start)
                   and finding.line_start <= anchor.line_end for anchor in case.source_anchors):
                mapping[case.id] = identifier
        write_json(destination / f"{split}-scoring.json", evaluate_scoring(selected, reports, mapping))
    summary = {"technically_valid": not errors, "technical_errors": errors,
        "sast_coverage_warnings": len(warnings), "queue_size": len(observations),
        "reported_verdicts": dict(Counter(r.status for r in reports)),
        "evidence_backed_binary_observations": sum(item.evidence_backed for item in observations),
        "metrics": scores, "repetitions": 1, "reproducibility": None, "mttr": None,
        "limitations": ["Only frozen A04 original cases, DEV and HOLDOUT separately.",
                        "Out-of-truth findings are not automatically false positives.",
                        "Known Semgrep warnings mean incomplete source coverage.",
                        "No new DAST baseline or repair measurement.",
                        "B05 write-v3 is not accepted; no claim of full Stage B completion."]}
    write_json(destination / "normalization.json", normalization)
    write_json(destination / "summary.json", summary)
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--dataset", type=Path,
                        default=Path("benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml"))
    args = parser.parse_args()
    print(json.dumps(score(args.artifacts.resolve(), args.dataset.resolve()), indent=2))


if __name__ == "__main__":
    main()
