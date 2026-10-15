"""Offline development scoring of sealed source candidates against frozen A04."""
from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path

import yaml

from app.juice_run_preflight import verify_frozen_benchmark
from app.research_handoff import verify_seal
from app.research_score import observation
from evaluation.b02_baseline_adapter import observations_semgrep_b02
from evaluation.benchmark_v2 import score_v2
from reporting.checkpoints import write_json
from schemas.benchmark_v2 import BenchmarkDatasetV2, BenchmarkObservationV2
from schemas.finding import Finding

ROOT = Path(__file__).resolve().parents[1]


def evaluate(run: Path, output: Path) -> dict:
    run, output = run.resolve(strict=True), output.resolve()
    if output.exists() or output.is_relative_to(run):
        raise ValueError("Use a fresh output directory outside the sealed scan")
    sealed = verify_seal(run)
    manifest = json.loads((run / "manifest.json").read_text())
    dataset = BenchmarkDatasetV2.model_validate(yaml.safe_load(
        (ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml").read_text()))
    verify_frozen_benchmark(ROOT, expected_commit=dataset.target_commit)
    if (manifest.get("schema") != "cft.juice.source-scan.v1"
            or manifest.get("target", {}).get("commit") != dataset.target_commit
            or not manifest.get("source_unchanged")):
        raise ValueError("Invalid source scan target or integrity")
    findings = [Finding.model_validate(v) for v in json.loads((run / "source-findings.json").read_text())]
    for finding in findings:
        provenance = finding.provenance
        if (finding.source != "juice_source_detector" or provenance is None
                or provenance.anchor_status != "source_bound"
                or manifest.get("source_sha256", {}).get(finding.file) != provenance.file_sha256
                or finding.line_start is None):
            raise ValueError("Source detector observation is not bound to the sealed source inventory")
    source = [observation(f) for f in findings]
    if any(o.verification != "not_run" or o.evidence_backed for o in source):
        raise ValueError("Source-only scan cannot contain runtime decisions")
    views = {"source_detector": source}
    if manifest.get("sast_enabled"):
        baseline = [BenchmarkObservationV2.model_validate(v) for v in observations_semgrep_b02(
            json.loads((run / "sast/raw-redacted.json").read_text()))]
        views.update({"sast": baseline, "combined": [*baseline, *source]})
    output.mkdir(parents=True)
    summary = {"schema": "cft.juice.source-progress.v1", "sealed_input_files": sealed,
        "source_scan_seal_sha256": sha256((run / "seal.json").read_bytes()).hexdigest(),
        "scope": "Development source detection only; no new runtime metrics",
        "runtime_confirmed": None, "runtime_recall": None, "runtime_fpr": None,
        "historical_holdout_used_for_development": True, "views": {}}
    for name, observations in views.items():
        positives, safe, rows = [], [], []
        for split in ("development", "holdout"):
            score = score_v2(dataset, observations, split=split, sample_kind="original")
            write_json(output / f"{name}-{split}.json", score.model_dump(mode="json"))
            rows.extend(score.cases)
            positives.extend(c.case_id for c in score.cases if c.expected == "vulnerable" and c.detected)
            safe.extend(c.case_id for c in score.cases if c.expected == "safe" and c.detected)
        denominator = sum(c.expected == "vulnerable" for c in rows)
        summary["views"][name] = {"detected_positive": len(positives), "positive_denominator": denominator,
            "detection_recall": len(positives) / denominator, "matched_positive_cases": sorted(positives),
            "safe_cases_with_candidate_alert": sorted(safe), "observations": len(observations)}
    write_json(output / "summary.json", summary)
    write_json(output / "seal.json", {p.name: sha256(p.read_bytes()).hexdigest()
        for p in sorted(output.iterdir()) if p.is_file()})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.run, args.output), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
