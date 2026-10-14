"""Offline DEV-only evaluation of discovery; cannot produce confirmed Evidence."""

from __future__ import annotations

import argparse
from pathlib import Path

import yaml

from agent.repository_scout import _has_read_provenance
from app.b03_acceptance import snapshot
from evaluation.baseline_adapter import observations_semgrep
from evaluation.benchmark_freeze import DIRECTORY, validate
from evaluation.benchmark_v2 import score_v2
from sast.identity import rule_family
from schemas.benchmark_v2 import BenchmarkDatasetV2, BenchmarkObservationV2
from schemas.scout import CandidateFindingBatch
from scripts.a08_finalize import read, seal_review, sha, write


def review(inputs, target, output):
    inputs, target, output = (Path(p).resolve() for p in (inputs, target, output))
    if output.exists() or output.is_relative_to(inputs) or inputs.is_relative_to(output):
        raise ValueError("Output must be fresh outside measured inputs")
    seal_review(inputs)
    if read(inputs / "completion.json")["status"] != "discovery_comparison_completed":
        raise ValueError("Incomplete discovery comparison")
    if snapshot(target) != read(inputs / "snapshot.json"):
        raise ValueError("Target snapshot changed")
    validate()
    dataset = BenchmarkDatasetV2.model_validate(yaml.safe_load((DIRECTORY / "ground_truth.yaml").read_text()))
    baseline = [BenchmarkObservationV2.model_validate(o) for o in observations_semgrep(
        read(inputs / "sast/raw-redacted.json"),
    )]
    scores = {"sast": score_v2(dataset, baseline, split="development", sample_kind="original")}
    review_rows = []
    for mode in ("round_robin", "handlers"):
        batch = CandidateFindingBatch.model_validate(read(inputs / mode / "candidates.json"))
        audit = read(inputs / mode / "summary.json")
        if audit["schedule_mode"] != mode or audit["stop_reason"] == "model_unavailable":
            raise ValueError("Invalid schedule/model result")
        ranges = {}
        for r in audit["reviewed_ranges"]:
            ranges.setdefault(r["file"], []).append((r["line_start"], r["line_end"]))
        observations = []
        for i, candidate in enumerate(batch.candidates):
            if not _has_read_provenance(candidate, ranges):
                raise ValueError("Candidate not bound to successful read source")
            identity = f"{mode}:scout:{i:02d}"
            observations.append(BenchmarkObservationV2(
                id=identity, source="model_scout", family=rule_family(candidate.rule_id),
                service="juice", source_file=candidate.file,
                line_start=candidate.line_start, line_end=candidate.line_end,
                verification="not_run", evidence_backed=False,
            ))
            review_rows.append({"id": identity, "schedule": mode, "file": candidate.file,
                                "line_start": candidate.line_start, "line_end": candidate.line_end,
                                "family": rule_family(candidate.rule_id), "title": candidate.title,
                                "read_binding": "passed", "runtime_verdict": "not_run",
                                "source_file_sha256": read(inputs / "snapshot.json")["files"][candidate.file]})
        scores[mode] = score_v2(dataset, [*baseline, *observations],
                                split="development", sample_kind="original")
    summary = {
        "schema_version": "b03.discovery-review.v1", "status": "dev_discovery_evaluated",
        "input_seal_sha256": sha(inputs / "seal.json"),
        "matcher_sha256": sha(Path("evaluation/benchmark_v2.py")),
        "scores": {key: {"detection": s.detection.model_dump(),
                          "detected_positive_case_ids": [c.case_id for c in s.cases
                              if c.expected == "vulnerable" and c.detected],
                          "positive_cases": sum(c.expected == "vulnerable" for c in s.cases),
                          "safe_cases": sum(c.expected == "safe" for c in s.cases)}
                   for key, s in scores.items()},
        "case_level_gain_over_sast": {m: scores[m].detection.tp - scores["sast"].detection.tp
                                      for m in ("round_robin", "handlers")},
        "confirmed_metrics": None, "holdout_evaluated": False,
        "limitations": ["One paired run, not statistical or causal improvement evidence",
                        "Ordinary full application source traversal; DEV-only labels used after discovery",
                        "Read bindings are not vulnerability confirmation; no runtime verifier run",
                        "Outside-DEV-catalog candidates are not automatically false positives"],
    }
    output.mkdir(parents=True)
    write(output / "summary.json", summary)
    write(output / "candidate-bindings.json", review_rows)
    for key, score in scores.items():
        write(output / f"score-{key}-dev.json", score.model_dump(mode="json"))
    write(output / "seal.json", {p.name: sha(p) for p in output.iterdir() if p.is_file()})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = review(args.inputs, args.target, args.output)
    print({"gain": result["case_level_gain_over_sast"], "holdout_evaluated": False})


if __name__ == "__main__":
    main()
