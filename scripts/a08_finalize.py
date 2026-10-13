"""Offline A08 readout. Never launches target, scanners or a model."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

import yaml

from evaluation.benchmark_freeze import DIRECTORY, validate
from evaluation.benchmark_v2 import score_v2
from evaluation.offline_rescore import observations_from_artifacts, rescore
from schemas.benchmark_v2 import BenchmarkDatasetV2, BenchmarkObservationV2


def read(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def seal_review(root, allowed_missing=()):
    root = Path(root)
    expected = read(root / "seal.json")
    actual = {p.relative_to(root).as_posix(): sha(p) for p in root.rglob("*")
              if p.is_file() and p != root / "seal.json"}
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    changed = sorted(k for k in expected.keys() & actual.keys() if expected[k] != actual[k])
    if extra or changed or set(missing) - set(allowed_missing):
        raise ValueError(f"Unexplained seal mismatch: {root.name}: {missing}, {extra}, {changed}")
    return {"sealed_files": len(expected), "received_files": len(actual),
            "full_seal_verified": not missing, "available_files_verified": True,
            "declared_missing": missing, "extra": extra, "changed": changed}


def write(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n")


def csv_rows(path, rows):
    with Path(path).open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def overlaps(anchor, observation):
    return (observation.source_file == anchor.file and observation.line_start is not None
            and observation.line_start <= anchor.line_end
            and anchor.line_start <= (observation.line_end or observation.line_start))


def loss_rows(dataset, scores, observations, scout, scope):
    results = {c.case_id: c for s in scores for c in s.cases}
    rows = []
    for case in dataset.cases:
        result = results[case.id]
        anchors = case.source_anchors
        full_reads = [a for a in anchors if any(
            r["file"] == a.file and r["line_start"] <= a.line_start and r["line_end"] >= a.line_end
            for r in scout.get("reviewed_ranges", []))]
        anchored = [o for o in observations if o.sample_kind == case.sample_kind
                    and any(overlaps(a, o) for a in anchors)]
        if case.sample_kind != "original":
            reason = "control_not_executed_in_a07"
        elif result.confirmation_supported:
            reason = "confirmed_evidence"
        elif result.detected:
            reason = "evidence_insufficient" if result.verification == "inconclusive" else result.verification
        elif anchored:
            reason = "binding_family_mismatch"
        elif full_reads:
            reason = "discovery_no_candidate_after_anchor_read"
        else:
            reason = "discovery_no_candidate_no_full_anchor_read"
        rows.append({
            "case_id": case.id, "family": case.family, "split": case.split,
            "sample_kind": case.sample_kind, "expected": case.expected,
            "runtime_eligible": scope[case.id]["runtime_eligible"],
            "detected": result.detected, "verification": result.verification,
            "confirmation_supported": result.confirmation_supported, "loss_stage": reason,
            "source_anchors": ";".join(f"{a.file}:{a.line_start}-{a.line_end}" for a in anchors),
            "scout_fully_read_anchors": ";".join(f"{a.file}:{a.line_start}-{a.line_end}" for a in full_reads),
            "scout_fully_read_anchor_roles": ";".join(a.role for a in full_reads),
            "anchored_observation_ids": ";".join(o.id for o in anchored),
            "matched_observation_ids": ";".join(result.matched_observation_ids),
        })
    return rows


def finalize(inputs, output, original_pipeline_root, allow_missing):
    inputs, output = Path(inputs).resolve(), Path(output).resolve()
    if output.exists() or output.is_relative_to(inputs) or inputs.is_relative_to(output):
        raise ValueError("Output must be a fresh directory outside immutable inputs")
    validate()
    dataset = BenchmarkDatasetV2.model_validate(yaml.safe_load((DIRECTORY / "ground_truth.yaml").read_text()))
    scope = {c["id"]: c for c in yaml.safe_load((DIRECTORY / "scope.yaml").read_text())["cases"]}
    run = inputs / "a07-series/agent-run-01-retry-01"
    audits = {p.parent.name: seal_review(p.parent) for p in (inputs / "a07-series").glob("agent-run-*/seal.json")}
    if len(audits) != 4:
        raise ValueError("Expected all four preserved A07 attempts")
    manifest = read(run / "manifest.json")
    if manifest["dataset_lock_sha256"] != sha(DIRECTORY / "dataset.lock.json"):
        raise ValueError("A07 dataset lock mismatch")
    if manifest["target_commit"] != dataset.target_commit:
        raise ValueError("A07 target mismatch")
    if manifest["matcher_sha256"] != sha(Path("evaluation/benchmark_v2.py")):
        raise ValueError("A07 matcher mismatch")
    config = read(inputs / "a07-series/a07-config.json")
    digest = config.pop("configuration_digest")
    computed = hashlib.sha256(json.dumps(config, sort_keys=True, ensure_ascii=False,
                                          separators=(",", ":")).encode()).hexdigest()
    if computed != digest or manifest["configuration_digest"] != digest:
        raise ValueError("A07 configuration digest mismatch")
    output.mkdir(parents=True)
    score = rescore(dataset, run, output / "agent-rescore", run_id="a08-final",
                    original_pipeline_root=original_pipeline_root)
    if not all(s.technically_valid for s in score.slices):
        raise ValueError("A07 offline validation failed; inspect saved diagnostics")
    for s in score.slices:
        saved = read(inputs / f"a07-series/score-agent-run-01-retry-01/scorecard-v2-{s.split}-{s.sample_kind}.json")
        if s.model_dump(mode="json") != saved:
            raise ValueError("A07 saved score differs from recomputation")
    observations = observations_from_artifacts(run / "pipeline")
    scout = read(run / "pipeline/scout/summary.json")
    rows = loss_rows(dataset, score.slices, observations, scout, scope)
    csv_rows(output / "case-losses.csv", rows)
    baseline = []
    for number in (1, 2, 3):
        root = inputs / f"a06-series/run-{number:02d}"
        audit = seal_review(root, ["sast/source.tar"] if allow_missing else [])
        m = read(root / "manifest.json")
        if m["dataset_lock_sha256"] != sha(DIRECTORY / "dataset.lock.json") or m["status"] not in {
            "COMPLETED", "COMPLETED_WITH_LIMITATIONS",
        }:
            raise ValueError("A06 frozen dataset/status mismatch")
        profile = yaml.safe_load(Path("benchmarks/baselines-a06-v5/profile.yaml").read_text())
        if (m.get("profile") != profile
                or m.get("scanner_lock") != read("benchmarks/baselines-a06-v5/scanners.lock.json")
                or m.get("original_unchanged") is not True
                or m.get("cleanup_complete") is not True):
            raise ValueError("A06 scanner/scope/integrity configuration mismatch")
        measurements = []
        for view in ("sast", "dast", "union"):
            obs = [BenchmarkObservationV2.model_validate(o) for o in read(root / f"{view}-observations-v2.json")]
            for split in ("development", "holdout"):
                s = score_v2(dataset, obs, split=split, sample_kind="original")
                saved = read(inputs / f"a06-series/score-{number:02d}/{view}-{split}.json")
                if s.model_dump(mode="json") != saved:
                    raise ValueError(f"A06 saved score differs: {number}/{view}/{split}")
                write(output / f"baseline/run-{number:02d}-{view}-{split}.json", s.model_dump(mode="json"))
                measurements.append({"view": view, "split": split,
                                     "detection": s.detection.model_dump(),
                                     "matched_ids": sorted(c.case_id for c in s.cases if c.detected)})
        baseline.append({"run": number, "seconds": m["seconds"], "input_integrity": audit,
                         "observation_counts": m["observation_counts"], "measurements": measurements,
                         "score_basis": "verified available normalized observations, not full strict bundle validation"})
    # Union across evaluation splits, never count the other split as unknown.
    known = {i for s in score.slices if s.sample_kind == "original"
             for c in s.cases for i in c.matched_observation_ids}
    outside = []
    reports = {read(p)["finding_id"]: read(p) for p in (run / "pipeline/reports").glob("*.json")}
    for o in observations:
        if o.id not in known:
            report = reports[o.id]
            outside.append({"id": o.id, "source": o.source, "file": o.source_file,
                            "line": o.line_start, "family": o.family, "status": report["status"],
                            "evidence_backed": o.evidence_backed,
                            "scope": ";".join(e["scope"]["description"] for e in report["evidence"]),
                            "rule": "excluded from benchmark TP/FP, retained for independent review"})
    csv_rows(output / "outside-findings.csv", outside)
    positive_rows = [r for r in rows if r["sample_kind"] == "original" and r["expected"] == "vulnerable"]
    summary = {
        "schema_version": "a08.readout.v1", "status": "complete_with_declared_limitations",
        "input_root": "a06-series and a07-series from supplied handoff",
        "a07_attempt_seals": audits, "successful_agent_runs": 1,
        "agent_configuration_digest": digest, "matcher_sha256": sha(Path("evaluation/benchmark_v2.py")),
        "offline_reader_sha256": sha(Path("evaluation/offline_rescore.py")),
        "readout_script_sha256": sha(Path(__file__)),
        "original_positive_inventory": dict(Counter(r["loss_stage"] for r in positive_rows)),
        "case_count": len(rows), "outside_observations": len(outside),
        "agent_original_scores": [s.model_dump(mode="json") for s in score.slices if s.sample_kind == "original"],
        "baseline": baseline, "agent_run_reproducibility": None,
        "mttr": None, "severity_accuracy": None, "context_priority_accuracy": None,
        "patched_synthetic_agent_controls_executed": 0,
        "limitations": ["single valid agent run", "three declared A06 source snapshots omitted",
                        "different baseline and agent discovery configurations",
                        "no successful negative benchmark verdicts", "no severity/CP accuracy or MTTR",
                        "public previously inspected holdout is not unseen/generalization evidence"],
    }
    write(output / "summary.json", summary)
    write(output / "seal.json", {p.relative_to(output).as_posix(): sha(p)
                                 for p in output.rglob("*") if p.is_file()})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--original-pipeline-root", required=True)
    parser.add_argument("--allow-missing-a06-source", action="store_true",
                        help="Accept only declared source.tar omissions; never claim full seal validation")
    args = parser.parse_args()
    result = finalize(args.inputs, args.output, args.original_pipeline_root, args.allow_missing_a06_source)
    print(json.dumps({"status": result["status"], "case_count": result["case_count"],
                      "positive_inventory": result["original_positive_inventory"],
                      "baseline_scores_reproduced": 18, "output": str(args.output)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
