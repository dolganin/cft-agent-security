"""Operator-only saved A06 rescore, original samples and separate DEV/HOLDOUT.

Run from repository root with the project Python. No target/provider calls.
Original artifacts/locks are read-only; outputs are in a fresh sibling directory.
"""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

import yaml

from evaluation.benchmark_freeze import DIRECTORY, validate
from evaluation.benchmark_v2 import score_v2
from evaluation.scanner_baseline import load_profile, write
from schemas.benchmark_v2 import BenchmarkDatasetV2, BenchmarkObservationV2

RUN = Path("artifacts/a06/2026-10-13-attempt-001")
OUTPUT = Path("artifacts/a06/2026-10-13-scores")


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--artifacts', type=Path, default=RUN)
    parser.add_argument('--output', type=Path, default=OUTPUT)
    args = parser.parse_args()
    run, output = args.artifacts.resolve(), args.output.resolve()
    if output == run or output.is_relative_to(run) or run.is_relative_to(output):
        raise ValueError('Outputs must not overlap sealed inputs')
    if output.exists():
        raise ValueError("Do not overwrite previous scores")
    validate()
    _, scanner_lock = load_profile()
    manifest = json.loads((run / "manifest.json").read_text())
    seal = json.loads((run / "seal.json").read_text())
    actual = {p.relative_to(run).as_posix(): sha(p)
              for p in run.rglob("*") if p.is_file() and p.name != "seal.json"}
    if seal != actual:
        raise ValueError("Saved run seal mismatch")
    if manifest["dataset_lock_sha256"] != sha(DIRECTORY / "dataset.lock.json"):
        raise ValueError("Dataset lock mismatch")
    if manifest["scanner_lock"] != scanner_lock:
        raise ValueError("Scanner lock mismatch")
    valid = manifest["status"] in {"COMPLETED", "COMPLETED_WITH_LIMITATIONS"}
    data = BenchmarkDatasetV2.model_validate(yaml.safe_load((DIRECTORY / "ground_truth.yaml").read_text()))
    rows = []
    for view in ("sast", "dast", "union"):
        observations = [BenchmarkObservationV2.model_validate(o) for o in json.loads(
            (run / (view + "-observations-v2.json")).read_text())]
        for split in ("development", "holdout"):
            score = score_v2(data, observations, split=split, sample_kind="original",
                             technically_valid=valid, technical_errors=manifest["technical_errors"])
            repeat = score_v2(data, observations, split=split, sample_kind="original",
                              technically_valid=valid, technical_errors=manifest["technical_errors"])
            if score != repeat:
                raise ValueError("Offline rescore is not reproducible")
            write(output / (view + "-" + split + ".json"), score.model_dump(mode="json"))
            rows.append({"view": view, "split": split,
                         "positives": sum(c.expected == "vulnerable" for c in score.cases),
                         "negatives": sum(c.expected == "safe" for c in score.cases),
                         "detection": score.detection.model_dump() if valid else None,
                         "matched_ids": [c.case_id for c in score.cases if c.detected]})
    receipt = {"attempt_id": manifest["attempt_id"], "status": manifest["status"],
               "seconds": manifest["seconds"], "observations": manifest["observation_counts"],
               "scope": "Original detection only; separate DEV/HOLDOUT, not agent verification",
               "rows": rows, "offline_repeat_equal": True, "sealed_files_checked": len(seal),
               "scorer_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
               "scorer_source_sha256": sha(Path("evaluation/benchmark_v2.py")),
               "agent_confirmation_metrics": None, "mttr": None,
               "warnings": len(manifest["coverage_limitations"]),
               "source_unchanged": manifest["original_unchanged"],
               "cleanup_complete": manifest["cleanup_complete"]}
    write(output / "summary.json", receipt)
    print(json.dumps(receipt, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
