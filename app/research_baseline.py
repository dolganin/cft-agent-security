"""R00: verify and rescore a portable B09 archive without modifying originals."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
import zipfile
from hashlib import sha256
from pathlib import Path, PurePosixPath

from app.b09_score import score


def verify_archive(path: Path) -> dict:
    expected = path.with_suffix(path.suffix + ".sha256").read_text().split()[0]
    actual = sha256(path.read_bytes()).hexdigest()
    if expected != actual:
        raise ValueError("Baseline archive digest mismatch")
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) > 10000 or len(names) != len(set(names)):
            raise ValueError("Invalid or duplicate baseline archive members")
        total = 0
        for info in archive.infolist():
            name = PurePosixPath(info.filename)
            total += info.file_size
            if (name.is_absolute() or ".." in name.parts or "\\" in info.filename
                    or any(":" in part for part in name.parts)
                    or (info.external_attr >> 16) & 0o170000 == 0o120000
                    or total > 256 * 1048576 or info.file_size > 32 * 1048576):
                raise ValueError("Unsafe or oversized baseline archive")
        if archive.testzip() is not None:
            raise ValueError("Baseline ZIP CRC mismatch")
        manifest = json.loads(archive.read("MANIFEST-SHA256.json"))
        if set(names) != set(manifest) | {"MANIFEST-SHA256.json"}:
            raise ValueError("Baseline manifest membership mismatch")
        for info in archive.infolist():
            if (info.filename != "MANIFEST-SHA256.json"
                    and sha256(archive.read(info.filename)).hexdigest() != manifest[info.filename]):
                raise ValueError("Baseline member digest mismatch")
    return {"archive_sha256": actual, "verified_files": len(manifest), "manifest": manifest}


def freeze(path: Path, output: Path, repo: Path):
    if output.exists():
        raise FileExistsError("Choose a fresh R00 output directory")
    verified = verify_archive(path)
    with tempfile.TemporaryDirectory(prefix="cft-r00-replay-") as directory:
        root = Path(directory)
        with zipfile.ZipFile(path) as archive:
            archive.extractall(root)  # membership/size/links verified before extraction
        runs = [p.parent for p in root.glob("*/run-result.json")
                if not (p.parent / "attempt-disposition.json").exists()
                or json.loads((p.parent / "attempt-disposition.json").read_text()).get("valid_measurement")]
        if len(runs) != 1:
            raise ValueError("Expected exactly one valid archived B09 run")
        run = runs[0]
        evaluation = run / "evaluation"
        originals = {p.name: sha256(p.read_bytes()).hexdigest()
                     for p in evaluation.iterdir() if p.is_file()}
        results = score(run, run / "benchmark/ground_truth.yaml")
        repeated = {p.name: sha256(p.read_bytes()).hexdigest()
                    for p in evaluation.iterdir() if p.is_file()}
        mismatches = sorted(name for name in originals if originals[name] != repeated.get(name))
        if mismatches:
            raise ValueError("Portable offline replay differs: " + ", ".join(mismatches))
        source = json.loads((run / "run-result.json").read_text())
        config = json.loads((run / "run-config.json").read_text())
        output.mkdir(parents=True)
        lock = {"schema": "research-baseline.v1", "archive": path.name,
                "archive_sha256": verified["archive_sha256"],
                "verified_archive_files": verified["verified_files"],
                "verified_replay_files": len(originals), "offline_replay_identical": True,
                "baseline_run": run.name, "run_result": source, "run_config": config,
                "development_base_commit": subprocess.check_output(
                    ["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip(),
                "dataset_sha256": sha256((run / "benchmark/ground_truth.yaml").read_bytes()).hexdigest(),
                "measurement": results,
                "limitations": {"final_runs": 1, "reproducibility": "N/A",
                                "mttr": "N/A", "cp_accuracy": "N/A",
                                "fresh_dast_baseline": False},
                "measurement_contract": {
                    "matching": "frozen A05 case matcher; deduplicate independent causes",
                    "positive_denominator": 27, "negative_denominator": 8,
                    "sample_kind": "original", "splits": ["development", "holdout"],
                    "holdout_independence": "historically inspected; no claim of unseen generalization",
                    "reported_fpr": "false confirmations/all safe cases; unresolved negatives reported",
                    "outside_ground_truth": "review separately, not automatic FP",
                    "comparative_spike": "DEV only; same model/inputs/scope/budgets; log exceptions",
                    "production_inputs": "projected source + observations, never evaluator labels",
                    "final_run_count": 1,
                }}
        (output / "baseline-lock.json").write_text(json.dumps(lock, indent=2) + "\n")
        (output / "archive-manifest.json").write_text(json.dumps(verified["manifest"], indent=2) + "\n")
        for name in sorted(originals):
            (output / name).write_bytes((evaluation / name).read_bytes())
        hashes = {p.name: sha256(p.read_bytes()).hexdigest() for p in output.iterdir() if p.is_file()}
        (output / "seal.json").write_text(json.dumps(hashes, indent=2) + "\n")
        return {"archive_files": verified["verified_files"], "replayed_files": len(originals),
                "archive_sha256": verified["archive_sha256"], "output": str(output)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path,
                        default=Path("artifacts/handoffs/b09-single-2026-10-15.zip"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(freeze(args.archive.resolve(), args.output.resolve(),
                            Path(__file__).resolve().parents[1]), indent=2))


if __name__ == "__main__":
    main()
