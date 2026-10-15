from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

import yaml

from evaluation.b02_baseline_adapter import observations_semgrep_b02
from evaluation.benchmark_freeze import validate as validate_frozen_dataset
from evaluation.benchmark_v2 import score_v2
from sast.profiles import classify_diagnostics, load_scan_profile, validate_target_snapshot
from sast.semgrep_runner import run_semgrep_scan
from schemas.benchmark_v2 import BenchmarkDatasetV2, BenchmarkObservationV2

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml"
PROFILE = ROOT / "sast/rules/juice-shop-v2/profile.yaml"


def canonical_scan_digest(raw: dict) -> str:
    comparable = {
        "version": raw.get("version"),
        "results": raw.get("results"),
        "paths_scanned": raw.get("paths", {}).get("scanned"),
    }
    encoded = json.dumps(comparable, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def development_dataset(expected_target_commit: str) -> BenchmarkDatasetV2:
    validate_frozen_dataset()
    raw = DATASET.read_bytes()
    lock = json.loads(DATASET.with_name("dataset.lock.json").read_text(encoding="utf-8"))
    relative = DATASET.relative_to(ROOT).as_posix()
    if hashlib.sha256(raw).hexdigest() != lock["input_sha256"].get(relative):
        raise ValueError("Frozen ground truth digest mismatch")
    source = yaml.safe_load(raw)
    if source.get("status") != "frozen_a04":
        raise ValueError("B02 requires the frozen A04 dataset")
    if source.get("target_commit") != expected_target_commit:
        raise ValueError("Dataset target commit differs from the scan profile")
    # Only DEV/original cases enter the scorer. No holdout anchors are emitted or scored.
    selected = [
        item for item in source["cases"]
        if item.get("split") == "development" and item.get("sample_kind") == "original"
    ]
    value = {**source, "cases": selected}
    return BenchmarkDatasetV2.model_validate(value)


def main() -> int:
    parser = argparse.ArgumentParser(description="Rescore A06 and B02 Semgrep on DEV/original only")
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/b02-sast-development")
    parser.add_argument("--reuse-raw", type=Path, metavar="INPUT_DIRECTORY",
                        help="Read saved raw artifacts from this directory; --output must be new")
    args = parser.parse_args()
    target = args.target.expanduser().resolve()
    output = args.output.expanduser().resolve()
    if output.exists() or output.is_relative_to(target):
        raise SystemExit("Output must be a new directory outside the target")
    inputs = args.reuse_raw.expanduser().resolve(strict=True) if args.reuse_raw else None
    if inputs is not None and (output.is_relative_to(inputs) or inputs.is_relative_to(output)):
        raise SystemExit("Output must be outside the saved input artifacts")

    profile = load_scan_profile(PROFILE)
    dataset = development_dataset(profile["target_commit"])
    target_snapshot_before = validate_target_snapshot(target, profile["target_commit"])
    target_commit = target_snapshot_before["commit"]
    if target_commit != profile["target_commit"]:
        raise SystemExit(f"Target commit mismatch: expected {profile['target_commit']}, got {target_commit}")
    previous_manifest = None
    if inputs is not None:
        previous_manifest = json.loads((inputs / "manifest.json").read_text(encoding="utf-8"))
        if (previous_manifest.get("profile_sha256") != profile["profile_sha256"]
                or previous_manifest.get("target_commit") != target_commit
                or previous_manifest.get("target_snapshot") != target_snapshot_before
                or previous_manifest.get("config_sha256") != profile["config_sha256"]):
            raise SystemExit("Saved raw manifest does not match current profile/target")

    output.mkdir(parents=True, exist_ok=False)
    raw_dir = output / "raw"
    raw_dir.mkdir()

    base_config = profile["config_files"][0]
    config_runs = {
        "a06_before": [base_config],
        "b02_agent": profile["config_files"],
        "b02_baseline": profile["config_files"],
    }
    scans = {}
    for name, configs in config_runs.items():
        raw_path = raw_dir / f"{name}.json"
        stderr_path = raw_dir / f"{name}.stderr.txt"
        if inputs is not None:
            raw_bytes = (inputs / "raw" / f"{name}.json").read_bytes()
            expected_digest = previous_manifest.get("raw_json_sha256", {}).get(name)
            if hashlib.sha256(raw_bytes).hexdigest() != expected_digest:
                raise SystemExit(f"Saved raw JSON digest mismatch: {name}")
            scans[name] = json.loads(raw_bytes)
            stderr_bytes = (inputs / "raw" / f"{name}.stderr.txt").read_bytes()
            if hashlib.sha256(stderr_bytes).hexdigest() != previous_manifest.get("stderr_sha256", {}).get(name):
                raise SystemExit(f"Saved scanner stderr digest mismatch: {name}")
            raw_path.write_bytes(raw_bytes)
            stderr_path.write_bytes(stderr_bytes)
        else:
            scan = run_semgrep_scan(target, config=configs)
            scans[name] = scan.raw
            raw_path.write_text(
                json.dumps(scan.raw, ensure_ascii=False, indent=2), encoding="utf-8", newline="\n"
            )
            stderr_path.write_text(scan.stderr, encoding="utf-8", newline="\n")

    versions = {name: raw.get("version") for name, raw in scans.items()}
    if any(version != profile["semgrep_version"] for version in versions.values()):
        raise SystemExit(f"Semgrep version mismatch; raw scans saved: {versions}")

    target_snapshot_after = validate_target_snapshot(target, profile["target_commit"])
    if target_snapshot_before != target_snapshot_after:
        raise SystemExit("Target source changed during scanning; saved raw artifacts are excluded")

    scorecards = {}
    diagnostic_classes = {}
    for name, raw in scans.items():
        observations = [BenchmarkObservationV2.model_validate(value) for value in observations_semgrep_b02(raw)]
        coverage, fatal = classify_diagnostics(raw)
        diagnostic_classes[name] = {"coverage_limitations": coverage, "fatal": fatal}
        scorecards[name] = score_v2(
            dataset, observations, technically_valid=not fatal,
            technical_errors=[item.get("message", "unknown diagnostic") for item in fatal],
            split="development", sample_kind="original",
        )
        (output / f"{name}-score.json").write_text(
            scorecards[name].model_dump_json(indent=2), encoding="utf-8", newline="\n"
        )

    dev_agent_digest = canonical_scan_digest(scans["b02_agent"])
    dev_baseline_digest = canonical_scan_digest(scans["b02_baseline"])
    identical = dev_agent_digest == dev_baseline_digest
    diagnostics_identical = scans["b02_agent"].get("errors") == scans["b02_baseline"].get("errors")
    if not identical:
        raise SystemExit("Agent and baseline alerts or scanned-file scope differ; score files are diagnostic only")

    family_counts = Counter(case.family for case in dataset.cases)
    cases_by_id = {case.id: case for case in dataset.cases}
    family_summary = {}
    for name, score in scorecards.items():
        rows = {}
        for family_name, total in sorted(family_counts.items()):
            family_cases = [case for case in score.cases if cases_by_id[case.case_id].family == family_name]
            tp = sum(case.detected and case.expected == "vulnerable" for case in family_cases)
            fp = sum(case.detected and case.expected == "safe" for case in family_cases)
            positives = sum(case.expected == "vulnerable" for case in family_cases)
            negatives = sum(case.expected == "safe" for case in family_cases)
            rows[family_name] = {
                "cases": total, "vulnerable": positives, "safe": negatives,
                "tp": tp, "fp": fp, "fn": positives - tp, "tn": negatives - fp,
                "coverage": (tp + fp) / total if total else None,
            }
        family_summary[name] = rows

    metadata = {
        "schema": "cft.b02-development-report.v1",
        "scope": {"split": "development", "sample_kind": "original"},
        "dataset": str(DATASET.relative_to(ROOT)),
        "dataset_digest": scorecards["b02_agent"].dataset_digest,
        "reused_from": str(inputs) if inputs is not None else None,
        "input_manifest_sha256": hashlib.sha256((inputs / "manifest.json").read_bytes()).hexdigest()
        if inputs is not None else None,
        "target_commit": target_commit,
        "target_snapshot": target_snapshot_before,
        "profile": profile["id"], "profile_version": profile["version"],
        "profile_sha256": profile["profile_sha256"],
        "semgrep_version": profile["semgrep_version"],
        "config_files": profile["config_files"], "config_sha256": profile["config_sha256"],
        "agent_baseline_alerts_and_scope_identical": identical,
        "agent_baseline_diagnostics_identical": diagnostics_identical,
        "agent_raw_digest": dev_agent_digest,
        "baseline_raw_digest": dev_baseline_digest,
        "raw_alerts": {name: len(raw.get("results", [])) for name, raw in scans.items()},
        "raw_json_sha256": {
            name: hashlib.sha256((raw_dir / f"{name}.json").read_bytes()).hexdigest()
            for name in scans
        },
        "parser_diagnostics": {name: len(raw.get("errors", [])) for name, raw in scans.items()},
        "coverage_limitations": {
            name: len(value["coverage_limitations"])
            for name, value in diagnostic_classes.items()
        },
        "fatal_diagnostics": {name: len(value["fatal"]) for name, value in diagnostic_classes.items()},
        "stderr_files": {
            name: str(raw_dir / f"{name}.stderr.txt") for name in scans
        },
        "stderr_sha256": {
            name: hashlib.sha256((raw_dir / f"{name}.stderr.txt").read_bytes()).hexdigest()
            for name in scans
        },
        "scanned_files": {
            name: len(raw.get("paths", {}).get("scanned", [])) for name, raw in scans.items()
        },
        "family_scores": family_summary,
        "metrics": {
            name: {
                key: getattr(score.detection, key) if score.detection is not None else None
                for key in ("tp", "fp", "fn", "tn", "precision", "recall", "duplicates",
                            "unresolved", "outside_ground_truth")
            }
            for name, score in scorecards.items()
        },
        "scored_case_count": len(dataset.cases),
        "caveats": [
            "Source SAST candidates are detection only; none is an Evidence-backed confirmation.",
            "DEV/original only. No HOLDOUT cases, anchors, or labels enter the score.",
            "Parser diagnostics and partial coverage are preserved in the raw Semgrep JSON.",
            "Identical-config repeat scans can report different per-rule timeout warnings; both raw diagnostics are retained.",
            "Dependency/SCA signals are not implemented by this ruleset.",
        ],
    }
    (output / "manifest.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8", newline="\n")
    lines = [
        "# B02 DEV/original SAST comparison", "",
        f"Target: `{target_commit}`; Semgrep CE `{profile['semgrep_version']}`.",
        f"Profile: `{profile['id']}`; raw alerts/scope equivalent for agent and baseline: **{identical}**.",
        f"Repeat-run parser diagnostics identical: **{diagnostics_identical}** (timeouts may vary).", "",
        "| Profile | TP | FP | FN | TN | Precision | Recall | Duplicates | Unresolved | Outside GT | Alerts | Parser diagnostics |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for name, score in scorecards.items():
        metric = score.detection
        lines.append(
            f"| {name} | {metric.tp} | {metric.fp} | {metric.fn} | {metric.tn} "
            f"| {metric.precision} | {metric.recall} | {metric.duplicates} "
            f"| {metric.unresolved} | {metric.outside_ground_truth} | {metadata['raw_alerts'][name]} "
            f"| {metadata['parser_diagnostics'][name]} |"
        )
    lines.extend(["", "## Family cases: TP / FP / FN / TN", ""])
    for family_name in sorted(family_counts):
        values = []
        for name in ("a06_before", "b02_agent"):
            row = family_summary[name][family_name]
            values.append(
                f"{name} {row['tp']}/{row['fp']}/{row['fn']}/{row['tn']}"
            )
        lines.append(f"- `{family_name}`: " + "; ".join(values))
    lines.extend([
        "", "SAST alerts are detection candidates only; this report contains zero Evidence-backed confirmations.",
        "The two DEV/original safe controls are included as negative cases. No holdout slice is scored.",
        "Raw JSON and stderr are retained under `raw/`; parser warnings and partial parse coverage remain visible.",
        "",
    ])
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
