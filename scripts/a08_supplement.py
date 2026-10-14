"""Additive, offline family metrics and stage accounting from sealed A08 data."""

from __future__ import annotations

import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path

from scripts.a08_finalize import csv_rows, read, seal_review, sha, write

STAGES = ("scanner", "scout", "binding", "capability", "policy", "limits", "llm", "evidence")


def truth(value):
    if value not in {"True", "False"}:
        raise ValueError("Invalid case boolean")
    return value == "True"


def family_metrics(rows):
    groups = defaultdict(list)
    for row in rows:
        groups[(row["split"], row["sample_kind"], row["family"])].append(row)
    result = []
    for (split, sample, family), cases in sorted(groups.items()):
        positive = [r for r in cases if r["expected"] == "vulnerable"]
        safe = [r for r in cases if r["expected"] == "safe"]
        confirmed = sum(truth(r["confirmation_supported"]) for r in positive)
        fp = sum(r["verification"] == "confirmed" for r in safe)
        rejected = sum(r["verification"] == "rejected" for r in safe)
        detected = sum(truth(r["detected"]) for r in positive)
        executed = sample == "original"
        result.append({
            "split": split, "sample_kind": sample, "family": family,
            "positive_cases": len(positive), "safe_cases": len(safe),
            "detected_positive": detected, "confirmed_positive": confirmed,
            "false_positive_cases": fp, "rejected_safe": rejected,
            "status": "measured" if executed else "not_executed",
            "detection_recall": detected / len(positive) if positive and executed else None,
            "confirmation_recall": confirmed / len(positive) if positive and executed else None,
            "precision": confirmed / (confirmed + fp) if executed and confirmed + fp else None,
            "false_positive_rate": fp / len(safe) if safe and executed else None,
            "safe_decision_coverage": (rejected + fp) / len(safe) if safe and executed else None,
        })
    return result


def stage_accounting(rows):
    result = []
    for row in rows:
        stages = {stage: "unknown" for stage in STAGES}
        reason = row["loss_stage"]
        if row["sample_kind"] != "original":
            stages = dict.fromkeys(STAGES, "not_executed")
        else:
            stages["scout"] = ("full_anchor_read" if row["scout_fully_read_anchors"]
                               else "no_full_anchor_read_recorded")
            stages["binding"] = ("matched" if truth(row["detected"]) else
                                 "family_mismatch" if reason == "binding_family_mismatch"
                                 else "no_case_match")
            stages["evidence"] = ("confirmation_supported" if truth(row["confirmation_supported"])
                                  else "insufficient" if reason == "evidence_insufficient"
                                  else "no_case_linked_confirmation")
        result.append({"case_id": row["case_id"], "split": row["split"],
                       "sample_kind": row["sample_kind"], "expected": row["expected"],
                       "observed_loss": reason, **stages,
                       "causal_attribution": "not_established",
                       "basis": "sealed case-losses.csv; accounting not root-cause inference"})
    return result


def supplement(source, handoff, output):
    source, handoff, output = (Path(p).resolve() for p in (source, handoff, output))
    if output.exists() or any(output.is_relative_to(p) or p.is_relative_to(output)
                              for p in (source, handoff)):
        raise ValueError("Output must be fresh and outside immutable inputs")
    audit = seal_review(source)
    with (source / "case-losses.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    if len(rows) != 41 or len({r["case_id"] for r in rows}) != 41:
        raise ValueError("Expected 41 distinct A08 cases")
    # Reconcile every CSV outcome with independently stored scorer rows.
    cases = {r["case_id"]: r for p in (source / "agent-rescore").glob("scorecard-v2-*-*.json")
             for r in read(p)["cases"]}
    if set(cases) != {r["case_id"] for r in rows}:
        raise ValueError("Case membership differs from scorecards")
    for row in rows:
        case = cases[row["case_id"]]
        if any(case[k] != truth(row[k]) for k in ("detected", "confirmation_supported")) or any(
            case[k] != row[k] for k in ("family", "expected", "verification")
        ):
            raise ValueError("Case CSV differs from scorecard")
    integrity = {f"run-{i:02d}": seal_review(handoff / f"a06-series/run-{i:02d}",
                                           ["sast/source.tar"]) for i in (1, 2, 3)}
    families = family_metrics(rows)
    stages = stage_accounting(rows)
    full_inputs = all(a["full_seal_verified"] for a in integrity.values())
    baseline = []
    for path in sorted((source / "baseline").glob("*.json")):
        score = read(path)
        by_id = {c["case_id"]: c for c in score["cases"]}
        subset = []
        for row in rows:
            if row["case_id"] in by_id:
                c = by_id[row["case_id"]]
                subset.append({**row, "detected": str(c["detected"]),
                               "confirmation_supported": "False", "verification": "not_run"})
        baseline.append({"artifact": path.name, "family_detection": family_metrics(subset),
                         "verification_measured": False})
    summary = {
        "schema_version": "a08.supplement.v1",
        "status": ("analysis_complete_with_measurement_limits" if full_inputs else
                   "analysis_complete_input_integrity_partial"),
        "source_seal_sha256": sha(source / "seal.json"), "source_output_integrity": audit,
        "a06_integrity": integrity, "case_count": len(rows), "family_metrics": families,
        "stage_counts": {s: dict(Counter(r[s] for r in stages)) for s in STAGES},
        "baseline": baseline, "new_runs": 0, "mttr": None, "agent_reproducibility": None,
        "limitations": ([] if full_inputs else
                        ["Original A06 source archives absent; full input seal unverified"]) + [
                        "Unknown stage attribution is not evidence of policy/LLM/capability failure",
                        "One valid agent run; baseline configurations differ",
                        "Outside-ground-truth observations excluded from family metrics",
                        "No binary safe verdicts; FPR zero does not demonstrate safe rejection",
                        "Patched/synthetic controls not executed; severity/CP accuracy unavailable"],
    }
    output.mkdir(parents=True)
    csv_rows(output / "family-metrics.csv", families)
    csv_rows(output / "stage-accounting.csv", stages)
    write(output / "summary.json", summary)
    write(output / "seal.json", {p.name: sha(p) for p in output.iterdir() if p.is_file()})
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--handoff", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = supplement(args.source, args.handoff, args.output)
    print(result["status"])


if __name__ == "__main__":
    main()
