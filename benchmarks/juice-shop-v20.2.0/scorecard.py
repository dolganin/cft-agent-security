"""Render sealed Stage 2 results without running the producer or rewriting its artifacts."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from itertools import combinations
from pathlib import Path
from statistics import mean

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from evaluation.benchmark_harness import (
    artifact_hashes,
    digest,
    read_json,
    read_jsonl,
    write_json,
)
from schemas.benchmark import BenchmarkAggregate


def build(directory: Path):
    aggregate = BenchmarkAggregate.model_validate(read_json(directory / "aggregate.json"))
    runs, cases, anchor_sets = [], {}, {}
    for result in aggregate.runs:
        run = directory / result.run_id
        seal = read_json(run / "seal.json")
        if seal != artifact_hashes(run):
            raise ValueError("Run seal mismatch: " + result.run_id)
        manifest = read_json(run / "manifest.json")
        if manifest["configuration_digest"] != aggregate.configuration_digest:
            raise ValueError("Run configuration mismatch")
        raw = read_json(run / "raw-findings.json")["detection"]
        by_id = {o["id"]: o for o in raw}
        diagnostic = read_jsonl(run / "pipeline/audit/llm-attempts.jsonl")
        # A fallback notification has no provider and is not an API request.
        requests = [event for event in diagnostic if event.get("provider") is not None]
        fallback = [event for event in diagnostic if event.get("status") == "fallback"]
        d = result.detection.detection
        v = result.detection.verification
        scout = read_json(run / "pipeline/scout/summary.json")
        runs.append(
            {
                "run_id": result.run_id,
                "status": result.status,
                "configuration_digest": result.configuration_digest,
                "seal_sha256": digest((run / "seal.json").read_bytes()),
                "tp": d.tp,
                "fp": d.fp,
                "fn": d.fn,
                "tn": d.tn,
                "precision": d.precision,
                "recall": d.recall,
                "f1": d.f1,
                "duplicates": d.duplicates,
                "outside_ground_truth": d.outside_ground_truth,
                "verified_positives": v.correctly_confirmed,
                "false_confirmations": v.false_confirmations,
                "verification_statuses": v.statuses,
                "confirmation_rate": v.confirmation_rate,
                "verified_recall": v.end_to_end_verified_recall,
                "duration_seconds": result.performance["total_seconds"],
                "tool_actions": result.performance["tool_actions"],
                "llm_requests": len(requests),
                "llm_request_statuses": dict(Counter(e["status"] for e in requests)),
                "llm_fallback_notifications": len(fallback),
                "llm_diagnostic_events": len(diagnostic),
                "actual_model_routes": sorted(
                    {(e["provider"] + "/" + e["model"]) for e in requests}
                ),
                "scout_reviewed_lines": scout.get("reviewed_source_lines"),
                "scout_indexed_lines": scout.get("indexed_source_lines"),
                "scout_recall_delta": d.recall - result.baseline.detection.recall,
            }
        )
        anchor_sets[result.run_id] = {
            (o["artifact"], o["line_start"], o["line_end"] or o["line_start"], o["family"])
            for o in raw
        }
        for c in result.detection.cases:
            matched = [by_id[oid] for oid in c.all_matched_findings]
            supporting = [
                o for o in matched if o["evidence_backed"] and o["verification"] == "confirmed"
            ]
            entry = cases.setdefault(
                c.case_id, {"expected": c.expected, "category": c.category, "runs": []}
            )
            entry["runs"].append(
                {
                    "run_id": result.run_id,
                    "detected": c.detected,
                    "primary_finding": c.finding_id,
                    "primary_reported_verdict": c.reported_verdict,
                    "primary_verification_status": c.verification,
                    "all_matched_findings": c.all_matched_findings,
                    "detection_sources": sorted({o["source"] for o in matched}),
                    "confirmation_supported": c.confirmation_supported,
                    "confirmed_by": [
                        {
                            "finding_id": o["id"],
                            "source": o["source"],
                            "capability": o["capability"],
                            "evidence_refs": o["evidence"],
                        }
                        for o in supporting
                    ],
                    "all_evidence_refs": sorted({ref for o in matched for ref in o["evidence"]}),
                }
            )
    for cid, entry in cases.items():
        entry.update(aggregate.stability[cid])
    pairwise = []
    for a, b in combinations(anchor_sets, 2):
        intersection, union = anchor_sets[a] & anchor_sets[b], anchor_sets[a] | anchor_sets[b]
        pairwise.append(
            {
                "a": a,
                "b": b,
                "shared_unique_anchors": len(intersection),
                "union_unique_anchors": len(union),
                "jaccard": len(intersection) / len(union) if union else None,
            }
        )
    output = {
        "schema_version": "stage2.scorecard.v1",
        "producer": "pentester",
        "dataset": manifest["dataset_id"],
        "configuration_digest": aggregate.configuration_digest,
        "reporter_sha256": digest(Path(__file__).read_bytes()),
        "runs": runs,
        "cases": cases,
        "stability_summary": aggregate.stability_summary,
        "anchor_set_pairwise": pairwise,
        "mean_duration_seconds": mean(r["duration_seconds"] for r in runs),
        "mean_llm_requests": mean(r["llm_requests"] for r in runs),
        "technical_failure_rate": aggregate.technical_failure_rate,
        "notes": [
            "Precision adjudicates only labeled cases; outside findings are not automatically FP.",
            "Primary llm_calls counts diagnostic events; llm_requests here counts actual provider attempts.",
            "Confirmation can come from a duplicate; confirmed_by includes that finding's Evidence.",
            "unstable_verdicts includes measurement status changes (timeout/error), not only report verdict changes.",
        ],
    }
    write_json(directory / "scorecard.json", output)
    lines = [
        "# Stage 2 final scorecard",
        "",
        f"Dataset: {output['dataset']}",
        f"Configuration: {aggregate.configuration_digest}",
        "",
        "Recall relative to benchmark-v1 scope; precision only over adjudicated cases.",
        "",
        "| Run | TP | FP | FN | TN | Recall | F1 | Confirmed positives | Inconclusive | Timeout | Error | Seconds | LLM requests |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for r in runs:
        s = r["verification_statuses"]
        lines.append(
            f"| {r['run_id']} | {r['tp']} | {r['fp']} | {r['fn']} | {r['tn']} | "
            f"{r['recall']} | {r['f1']} | {r['verified_positives']} | {s.get('inconclusive', 0)} | "
            f"{s.get('timeout', 0)} | {s.get('technical_error', 0)} | {r['duration_seconds']} | {r['llm_requests']} |"
        )
    lines.extend(
        [
            "",
            "## Case results",
            "",
            "| Case | Expected | Found | Evidence confirmed | Measurement statuses | Confirmed by |",
            "|---|---|---|---|---|---|",
        ]
    )
    for cid, c in cases.items():
        by = [
            f"{r['run_id']}: {o['source']}/{o['capability']}"
            for r in c["runs"]
            for o in r["confirmed_by"]
        ]
        lines.append(
            f"| {cid} | {c['expected']} | {c['detected_runs']}/{len(runs)} | "
            f"{c['confirmed_runs']}/{len(runs)} | {', '.join(c['verdicts'])} | {'; '.join(by) or 'none'} |"
        )
    lines.extend(
        [
            "",
            "## Stability and performance",
            "",
            json.dumps(aggregate.stability_summary),
            "",
            f"Mean duration: {output['mean_duration_seconds']} seconds.",
            f"Mean actual LLM requests: {output['mean_llm_requests']}.",
            "",
            "Exact finding-anchor pairwise stability: " + json.dumps(pairwise),
            "",
            *["- " + note for note in output["notes"]],
            "",
            "Complete case-level Evidence links and successful model routes are in scorecard.json.",
            "",
        ]
    )
    (directory / "scorecard.md").write_text("\n".join(lines), encoding="utf-8")
    # Root-level derived outputs do not modify sealed producer runs.
    for r in runs:
        run = directory / r["run_id"]
        if read_json(run / "seal.json") != artifact_hashes(run):
            raise ValueError("Reporting altered a sealed run")
    return output


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "artifacts/benchmarks/juice-shop-v20.2.0-v1"
    )
    value = build(parser.parse_args().output.resolve())
    print("Sealed runs validated:", len(value["runs"]))
    print("Mean duration:", value["mean_duration_seconds"])
    print("Actual LLM requests:", [r["llm_requests"] for r in value["runs"]])
