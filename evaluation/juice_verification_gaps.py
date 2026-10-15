"""Evaluator-only diagnosis of missing proofs, never a runtime permission source."""
from __future__ import annotations

import argparse
import json
import tempfile
from collections import Counter
from hashlib import sha256
from pathlib import Path

import yaml

from app.research_handoff import verify_seal
from app.research_score import score_research
from reporting.checkpoints import write_json
from schemas.benchmark_v2 import BenchmarkCaseResultV2, BenchmarkDatasetV2

ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml"


def classify(case, findings, handoffs, reviews, profiles):
    """Only archived operational facts determine readiness; no inferred verdict."""
    if case.confirmation_supported:
        return "runtime_confirmed"
    if not case.detected:
        return "not_detected"
    matched = [findings[identifier] for identifier in case.matched_observation_ids]
    if case.family == "weak-cryptography":
        return "source_property_review_required"
    executed = [reviews[identifier] for identifier in case.matched_observation_ids
                if identifier in reviews]
    if any(row.get("executed") is None for row in executed):
        return "execution_or_cleanup_failure"
    if any(row.get("executed") is True for row in executed):
        return "executed_without_sufficient_proof"
    ready = [handoffs.get(item["id"], {}) for item in matched]
    if any(row.get("binding") for row in ready):
        return "bound_protocol_not_executed"
    routes = [route for profile in profiles for route in profile.get("verification_routes", [])]
    relevant = [route for route in routes if route.get("family") == case.family
                and any(source["file"] == finding["file"]
                        for source in route.get("sources", []) for finding in matched)]
    return "source_binding_unavailable" if relevant else "no_registered_runtime_protocol"


def audit(run: Path, output: Path, *, dataset_path=DATASET):
    run, output = run.resolve(strict=True), output.resolve()
    if output.exists() or output.is_relative_to(run):
        raise ValueError("Use a fresh output outside the sealed run")
    sealed = verify_seal(run)
    # Recompute, rather than trust a submitted scorecard or its confirmed totals.
    with tempfile.TemporaryDirectory(prefix="cft-gap-score-") as temporary:
        score_dir = Path(temporary) / "score"
        summary = score_research(run, dataset_path, score_dir)
        scores = [json.loads((score_dir / f"{split}-agent.json").read_text())
                  for split in ("development", "holdout")]
    dataset = BenchmarkDatasetV2.model_validate(yaml.safe_load(dataset_path.read_text()))
    definitions = {case.id: case for case in dataset.cases}
    findings = {row["id"]: row for row in json.loads((run / "campaign/findings.json").read_text())}
    handoff = json.loads((run / "campaign/canonical-verification-handoff.json").read_text())
    handoffs = {row["finding_id"]: row for row in handoff["checks"]}
    reviews = {}
    for row in json.loads((run / "campaign/canonical-runtime-reviews.json").read_text()):
        for identifier in row.get("job_finding_ids") or [row["finding_id"]]:
            if identifier in reviews:
                raise ValueError("Duplicate operational review identity")
            reviews[identifier] = row
    manifest = json.loads((run / "campaign/manifest.json").read_text())
    profiles = manifest["canonical_verification_profiles"]
    rows = []
    for score in scores:
        for raw in score["cases"]:
            case = BenchmarkCaseResultV2.model_validate(raw)
            definition = definitions[case.case_id]
            if case.expected != "vulnerable":
                continue
            blocker = classify(case, findings, handoffs, reviews, profiles)
            rows.append({"case_id": case.case_id, "family": case.family,
                "split": definition.split, "detected": case.detected,
                "runtime_confirmation_supported": case.confirmation_supported,
                "blocker": blocker, "semantic_review_required": not case.confirmation_supported,
                "source_anchors": [a.model_dump(mode="json") for a in definition.source_anchors],
                "http_anchors": [a.model_dump(mode="json") for a in definition.http_anchors],
                "candidate_observations": [{"finding_id": identifier,
                    "rule_id": findings[identifier]["rule_id"],
                    "title": findings[identifier]["title"], "file": findings[identifier]["file"],
                    "line_start": findings[identifier]["line_start"],
                    "line_end": findings[identifier]["line_end"],
                    "handoff_reason": handoffs.get(identifier, {}).get("reason"),
                    "route_id": (handoffs.get(identifier, {}).get("binding") or {}).get("route_id"),
                    "runtime_review_reason": reviews.get(identifier, {}).get("reason")}
                    for identifier in case.matched_observation_ids]})
    rows.sort(key=lambda row: row["case_id"])
    result = {"schema": "cft.juice.verification-gaps.v1", "scope": "evaluator_only",
        "is_evidence": False, "changes_verdicts": False,
        "input_sealed_files": sealed, "input_seal_sha256": sha256((run / "seal.json").read_bytes()).hexdigest(),
        "positive_cases": len(rows),
        "runtime_confirmed": sum(row["runtime_confirmation_supported"] for row in rows),
        "unconfirmed": sum(not row["runtime_confirmation_supported"] for row in rows),
        "blockers": dict(sorted(Counter(row["blocker"] for row in rows).items())),
        "runtime_metrics_replayed": summary["measurement"], "cases": rows,
        "limitations": ["Source-anchor/family matching does not prove semantic equivalence.",
            "Missing runtime protocol is not a rejected or safe verdict.",
            "Source-property proofs cannot be counted as runtime confirmations.",
            "This evaluator output must not be loaded as model context or operator permissions."]}
    output.mkdir(parents=True)
    write_json(output / "gaps.json", result)
    lines = ["# Неподтвержденные случаи: операционная диагностика", "",
        (f"Положительных: {len(rows)}. Runtime confirmed: {result['runtime_confirmed']}. "
         f"Осталось: {result['unconfirmed']}."), "",
        "Сопоставление кандидата не доказывает, что он описывает правильную причину.", "",
        "| Случай | Семейство | Блокер | Наблюдения |", "|---|---|---|---|"]
    for row in rows:
        if row["runtime_confirmation_supported"]:
            continue
        anchors = "; ".join(f"{item['file']}:{item['line_start']}"
                            for item in row["candidate_observations"])
        lines.append(f"| {row['case_id']} | {row['family']} | {row['blocker']} | {anchors} |")
    (output / "gaps.md").write_text("\n".join(lines) + "\n")
    write_json(output / "seal.json", {path.name: sha256(path.read_bytes()).hexdigest()
        for path in sorted(output.iterdir()) if path.is_file()})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = audit(args.run, args.output)
    print(json.dumps({key: value for key, value in result.items() if key != "cases"}, indent=2))


if __name__ == "__main__":
    main()
