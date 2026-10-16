"""Offline ordinal scoring and a blind CP annotation packet; original A04 stays frozen."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from hashlib import sha256
from pathlib import Path

import yaml

from app.delivery_metrics import ROOT, verify_files
from app.research_score import score_research
from schemas.architecture import ArchitectureContext
from schemas.benchmark_v2 import BenchmarkDatasetV2
from scoring.service import ScoringService


def annotation_packet(dataset: BenchmarkDatasetV2, dataset_sha256: str, checkout: Path):
    """Only frozen source anchors enter the reference packet, never agent scores."""
    cases = []
    for case in dataset.cases:
        if case.sample_kind != "original":
            continue
        anchors = []
        for anchor in case.source_anchors:
            path = (checkout / anchor.file).resolve(strict=True)
            if not path.is_relative_to(checkout.resolve()):
                raise ValueError("Annotation source escapes pinned checkout")
            anchors.append({**anchor.model_dump(), "file_sha256": sha256(path.read_bytes()).hexdigest()})
        cases.append({"case_id": case.id, "independence_group": case.independence_group,
                      "split": case.split, "source_anchors": anchors,
                      "http_anchors": [anchor.model_dump() for anchor in case.http_anchors],
                      "expected_context_priority": None, "rationale": None,
                      "fact_references": [], "reviewed_by": None})
    return {"schema_version": "context-priority.reference-draft.v1", "status": "draft_unreviewed",
            "dataset_id": dataset.id, "dataset_sha256": dataset_sha256,
            "target_commit": dataset.target_commit, "independent_review_completed": False,
            "scenario": "Isolated local Docker test lab from the measured run; no production business context supplied",
            "instructions": [
                "Review source and declared architecture/business facts without opening agent CP outputs.",
                "Choose LOW, MEDIUM or HIGH independently; leave unknown values null with an explanation.",
                "Do not run the agent scoring function to generate reference labels.",
                "Record the reviewer, reasoning and facts; do not edit frozen A04 inputs.",
                "This draft is not an independent benchmark and cannot establish CP accuracy."],
            "cases": cases}


def architecture_preview(checkout, manifest):
    """Known backend DB facts; unknown business impact stays explicit, never zero impact."""
    references = []
    for name, literal in (("models/index.ts", "dialect: 'sqlite'"),
                          ("data/mongodb.ts", "new MarsDB.Collection('orders')")):
        raw = (checkout / name).read_bytes()
        matches = [i for i, line in enumerate(raw.decode().splitlines(), 1) if literal in line]
        if len(matches) != 1:
            raise ValueError("Pinned backend architecture fact is ambiguous")
        references.append({"file": name, "sha256": sha256(raw).hexdigest(), "line": matches[0]})
    context = ArchitectureContext(service="juice", databases=["sqlite", "marsdb"],
                                  unknown_inputs=["public_exposure", "criticality", "critical_paths",
                                                  "authentication", "blast_radius"])
    return {"schema_version": "context-priority.architecture-preview.v1", "status": "partial_unreviewed",
            "target_snapshot": manifest["target"], "context": context.model_dump(),
            "references": references, "priority_preview": ScoringService().score_context_priority(context).model_dump(),
            "scope": "Backend service context only, not automatically assigned to frontend findings or all cases",
            "accuracy_claimed": False,
            "notes": ["Docker lab isolation is not evidence of the application's production exposure.",
                      "Business criticality, critical service paths, per-route authentication and blast radius remain unknown.",
                      "The partial LOW score is a lower-bound calculation from known facts, not a final low-risk verdict."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root, checkout, output = args.run.resolve(strict=True), args.checkout.resolve(strict=True), args.output.resolve()
    if output.exists() or any(output.is_relative_to(p) or p.is_relative_to(output) for p in (root, checkout)):
        parser.error("Output must be fresh and disjoint from measured run and target")
    from sast.profiles import validate_target_snapshot

    manifest = json.loads((root / "run-manifest.json").read_bytes())
    if validate_target_snapshot(checkout, manifest["target"]["commit"]) != manifest["target"]:
        raise ValueError("CP annotation checkout differs from measured immutable snapshot")
    dataset_path = ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml"
    dataset = BenchmarkDatasetV2.model_validate(yaml.safe_load(dataset_path.read_bytes()))
    # Freeze the reference draft before computing any new scoring outputs. It contains no predictions.
    packet = annotation_packet(dataset, sha256(dataset_path.read_bytes()).hexdigest(), checkout)
    output.mkdir(parents=True)
    (output / "context-priority-reference-draft.json").write_text(json.dumps(packet, indent=2, ensure_ascii=False) + "\n")
    preview = architecture_preview(checkout, manifest)
    (output / "architecture-facts-and-cp-preview.json").write_text(json.dumps(preview, indent=2, ensure_ascii=False) + "\n")
    summary = score_research(root, dataset_path, output / "rescore")
    original = json.loads((root / "campaign/reports.json").read_bytes())
    states = Counter((row["report"].get("context_priority") or {}).get("assessment_status", "absent")
                     for row in original)
    data = {"schema_version": "scoring.audit.v1", "posthoc": True, "new_model_calls": 0,
            "new_target_checks": 0, "severity_scheme": "source-impact.a04.v1",
            "scoring_metrics": summary["scoring_metrics"], "cp_saved_report_statuses": dict(states),
            "cp_reference_status": "draft_unreviewed", "original_run_changed": False,
            "frozen_dataset_changed": False, "scope": "35 original cases, 4 existing ordinal labels, no independent CP labels",
            "caveats": ["Posthoc deterministic impact assessment, not original LLM scoring or CVSS accuracy",
                         "All reviewed severity labels are HIGH; a tiny one-class slice does not measure broad classification quality",
                         "SQL search differential alone is insufficient to infer a supported high-impact category",
                         "Independent human review of CP reference and declared business context remains required"]}
    (output / "summary.json").write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n")
    (output / "seal.json").write_text(json.dumps({p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
        for p in sorted(output.rglob("*")) if p.is_file()}, indent=2) + "\n")
    verify_files(output, json.loads((output / "seal.json").read_bytes()))
    print(json.dumps(data, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
