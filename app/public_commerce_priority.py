"""Posthoc CP for the user-declared public-store scenario, with a model draft comparator."""
from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path

import yaml

from app.delivery_metrics import ROOT, verify_files
from app.research_score import score_research
from app.scoring_audit import architecture_preview
from schemas.architecture import ArchitectureContext
from schemas.benchmark_v2 import BenchmarkDatasetV2
from schemas.finding import Finding
from scoring.context_bounds import priority_bounds


def declared_context(finding: Finding):
    # Component classification uses application paths, not benchmark families or expected labels.
    if finding.file.startswith("frontend/"):
        return ArchitectureContext(service="browser", public_exposure=True, criticality="high",
            databases=[], critical_paths=["browser -> commerce backend"], authentication="unknown",
            blast_radius="unknown", unknown_inputs=["authentication", "blast_radius"])
    if finding.file == "server.ts" or finding.file.startswith(("routes/", "models/", "lib/", "data/")):
        return ArchitectureContext(service="juice", public_exposure=True, criticality="high",
            databases=["sqlite", "marsdb"], critical_paths=["juice -> account/order databases"],
            authentication="unknown", blast_radius="shared", unknown_inputs=["authentication"])
    return ArchitectureContext(service=finding.service or "unknown")


def compare_reference(cases, predictions, reference):
    if (reference.get("author_type") != "model"
            or reference.get("status") != "model_reference_draft_requires_human_review"
            or reference.get("scenario_id") != "public-real-commerce.v1"
            or set(reference.get("inputs_excluded", [])) != {"agent_predictions", "scoring_formula"}):
        raise ValueError("Reference is not the declared blinded model draft")
    labels = reference["cases"]
    if len({row["case_id"] for row in labels}) != len(labels) or {row["case_id"] for row in labels} != set(cases):
        raise ValueError("Reference must cover exactly the original frozen cases")
    rows = []
    for label in labels:
        value = label["expected_context_priority"]
        if value not in {None, "LOW", "MEDIUM", "HIGH"} or not label.get("rationale"):
            raise ValueError("Invalid independent reference label or rationale")
        if value is not None and cases[label["case_id"]].expected == "safe":
            raise ValueError("A safe control is not a vulnerable remediation-priority example")
        predicted = predictions.get(label["case_id"], {}).get("level")
        rows.append({"case_id": label["case_id"], "reference": value, "predicted": predicted,
                     "correct": predicted == value if value is not None and predicted is not None else None})
    reviewed = sum(row["reference"] is not None for row in rows)
    assessed = sum(row["correct"] is not None for row in rows)
    correct = sum(row["correct"] is True for row in rows)
    return {"metric": "agreement_with_blinded_model_reference_draft", "human_validated_accuracy": None,
            "reviewed_cases": reviewed, "assessed_cases": assessed, "correct_cases": correct,
            "agreement": correct / assessed if assessed else None,
            "assessed_coverage": assessed / reviewed if reviewed else None, "cases": rows}


def verify_reference_sources(cases, reference, checkout):
    for row in reference["cases"]:
        case = cases[row["case_id"]]
        anchored = False
        for ref in row.get("source_references", []):
            relative = Path(ref["file"])
            if relative.is_absolute() or ".." in relative.parts or "\\" in ref["file"]:
                raise ValueError("Reference source path is not canonical")
            file = (checkout / relative).resolve(strict=True)
            if not file.is_relative_to(checkout.resolve()):
                raise ValueError("Reference source escaped the pinned target")
            if not 1 <= ref["line_start"] <= ref["line_end"] <= len(file.read_text().splitlines()):
                raise ValueError("Reference source range is invalid")
            anchored |= any(anchor.file == ref["file"] and anchor.line_start <= ref["line_end"]
                            and ref["line_start"] <= anchor.line_end for anchor in case.source_anchors)
        if row["expected_context_priority"] is not None and not anchored:
            raise ValueError("Reference priority lacks its frozen case source anchor")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root, checkout, output = args.run.resolve(strict=True), args.checkout.resolve(strict=True), args.output.resolve()
    if output.exists() or any(output.is_relative_to(p) or p.is_relative_to(output) for p in (root, checkout)):
        parser.error("Use fresh output disjoint from measured target and run")
    manifest = json.loads((root / "run-manifest.json").read_bytes())
    from sast.profiles import validate_target_snapshot

    if validate_target_snapshot(checkout, manifest["target"]["commit"]) != manifest["target"]:
        raise ValueError("Architecture source snapshot differs from the measured target")
    facts = architecture_preview(checkout, manifest)
    dataset_path = ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml"
    dataset = BenchmarkDatasetV2.model_validate(yaml.safe_load(dataset_path.read_bytes()))
    reference = json.loads(args.reference.read_bytes())
    output.mkdir(parents=True)
    summary = score_research(root, dataset_path, output / "rescore")
    findings = [Finding.model_validate(row) for row in json.loads((root / "campaign/findings.json").read_bytes())]
    # Freeze all predictions before reference labels are compared. No reference value feeds the scorer.
    assessments = {finding.id: {"finding_id": finding.id, "source_file": finding.file,
        "context": declared_context(finding).model_dump(), **priority_bounds(declared_context(finding))}
        for finding in findings}
    (output / "finding-priorities.json").write_text(json.dumps(assessments, indent=2) + "\n")
    predictions = {}
    for split in ("development", "holdout"):
        scored = json.loads((output / f"rescore/{split}-agent.json").read_bytes())
        for case in scored["cases"]:
            predictions[case["case_id"]] = assessments.get(case["primary_observation_id"], {})
    original = {case.id: case for case in dataset.cases if case.sample_kind == "original"}
    comparison = compare_reference(original, predictions, reference)
    verify_reference_sources(original, reference, checkout)
    scenario = {"id": "public-real-commerce.v1", "declared_by": "user", "public_exposure": True,
        "business_assets": "Real customer accounts and orders", "asset_criticality": "high",
        "backend_topology": "Shared centralized application with direct SQLite/MarsDB access",
        "critical_path": "Backend -> customer/account/order data stores", "topology_source_references": facts["references"],
        "auth_prerequisites": "Unknown per finding; propagated as intervals",
        "scope": "Posthoc declared deployment scenario; not the original lab's measured exposure",
        "independent_human_cp_reference": False}
    result = {"schema_version": "context-priority.public-commerce-evaluation.v1", "scenario": scenario,
              "scoring_metrics": summary["scoring_metrics"], "context_priority_draft_agreement": comparison,
              "new_target_checks": 0, "new_application_model_calls": 0,
              "reference_author_type": "blinded_model", "reference_sha256": sha256(args.reference.read_bytes()).hexdigest(),
              "limitations": ["Reference is a model draft pending independent human review, not frozen A04 truth",
                              "Agent CP is deterministic and service-context based; reference judges case-level remediation priority",
                              "Interval-determined labels do not invent a complete numeric CP score",
                              "CP scenario and ratings were added after the original live run; no original ratings are retroactively claimed"]}
    for name, value in (("summary.json", result), ("scenario.json", scenario), ("reference.json", reference)):
        (output / name).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n")
    (output / "seal.json").write_text(json.dumps({p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
        for p in sorted(output.rglob("*")) if p.is_file()}, indent=2) + "\n")
    verify_files(output, json.loads((output / "seal.json").read_bytes()))
    print(json.dumps({key: comparison[key] for key in comparison if key != "cases"}, indent=2))


if __name__ == "__main__":
    main()
