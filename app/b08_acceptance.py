"""Deterministic synthetic B08 acceptance and portable offline replay, not a benchmark run."""
from __future__ import annotations

import argparse
import hashlib
import json
import zipfile
from pathlib import Path

import yaml

from agent.graph import build_graph
from app.config import settings
from evaluation.scoring_b08 import evaluate_scoring
from schemas.architecture import ArchitectureContext
from schemas.benchmark_v2 import BenchmarkDatasetV2
from schemas.finding import Finding
from schemas.report import FinalReport
from schemas.scoring import ScoringReview
from schemas.target import TargetProfile
from scoring.review import finding_review_digest, score_state

ROOT = Path(__file__).resolve().parents[1]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def write_json(path, data):
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def run(output: Path):
    output.mkdir(parents=True, exist_ok=False)
    source = output / "target"
    source.mkdir()
    raw = b"// Synthetic scoring fixture; not a vulnerability reproduction.\nexport const fixture = 1;\n"
    (source / "example.ts").write_bytes(raw)
    finding = Finding(id="b08-fixture", source="synthetic", rule_id="fixture.rule",
                      title="Synthetic scoring acceptance", description="Not a Juice Shop measurement",
                      file="example.ts", line_start=2, severity="TEST_CONFIRMED", service="backend")
    metrics = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H",
               "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "N"}
    review = ScoringReview.model_validate({
        "finding_id": finding.id, "finding_digest": finding_review_digest(finding),
        "reviewed_by": "synthetic-acceptance", "rationale": "Synthetic fixture only, not impact proof",
        "references": [{"id": "fixture-source", "file": "example.ts",
                        "sha256": hashlib.sha256(raw).hexdigest(), "line_start": 2, "line_end": 2,
                        "metrics": list(metrics), "impacts": ["direct_database_disclosure"]}],
        "impacts": ["direct_database_disclosure"],
        "cvss": {"finding_id": finding.id, "metrics": {
            key: {"value": value, "reasoning": "Published calculator test vector, not source inference",
                  "evidence_refs": ["fixture-source"]} for key, value in metrics.items()
        }},
    })
    write_json(output / "finding.json", finding.model_dump(mode="json"))
    write_json(output / "review.json", review.model_dump(mode="json"))
    profile = TargetProfile.from_yaml(ROOT / "targets/sberlab.yaml", repository_path_override=source)
    state = {"finding": finding, "target_profile": profile, "scoring_review": review,
             "architecture_context": ArchitectureContext(service="backend"),
             "evidence": [], "max_iterations": 1}
    names = ("agent_mode", "executor_work_dir", "evidence_dir", "executor_audit_log")
    previous = {name: getattr(settings, name) for name in names}
    try:
        settings.agent_mode = "stub"
        settings.executor_work_dir = output / "execution/workspaces"
        settings.evidence_dir = output / "execution/evidence"
        settings.executor_audit_log = output / "execution/audit.jsonl"
        result = build_graph().invoke(state)
        report = result["final_report"]
        write_json(output / "report.json", report.model_dump(mode="json"))
        # Same operator finding, no review; assert scoring does not rewrite the plan/permissions.
        settings.executor_work_dir = output / "control/workspaces"
        settings.evidence_dir = output / "control/evidence"
        settings.executor_audit_log = output / "control/audit.jsonl"
        control_result = build_graph().invoke({**state, "scoring_review": None})
        control = control_result["final_report"]
        write_json(output / "control-report.json", control.model_dump(mode="json"))
        require(report.status == control.status, "Scoring changed the workflow verdict")
        actions = [result["proposed_action"].model_dump(mode="json"),
                   control_result["proposed_action"].model_dump(mode="json")]
        write_json(output / "actions.json", actions)
        require(actions[0] == actions[1], "Scoring changed the action")
        require(report.policy_decisions == control.policy_decisions, "Scoring changed policy decisions")
    finally:
        for name, value in previous.items():
            setattr(settings, name, value)
    # Evaluator-only protocol check; no supplied agent observations, no measured quality claims.
    dataset = BenchmarkDatasetV2.model_validate_json(json.dumps(
        yaml.safe_load((ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml").read_text())
    ))
    write_json(output / "a04-denominator-check.json", {
        "purpose": "Schema/denominator check with NO observations, not a benchmark result",
        "evaluation": evaluate_scoring(dataset, [], {}),
    })
    # Store only explicitly enumerated implementation inputs, never repository environments.
    paths = ["pyproject.toml", "schemas/scoring.py", "schemas/architecture.py", "schemas/state.py",
             "schemas/report.py", "architecture/context.py", "scoring/service.py", "scoring/review.py",
             "agent/nodes.py", "agent/prompts.py", "reporting/builder.py", "reporting/presentation.py",
             "app/pipeline_run.py", "app/b08_acceptance.py", "evaluation/scoring_b08.py",
             "tests/test_b08_scoring.py", "tests/test_b08_review.py",
             "docs/b08-scoring-progress.md", "frontend/src/api/types.ts",
             "docs/b08-validation-2026-10-14.txt", "AGENTS.md",
             "frontend/src/components/chat/FindingBlock.tsx",
             "frontend/src/components/chat/FindingBlock.scoring.test.tsx"]
    implementation = output / "implementation"
    for name in paths:
        destination = implementation / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes((ROOT / name).read_bytes())
    files = {p.relative_to(output).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
             for p in sorted(output.rglob("*")) if p.is_file()}
    write_json(output / "seal.json", files)
    return replay(output)


def replay(root: Path):
    seal = json.loads((root / "seal.json").read_text())
    actual = {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in root.rglob("*") if p.is_file() and p != root / "seal.json"}
    if seal != actual:
        raise ValueError("B08 acceptance seal/membership mismatch")
    finding = Finding.model_validate_json((root / "finding.json").read_text())
    review = ScoringReview.model_validate_json((root / "review.json").read_text())
    report = FinalReport.model_validate_json((root / "report.json").read_text())
    profile = TargetProfile(id="offline", repository_path=root / "target")
    state = {"finding": finding, "target_profile": profile, "scoring_review": review,
             "architecture_context": ArchitectureContext(service="backend")}
    scored = score_state(state)
    require(report.cvss == scored["cvss"] and report.cvss.score == 9.9, "CVSS replay mismatch")
    require(report.technical_severity == scored["technical_severity"], "Ordinal replay mismatch")
    require(report.scoring_review_resolution == scored["scoring_review_resolution"], "Review replay mismatch")
    require(report.context_priority == scored["context_priority"], "Context replay mismatch")
    bad = review.model_copy(deep=True)
    bad.references[0].sha256 = "0" * 64
    rejected = score_state({**state, "scoring_review": bad})
    require(rejected["cvss"].score is None, "Stale source retained CVSS")
    require(rejected["technical_severity"].assessment_status == "unassessed", "Stale source retained ordinal")
    control = FinalReport.model_validate_json((root / "control-report.json").read_text())
    actions = json.loads((root / "actions.json").read_text())
    require(len(actions) == 2 and actions[0] == actions[1], "Action digest/control mismatch")
    require(report.policy_decisions == control.policy_decisions, "Policy replay mismatch")
    require(control.cvss.score is None and control.status == report.status, "Control mismatch")
    require([(a.capability, a.parameter_names, a.command) for a in control.sandbox_actions] == [
        (a.capability, a.parameter_names, a.command) for a in report.sandbox_actions
    ], "Action replay mismatch")
    return {"status": "passed", "scope": "synthetic B08 acceptance, not benchmark metrics",
            "files_verified": len(seal), "cvss_reference_score": report.cvss.score,
            "source_binding": "passed", "stale_source_denied": True,
            "planning_independence": True, "a04_mutated": False, "llm_calls": 0}


def package(root: Path, output: Path):
    result = replay(root)
    files = {p.relative_to(root).as_posix(): p.read_bytes() for p in root.rglob("*") if p.is_file()}
    if any(p.is_symlink() for p in root.rglob("*")):
        raise ValueError("Symlinks are forbidden in handoff")
    if any(part in {".env", ".venv", "node_modules", ".git", "__pycache__"}
           for name in files for part in Path(name).parts):
        raise ValueError("Excluded handoff path")
    with zipfile.ZipFile(output, "x", zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError("Invalid ZIP")
    checksum = hashlib.sha256(output.read_bytes()).hexdigest()
    with output.with_suffix(output.suffix + ".sha256").open("x") as stream:
        stream.write(checksum + "  " + output.name + "\n")
    return {**result, "archive_sha256": checksum}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("run", "replay", "package"))
    parser.add_argument("--input", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.command == "run" and args.output:
        result = run(args.output)
    elif args.command == "replay" and args.input:
        result = replay(args.input)
    elif args.command == "package" and args.input and args.output:
        result = package(args.input, args.output)
    else:
        parser.error("run requires --output; replay requires --input; package requires both")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
