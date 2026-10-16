import hashlib
import json

import pytest

from agent.graph import build_graph
from app.config import settings
from evaluation.scoring_b08 import evaluate_scoring
from reporting.builder import build_final_report
from reporting.presentation import render_final_report
from schemas.architecture import ArchitectureContext
from schemas.benchmark_v2 import BenchmarkDatasetV2
from schemas.finding import Finding
from schemas.report import FinalReport
from schemas.scoring import (
    CVSSAssessmentInput,
    CVSSMetricFact,
    ScoringReview,
    ScoringSourceReference,
)
from schemas.target import TargetProfile
from scoring.review import finding_review_digest, load_reviews, resolve_review


def example(root):
    source = root / "example.ts"
    source.write_text("// Synthetic scoring acceptance fixture, not Juice Shop\nexport const sample = 1;\n")
    finding = Finding(id="fixture", source="test", rule_id="fixture.rule", title="Scoring fixture",
                      description="Not a discovery measurement", file="example.ts", line_start=2,
                      severity="TEST_CONFIRMED", service="backend")
    values = {"AV": "N", "AC": "L", "AT": "N", "PR": "N", "UI": "N", "VC": "H",
              "VI": "H", "VA": "H", "SC": "H", "SI": "H", "SA": "N"}
    review = ScoringReview(
        finding_id=finding.id, finding_digest=finding_review_digest(finding),
        reviewed_by="synthetic-acceptance", rationale="Synthetic binding/calculator test only",
        references=[ScoringSourceReference(
            id="fixture-source", file="example.ts", sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            line_start=2, line_end=2, metrics=list(values), impacts=["direct_database_disclosure"],
        )],
        impacts=["direct_database_disclosure"],
        cvss=CVSSAssessmentInput(finding_id=finding.id, metrics={
            key: CVSSMetricFact(value=value, reasoning="Synthetic test vector, not source inference",
                                evidence_refs=["fixture-source"])
            for key, value in values.items()
        }),
    )
    profile = TargetProfile.from_yaml("targets/sberlab.yaml", repository_path_override=root)
    state = {"finding": finding, "target_profile": profile, "scoring_review": review,
             "architecture_context": ArchitectureContext(service="backend"),
             "evidence": [], "max_iterations": 1}
    return finding, review, state


def test_full_graph_report_and_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "agent_mode", "stub")
    _, _, state = example(tmp_path)
    result = build_graph().invoke(state)
    report = FinalReport.model_validate_json(result["final_report"].model_dump_json())
    assert report.cvss.score == 9.9
    assert report.technical_severity.level == "HIGH"
    assert report.scoring_review_resolution.status == "accepted"
    assert report.context_priority.assessment_status == "partial"
    assert len(report.context_priority.unknown_inputs) == 6
    assert "Unknown inputs" in render_final_report(report)
    assert report.verification.validator_decision == "approved"


@pytest.mark.parametrize("problem", ["hash", "path", "range", "anchor", "metric_ref",
                                      "impact_ref", "id", "duplicate", "symlink", "other_cvss"])
def test_bad_reviews_fail_closed_without_changing_verdict(tmp_path, problem):
    finding, review, _ = example(tmp_path)
    ref = review.references[0]
    if problem == "hash":
        ref.sha256 = "0" * 64
    elif problem == "path":
        ref.file = "../example.ts"
    elif problem == "range":
        ref.line_end = 999
    elif problem == "anchor":
        ref.line_start = ref.line_end = 1
    elif problem == "metric_ref":
        ref.metrics = []
    elif problem == "impact_ref":
        ref.impacts = []
    elif problem == "id":
        review.finding_id = "other"
    elif problem == "duplicate":
        review.references.append(ref)
    elif problem == "other_cvss":
        review.cvss.finding_id = "other"
    else:
        try:
            (tmp_path / "link.ts").symlink_to(tmp_path / "example.ts")
        except OSError as error:
            if getattr(error, "winerror", None) == 1314:
                pytest.skip("Windows symlink creation requires developer mode or privilege")
            raise
        ref.file = "link.ts"
    assessment, refs, severity, resolution = resolve_review(finding, tmp_path, review)
    assert assessment is None
    assert not refs
    assert severity.level == "UNASSESSED"
    assert resolution.status == "invalid"
    assert str(tmp_path) not in resolution.model_dump_json()


def test_review_rechecked_at_report_time(tmp_path):
    _, _, state = example(tmp_path)
    from agent.nodes import score_finding
    state.update(score_finding(state))
    assert state["cvss"].score == 9.9
    (tmp_path / "example.ts").write_text("changed\n")
    state["status"] = "inconclusive"
    report = build_final_report(state)
    assert report.cvss.score is None
    assert report.technical_severity.level == "UNASSESSED"
    assert report.scoring_review_resolution.status == "invalid"
    assert report.status == "inconclusive"


def test_unknown_context_survives_json_and_explicit_override(tmp_path):
    from architecture.service import ArchitectureService
    context = ArchitectureContext(service="unknown")
    roundtrip = ArchitectureContext.model_validate_json(context.model_dump_json())
    assert context.unknown_inputs == roundtrip.unknown_inputs
    (tmp_path / "architecture.yaml").write_text("services:\n  backend:\n    type: api\n")
    (tmp_path / "overrides.yaml").write_text("services:\n  backend:\n    public_exposure: false\n")
    context = ArchitectureService(tmp_path / "architecture.yaml",
                                  overrides_path=tmp_path / "overrides.yaml").get_context("backend")
    assert "public_exposure" not in context.unknown_inputs
    assert "databases" in context.unknown_inputs


def test_duplicate_review_input_rejected(tmp_path):
    _, review, _ = example(tmp_path)
    path = tmp_path / "reviews.json"
    path.write_text(json.dumps([review.model_dump(mode="json")] * 2))
    with pytest.raises(ValueError, match="Duplicate"):
        load_reviews(path)


def test_cvss_cannot_supply_ordinal_accuracy(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "agent_mode", "stub")
    _, _, state = example(tmp_path)
    report = build_graph().invoke(state)["final_report"]
    dataset = BenchmarkDatasetV2.model_validate({
        "id": "synthetic", "status": "synthetic", "target_commit": "0" * 40,
        "cases": [{"id": "TEST-001", "expected": "vulnerable", "family": "sql",
                   "independence_group": "one", "sample_kind": "original", "split": "development",
                   "source_anchors": [{"file": "example.ts", "line_start": 2, "line_end": 2}],
                   "expected_severity": "HIGH"}],
    })
    metrics = evaluate_scoring(dataset, [report], {"TEST-001": "fixture"})
    assert metrics["severity"]["accuracy"] == 1.0
    assert metrics["context_priority"]["accuracy"] is None
    report.technical_severity = None
    metrics = evaluate_scoring(dataset, [report], {"TEST-001": "fixture"})
    assert metrics["severity"]["assessed_coverage"] == 0
    assert metrics["severity"]["accuracy"] is None  # CRITICAL CVSS must never match ordinal HIGH.
    with pytest.raises(ValueError):
        evaluate_scoring(dataset, [report], {"UNKNOWN": "fixture"})


def test_static_report_keeps_scoring_without_claiming_runtime_verification(tmp_path):
    from app.pipeline_run import _build_static_finding_report
    finding, review, _ = example(tmp_path)
    report = _build_static_finding_report(finding, tmp_path, reason="Unsupported fixture",
                                          scoring_review=review)
    assert report.cvss.score == 9.9
    assert report.technical_severity.level == "HIGH"
    assert report.status == "inconclusive"
    assert report.verification.evidence_count == 0
    assert report.verification.validator_decision == "not_run"


def test_invalid_review_is_not_a_pipeline_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "agent_mode", "stub")
    _, review, state = example(tmp_path)
    review.references[0].sha256 = "0" * 64
    report = build_graph().invoke(state)["final_report"]
    assert report.status == "confirmed"  # Synthetic safe_noop Evidence, not review input.
    assert report.cvss.score is None
    assert report.scoring_review_resolution.status == "invalid"


def test_portable_acceptance_and_tamper_detection(tmp_path):
    import zipfile

    from app.b08_acceptance import package, replay, run
    root = tmp_path / "acceptance"
    result = run(root)
    assert result == replay(root) == replay(root)
    archive = tmp_path / "handoff.zip"
    package(root, archive)
    extracted = tmp_path / "extracted"
    with zipfile.ZipFile(archive) as stream:
        stream.extractall(extracted)
    assert replay(extracted) == result
    (extracted / "target/example.ts").write_text("changed\n")
    with pytest.raises(ValueError, match="seal"):
        replay(extracted)


def test_pipeline_accepts_operator_reviews_and_freezes_input(tmp_path, monkeypatch):
    from app.pipeline_run import _parse_args, run_pipeline
    source_root = tmp_path / "backend"
    source_root.mkdir()
    finding, review, _ = example(source_root)
    finding.file = "backend/example.ts"
    review.references[0].file = finding.file
    review.finding_digest = finding_review_digest(finding)
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps([finding.model_dump(mode="json")]))
    review_path = tmp_path / "operator-review.json"
    review_path.write_text(json.dumps([review.model_dump(mode="json")]))
    output = tmp_path / "pipeline"
    monkeypatch.setattr("sys.argv", ["pipeline", "--profile", "targets/sberlab.yaml",
                                    "--target", str(tmp_path), "--agent-mode", "stub",
                                    "--findings", str(findings_path), "--scoring-reviews", str(review_path),
                                    "--output-dir", str(output)])
    for name in ("target_file", "target_repository_path", "agent_mode"):
        monkeypatch.setattr(settings, name, getattr(settings, name))
    assert run_pipeline(_parse_args()) == 1  # Synthetic confirmed; not technical error exit 2.
    report_path = next((output / "reports").glob("*.json"))
    report = FinalReport.model_validate_json(report_path.read_text())
    assert report.cvss.score == 9.9
    assert report.scoring_review_resolution.status == "accepted"
    assert json.loads((output / "scoring-reviews.json").read_text()) == [review.model_dump(mode="json")]
