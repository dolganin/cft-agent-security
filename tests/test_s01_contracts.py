"""Compatibility and trust-boundary checks for the S01 integration contract."""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent.graph import build_graph
from api.service import RunOrchestrator
from reporting.presentation import render_final_report
from schemas.finding import Finding
from schemas.fix import FixVerificationArtifact, PatchReviewArtifact
from schemas.pipeline import GateResult
from schemas.report import FinalReport

EXAMPLES = Path(__file__).resolve().parents[1] / "contracts/examples/s01"


@pytest.mark.parametrize("name,model", [
    ("finding.json", Finding),
    ("report-v1-minimal.json", FinalReport),
    ("patch-review-v1.json", PatchReviewArtifact),
    ("fix-v1-minimal.json", FixVerificationArtifact),
    ("gate-v1-legacy.json", GateResult),
])
def test_documented_examples_roundtrip(name, model):
    value = model.model_validate_json((EXAMPLES / name).read_text())
    assert model.model_validate_json(value.model_dump_json()) == value


def _api_reader(path):
    return SimpleNamespace(
        _require_completed=lambda _: None,
        store=SimpleNamespace(report_path=lambda *_: path),
    )


def test_old_report_remains_readable_by_api_and_renderer():
    path = EXAMPLES / "report-v1-minimal.json"
    result = RunOrchestrator.get_report(_api_reader(path), "example-run-1", "example-finding-1")
    assert result.schema_version == "1.0"
    assert result.agent_decisions == [] and result.evidence == []
    assert result.status == "inconclusive"
    assert "INCONCLUSIVE" in render_final_report(result)


def test_api_reader_rejects_valid_report_for_different_requested_finding():
    path = EXAMPLES / "report-v1-minimal.json"
    with pytest.raises(ValueError, match="requested finding"):
        RunOrchestrator.get_report(_api_reader(path), "example-run-1", "other-finding")


@pytest.mark.parametrize("field", ["finding_id", "finding"])
def test_report_rejects_cross_finding_join(field):
    payload = json.loads((EXAMPLES / "report-v1-minimal.json").read_text())
    if field == "finding_id":
        payload[field] = "other-finding"
    else:
        payload[field]["id"] = "other-finding"
    with pytest.raises(ValidationError, match="must match"):
        FinalReport.model_validate_json(json.dumps(payload))


@pytest.mark.parametrize("status", ["ready_for_review", "rejected"])
def test_review_rejects_cross_finding_proposal(status):
    payload = json.loads((EXAMPLES / "patch-review-v1.json").read_text())
    payload["status"] = status
    payload["proposal"]["finding_id"] = "other-finding"
    with pytest.raises(ValidationError, match="must match"):
        PatchReviewArtifact.model_validate(payload)


@pytest.mark.parametrize("name,model", [
    ("report-v1-minimal.json", FinalReport),
    ("patch-review-v1.json", PatchReviewArtifact),
    ("fix-v1-minimal.json", FixVerificationArtifact),
    ("gate-v1-legacy.json", GateResult),
])
def test_unknown_schema_version_is_not_silently_accepted(name, model):
    payload = json.loads((EXAMPLES / name).read_text())
    payload["schema_version"] = "999.0"
    with pytest.raises(ValidationError):
        model.model_validate(payload)


def test_legacy_gate_errors_are_structured_and_redacted():
    gate = GateResult.model_validate({
        "decision": "fail", "exit_code": 2,
        "stage_errors": ["token=secret-value failed"],
    })
    assert gate.errors[0].layer == "pipeline"
    assert gate.errors[0].code == "INTERNAL_ERROR"
    assert "secret-value" not in gate.model_dump_json()
    assert gate.stage_errors == [gate.errors[0].message]


def test_review_is_never_execution_approval_or_verified_fix():
    payload = json.loads((EXAMPLES / "patch-review-v1.json").read_text())
    for flag in ("applied", "security_verified"):
        with pytest.raises(ValidationError):
            PatchReviewArtifact.model_validate({**payload, flag: True})


def test_old_fix_without_chain_stays_inconclusive():
    payload = json.loads((EXAMPLES / "fix-v1-minimal.json").read_text())
    artifact = FixVerificationArtifact.model_validate(payload)
    assert artifact.status == "INCONCLUSIVE" and not artifact.security_verified
    with pytest.raises(ValidationError, match="complete evidence chain"):
        FixVerificationArtifact.model_validate({**payload, "status": "FIXED", "security_verified": True})


def test_graph_report_preserves_canonical_identity_and_evidence_links():
    finding = Finding.model_validate_json((EXAMPLES / "finding.json").read_text())
    finding.severity = "TEST_CONFIRMED"
    report = build_graph().invoke({
        "finding": finding, "evidence": [], "iteration_count": 0, "max_iterations": 1,
    })["final_report"]
    restored = FinalReport.model_validate_json(report.model_dump_json())
    assert restored.finding_id == restored.finding.id == finding.id
    assert restored.evidence and restored.verification.validator_decision == "approved"
    assert all(item.action_id == item.action.id for item in restored.evidence)
    assert {item.action_id for item in restored.evidence} <= {
        action.action_id for action in restored.sandbox_actions
    }
