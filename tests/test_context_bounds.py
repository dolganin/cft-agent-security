from types import SimpleNamespace

import pytest

from app.public_commerce_priority import compare_reference, declared_context
from schemas.architecture import ArchitectureContext
from schemas.finding import Finding
from scoring.context_bounds import priority_bounds


def test_unknown_auth_can_leave_priority_level_determined_without_inventing_numeric_score():
    context = ArchitectureContext(service="juice", public_exposure=True, criticality="high",
        databases=["db"], critical_paths=["juice -> db"], authentication="unknown", blast_radius="shared",
        unknown_inputs=["authentication"])
    result = priority_bounds(context)
    assert (result["minimum_score"], result["maximum_score"], result["level"]) == (9, 10, "HIGH")
    assert result["original_priority"]["assessment_status"] == "partial"
    assert result["unknown_inputs_preserved"] == ["authentication"]
    assert result["complete_numeric_assessment"] is False
    assert context.authentication == "unknown"


def test_unknown_context_does_not_become_low_risk_or_complete():
    result = priority_bounds(ArchitectureContext(service="unknown"))
    assert result["minimum_score"] == 0 and result["maximum_score"] == 10
    assert result["level"] is None
    assert set(result["possible_levels"]) == {"LOW", "MEDIUM", "HIGH"}


def test_browser_context_does_not_inherit_database_or_backend_blast_radius():
    finding = Finding(id="x", source="test", rule_id="test", title="test", description="test",
                      file="frontend/src/component.ts", service="juice")
    context = declared_context(finding)
    assert context.databases == [] and context.blast_radius == "unknown"
    assert priority_bounds(context)["level"] is None


def test_model_draft_agreement_keeps_unknowns_in_coverage_and_is_not_human_accuracy():
    cases = {key: SimpleNamespace(expected="vulnerable") for key in ["A", "B", "C"]}
    predictions = {"A": {"level": "HIGH"}, "B": {"level": "HIGH"}, "C": {"level": None}}
    reference = {"author_type": "model", "status": "model_reference_draft_requires_human_review",
        "scenario_id": "public-real-commerce.v1", "inputs_excluded": ["agent_predictions", "scoring_formula"],
        "cases": [{"case_id": key, "expected_context_priority": level, "rationale": "blind review"}
                  for key, level in [("A", "HIGH"), ("B", "MEDIUM"), ("C", "HIGH")]]}
    result = compare_reference(cases, predictions, reference)
    assert result["agreement"] == .5 and result["assessed_coverage"] == 2 / 3
    assert result["human_validated_accuracy"] is None
    reference["author_type"] = "human"
    with pytest.raises(ValueError, match="model draft"):
        compare_reference(cases, predictions, reference)
