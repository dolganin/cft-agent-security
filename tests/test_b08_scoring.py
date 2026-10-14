import pytest
from pydantic import ValidationError

from architecture.context import ProjectDescriptionAdapter
from schemas.architecture import ArchitectureContext, ProjectDescription
from schemas.finding import Finding
from schemas.scoring import CVSSAssessmentInput, CVSSMetricFact
from scoring.service import ScoringService


def finding():
    return Finding(
        id="reviewed",
        source="test",
        rule_id="test.rule",
        title="Example",
        description="Fixture, not target evidence",
        file="example.ts",
        severity="ERROR",
    )


def assessment():
    values = {
        "AV": "N",
        "AC": "L",
        "AT": "N",
        "PR": "N",
        "UI": "N",
        "VC": "H",
        "VI": "H",
        "VA": "H",
        "SC": "H",
        "SI": "H",
        "SA": "N",
    }
    return CVSSAssessmentInput(
        finding_id="reviewed",
        metrics={
            key: CVSSMetricFact(
                value=value,
                reasoning="Synthetic calculator fixture",
                evidence_refs=["fixture:reviewed"],
            )
            for key, value in values.items()
        },
    )


def test_reference_vector_is_deterministic_and_keeps_justifications():
    scorer = ScoringService()
    inputs = assessment()
    first = scorer.score_cvss(
        finding(), inputs, trusted_evidence_refs=frozenset({"fixture:reviewed"})
    )
    assert first == scorer.score_cvss(
        finding(), inputs, trusted_evidence_refs=frozenset({"fixture:reviewed"})
    )
    assert first.score == 9.9
    assert first.severity == "CRITICAL"
    assert first.assessment_status == "assessed"
    assert first.metric_facts == inputs.metrics
    assert first.scheme == "CVSS:4.0/B"


@pytest.mark.parametrize("problem", ["wrong_finding", "missing", "extra", "invalid", "untrusted"])
def test_bad_inputs_never_produce_numeric_scores(problem):
    inputs = assessment()
    refs = frozenset({"fixture:reviewed"})
    if problem == "wrong_finding":
        inputs.finding_id = "other"
    elif problem == "missing":
        del inputs.metrics["VC"]
    elif problem == "extra":
        inputs.metrics["E"] = inputs.metrics["AV"]
    elif problem == "invalid":
        inputs.metrics["AV"] = CVSSMetricFact(
            value="Z", reasoning="Invalid", evidence_refs=["fixture:reviewed"]
        )
    else:
        refs = frozenset()
    result = ScoringService().score_cvss(finding(), inputs, trusted_evidence_refs=refs)
    assert result.score is None
    assert result.assessment_status == "unassessed"
    assert result.severity == "UNASSESSED"


@pytest.mark.parametrize(
    "field,value",
    [
        ("reasoning", "  "),
        ("evidence_refs", []),
        ("evidence_refs", [" "]),
        ("value", "N/E:A"),
    ],
)
def test_justification_is_required_and_vector_injection_is_rejected(field, value):
    data = {"value": "N", "reasoning": "Source-reviewed fact", "evidence_refs": ["source:1"]}
    data[field] = value
    with pytest.raises(ValidationError):
        CVSSMetricFact.model_validate(data)


def test_all_no_impact_metrics_are_zero_not_unassessed():
    inputs = assessment()
    for key in ("VC", "VI", "VA", "SC", "SI", "SA"):
        inputs.metrics[key] = inputs.metrics[key].model_copy(update={"value": "N"})
    result = ScoringService().score_cvss(
        finding(), inputs, trusted_evidence_refs=frozenset({"fixture:reviewed"})
    )
    assert result.score == 0.0
    assert result.severity == "NONE"
    assert result.assessment_status == "assessed"


def test_absent_context_is_partial_not_a_claim_of_low_business_risk():
    result = ScoringService().score_context_priority(ArchitectureContext(service="unknown"))
    assert result.score == 0.0  # Preserve the v0.1 contribution calculation.
    assert result.assessment_status == "partial"
    assert len(result.unknown_inputs) == 6


def test_explicit_negative_facts_are_known_and_cvss_does_not_change_priority():
    context = ArchitectureContext(
        service="lab",
        public_exposure=False,
        criticality="test",
        databases=[],
        critical_paths=[],
        authentication="admin",
        blast_radius="isolated",
    )
    scorer = ScoringService()
    plain = scorer.score(finding(), context)
    assessed = scorer.score(
        finding(),
        context,
        assessment=assessment(),
        trusted_evidence_refs=frozenset({"fixture:reviewed"}),
    )
    assert plain[1] == assessed[1]
    assert assessed[1].assessment_status == "assessed"
    assert assessed[1].unknown_inputs == []


def test_unknown_category_is_not_silently_assessed():
    result = ScoringService().score_context_priority(
        ArchitectureContext(service="lab", authentication="magic")
    )
    assert "authentication" in result.unknown_inputs


def test_adapter_does_not_turn_missing_description_into_negative_facts():
    description = ProjectDescription.model_validate({"services": {"lab": {"type": "api"}}})
    context = ProjectDescriptionAdapter(description).get_context("lab")
    result = ScoringService().score_context_priority(context)
    assert "public_exposure" in result.unknown_inputs
    assert "databases" in result.unknown_inputs
    assert "critical_paths" in result.unknown_inputs
