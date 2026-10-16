"""Ordinal assessment is narrower than confirmation and cannot invent impact."""
from copy import deepcopy

import pytest

from schemas.action import ActionProposal
from schemas.evidence import Evidence, EvidenceAction, EvidenceObservation, EvidenceScope
from schemas.juice_incremental_proof import JuiceProofBinding
from schemas.verification_binding import VerificationBinding
from scoring.runtime_impact import assess_verified_impact


def proof(check="role-registration"):
    binding = JuiceProofBinding(target="juice", finding_id="fixture", rule_id="fixture.rule",
        source_file="models/user.ts", check_id=check, route_sha256="a" * 64,
        source_snapshot_sha256="b" * 64)
    action = ActionProposal(id="a", tool="verify_juice_proof", target="juice", environment="sandbox",
        parameters={"check_id": check}, purpose="test", expected_evidence="test", juice_proof_binding=binding)
    facts = {"proof_binding_valid": True, "audit_bound": True, "cleanup_complete": True,
        "target_source_unchanged": True, "source_snapshot_sha256": "b" * 64,
        "finding_id": "fixture", "protocol": check, "disposition": "confirmed"}
    evidence = Evidence(id="e", action_id="a", type="juice_incremental_runtime_proof", summary="fixture",
        reliability="high", verdict="confirmed", source="runtime", sandbox_session_id="s",
        hypothesis_id="fixture", action=EvidenceAction(id="a", tool=action.tool),
        observation=EvidenceObservation(kind="juice_incremental_runtime_proof", facts=facts),
        scope=EvidenceScope(target="juice", environment="sandbox", description="fixture"))
    return action, evidence


@pytest.mark.parametrize("check,impact", [
    ("role-registration", "administrative_role_acquisition"),
    ("anonymous-product-put", "unauthorized_persistent_update"),
])
def test_fixed_properties_have_exact_narrow_ordinal_impacts(check, impact):
    action, evidence = proof(check)
    result = assess_verified_impact(action, evidence)
    assert result.level == "HIGH" and result.impact_facts == [impact]


@pytest.mark.parametrize("field", ["proof_binding_valid", "audit_bound", "cleanup_complete",
                                 "target_source_unchanged", "source_snapshot_sha256", "finding_id", "protocol"])
def test_missing_or_mismatched_proof_never_retains_high(field):
    action, evidence = proof()
    facts = deepcopy(evidence.observation.facts)
    facts[field] = False
    changed = evidence.model_copy(update={"observation": evidence.observation.model_copy(update={"facts": facts})})
    assert assess_verified_impact(action, changed).assessment_status == "unassessed"


@pytest.mark.parametrize("change", [{"verdict": "inconclusive"}, {"reliability": "low"},
                                    {"source": "static"}, {"action_id": "other"}])
def test_confirmation_reliability_and_identity_required(change):
    action, evidence = proof()
    assert assess_verified_impact(action, evidence.model_copy(update=change)).level == "UNASSESSED"


def test_severity_never_changes_original_evidence_or_action():
    action, evidence = proof()
    before = (action.model_dump_json(), evidence.model_dump_json())
    assess_verified_impact(action, evidence)
    assert before == (action.model_dump_json(), evidence.model_dump_json())


def sql_proof(mode):
    binding = VerificationBinding(route_id="sql", handler_id="sql", target="juice", finding_id="fixture",
        family="sql-injection", source_file="handler.ts", line_start=1, line_end=1,
        anchor_sha256="a" * 64, source_snapshot="b" * 64, source_files={"handler.ts": "c" * 64},
        map_sha256="d" * 64, service="juice", endpoint="/login", method="POST",
        tool="verify_sql_injection", check="sql_interpolation", mode=mode)
    action = ActionProposal(id="a", tool="verify_sql_injection", target="juice", environment="sandbox",
        parameters={"mode": mode}, purpose="test", expected_evidence="test", verification_binding=binding)
    observations = [{"status": 401, "authenticated": False}, {"status": 200, "authenticated": True}] * 2
    facts = {"verification_binding": binding.model_dump(mode="json"), "facts": {
        "mode": mode, "control_repeated": True, "probe_repeated": True, "observations": observations}}
    _, evidence = proof()
    evidence = evidence.model_copy(update={"type": "sql_differential_check",
        "action": EvidenceAction(id="a", tool=action.tool),
        "observation": EvidenceObservation(kind="sql_differential_check", facts=facts)})
    return action, evidence


def test_authentication_differential_proves_bypass_but_search_does_not_prove_disclosure():
    action, evidence = sql_proof("authentication")
    assert assess_verified_impact(action, evidence).impact_facts == ["authentication_bypass"]
    action, evidence = sql_proof("search")
    assert assess_verified_impact(action, evidence).level == "UNASSESSED"


def test_a_success_status_without_authenticated_controls_is_not_an_authentication_bypass():
    action, evidence = sql_proof("authentication")
    facts = deepcopy(evidence.observation.facts)
    facts["facts"]["observations"][1]["authenticated"] = False
    evidence = evidence.model_copy(update={"observation": evidence.observation.model_copy(update={"facts": facts})})
    assert assess_verified_impact(action, evidence).level == "UNASSESSED"
