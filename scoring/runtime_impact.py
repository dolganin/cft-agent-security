"""Narrow ordinal impact assessment from independently replayed fixed protocols.

This is not an operator ScoringReview, CVSS, or a new vulnerability verdict.
The caller must reconstruct Evidence from persisted execution/audit first.
No benchmark cases, expected labels or scanner severity enter this module.
"""
from schemas.action import ActionProposal
from schemas.evidence import Evidence
from schemas.scoring import TechnicalSeverity


def assess_verified_impact(action: ActionProposal, evidence: Evidence) -> TechnicalSeverity:
    unknown = TechnicalSeverity(reasoning="The verified property does not establish a supported ordinal impact.")
    if (evidence.source != "runtime" or evidence.verdict != "confirmed"
            or evidence.reliability != "high" or evidence.action_id != action.id
            or evidence.action.tool != action.tool or evidence.scope.target != action.target
            or action.environment != "sandbox" or evidence.scope.environment != action.environment):
        return unknown
    facts = evidence.observation.facts
    impact = None
    if action.tool == "verify_juice_proof":
        binding = action.juice_proof_binding
        if (binding is None or binding.target != action.target or evidence.type != "juice_incremental_runtime_proof"
                or facts.get("proof_binding_valid") is not True
                or facts.get("audit_bound") is not True
                or facts.get("cleanup_complete") is not True
                or facts.get("target_source_unchanged") is not True
                or facts.get("source_snapshot_sha256") != binding.source_snapshot_sha256
                or facts.get("finding_id") != binding.finding_id
                or facts.get("protocol") != binding.check_id
                or facts.get("disposition") != "confirmed"
                or action.parameters.get("check_id") != binding.check_id):
            return unknown
        impact = {"role-registration": "administrative_role_acquisition",
                  "anonymous-product-put": "unauthorized_persistent_update"}.get(binding.check_id)
    elif action.tool == "verify_sql_injection":
        binding = action.verification_binding
        details = facts.get("facts", {})
        if (binding is None or binding.target != action.target or evidence.type != "sql_differential_check"
                or action.parameters.get("mode") != "authentication"
                or binding.mode != "authentication"
                or facts.get("verification_binding") != binding.model_dump(mode="json")
                or details.get("mode") != "authentication"
                or details.get("control_repeated") is not True
                or details.get("probe_repeated") is not True):
            return unknown
        observations = details.get("observations", [])
        if len(observations) != 4 or not all(
                observations[i].get("status") in {400, 401, 403}
                and observations[i].get("authenticated") is False for i in (0, 2)) or not all(
                observations[i].get("status") == 200
                and observations[i].get("authenticated") is True for i in (1, 3)):
            return unknown
        impact = "authentication_bypass"
    if impact:
        return TechnicalSeverity(level="HIGH", assessment_status="assessed", impact_facts=[impact],
            reasoning="Deterministic source-impact.a04.v1 assessment of an independently replayed "
                      "fixed runtime property: " + impact + ". Not CVSS or a human operator review.")
    return unknown
