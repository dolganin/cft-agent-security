"""R01 bounded-verification specification conformance tests.

The helpers below are a test-only semantic conformance evaluator for the
synthetic R01 contract fixtures. They are not a production Evidence model,
interpreter capability, or registered tool, and they never run live requests.
"""

import json
import re
from pathlib import Path

import pytest
import yaml

from schemas.evidence import Evidence

ROOT = Path(__file__).resolve().parents[1]
R01_DIR = ROOT / "contracts/examples/r01"
SPEC = ROOT / "docs/r01-verification-specifications.md"
FAMILY_SPEC = R01_DIR / "r01-family-specifications.synthetic.json"
SYNTHETIC_VERDICTS = {"confirmed", "rejected", "inconclusive"}
LEGACY_OWN_READ_FIXTURES = {
    "evidence-confirmed.synthetic.json",
    "evidence-rejected.synthetic.json",
    "evidence-inconclusive.synthetic.json",
}


def _load_family_spec() -> dict:
    return json.loads(FAMILY_SPEC.read_text(encoding="utf-8"))


def _family(family_id: str) -> dict:
    return next(f for f in _load_family_spec()["families"] if f["id"] == family_id)


def _evidence(path: Path) -> Evidence:
    return Evidence.model_validate(json.loads(path.read_text(encoding="utf-8")))


def _truthy(facts: dict, key: str) -> bool:
    return facts.get(key) is True


def _evaluate(record: Evidence, family: dict) -> list[str]:
    """Test-only semantic sufficiency evaluator returning deficiency codes."""
    common = _load_family_spec()["common"]
    facts = dict(record.observation.facts)
    deficiencies: list[str] = []

    if record.verdict not in SYNTHETIC_VERDICTS:
        deficiencies.append("unsupported_verdict")
    if facts.get("synthetic") is not True:
        deficiencies.append("not_synthetic")
    if record.source != "runtime" or not record.sandbox_session_id:
        deficiencies.append("runtime_provenance_missing")
    if record.observation.kind != family["observation_kind"] or record.type != record.observation.kind:
        deficiencies.append("binding_mismatch")
    missing = sorted(key for key in common["shared_required_facts"] + family["family_required_facts_for_confirm_or_reject"] if key not in facts)
    terminal = record.verdict in {"confirmed", "rejected"}
    if missing and terminal:
        deficiencies.append("missing_required_facts")

    binding_checks = [
        record.action_id == record.action.id,
        record.scope.target == facts.get("target_id"),
        record.scope.service == facts.get("service_id"),
        _truthy(facts, "binding_match"),
        isinstance(facts.get("source_snapshot_id"), str),
        isinstance(facts.get("endpoint_id"), str),
    ]
    if not all(binding_checks):
        deficiencies.append("binding_mismatch")

    roles = {artifact.role for artifact in record.artifacts}
    if not set(common["required_artifact_roles"]) <= roles:
        deficiencies.append("artifact_roles_incomplete")

    if facts.get("output_truncated") is True:
        deficiencies.append("truncated_output")
    if facts.get(common["insufficient_basis_fact"]) is True:
        deficiencies.append("insufficient_basis")
    if family["observation_kind"] == "r01_redirect_observation_v1":
        if facts.get("redirect_not_followed") is not True or facts.get("sink_contacted") is not False or facts.get("sink_request_count") != 0:
            deficiencies.append("redirect_followed")
        if facts.get("location_header_parse_unambiguous") is not True or facts.get("canonicalization_applied") is not True:
            deficiencies.append("ambiguous_normalization")
    if "object_b_owner_manifest_verified" in facts and (
        not _truthy(facts, "object_b_owner_manifest_verified") or not _truthy(facts, "owner_proved_from_manifest")
    ):
        deficiencies.append("ambiguous_owner")
    if family["observation_kind"] == "r01_auth_bypass_observation_v1":
        principal = facts.get("server_observed_principal_id")
        if not _truthy(facts, "identity_proof_established") or principal in (None, "unknown") or facts.get("session_lost_or_rotated") is True:
            deficiencies.append("identity_unverified")

    if terminal:
        if not _truthy(facts, "identity_proof_established"):
            deficiencies.append("identity_unverified")
        if family["id"] == "R01-AUTH" and facts.get("claim_id") == "authorization_bypass" and facts.get("auth_control_operation_id") == facts.get("operation_id"):
            deficiencies.append("negative_control_not_enforced")
        if family["id"] == "R01-REDIRECT" and facts.get("negative_control_destination_id") == facts.get("probe_destination_id"):
            deficiencies.append("negative_control_not_enforced")
        if facts.get("side_effects_unexplained") is not False:
            deficiencies.append("cleanup_incomplete")
        if facts.get("positive_control") is None:
            deficiencies.append("positive_control_missing")
        elif facts.get("positive_control") != "passed":
            deficiencies.append("positive_control_not_passed")
        if not _truthy(facts, "normal_output_control_passed"):
            deficiencies.append("positive_control_not_passed")
        negative = facts.get(family["negative_control_fact"])
        negative_ok = negative is True or (
            isinstance(negative, str) and negative.startswith(("denied", "literal"))
        )
        if negative is None:
            deficiencies.append("negative_control_missing")
        elif not negative_ok:
            deficiencies.append("negative_control_not_enforced")
        if not isinstance(facts.get("trials_after_reset"), int) or facts["trials_after_reset"] < common["min_required_trials"]:
            deficiencies.append("trial_count_insufficient")
        if facts.get("cleanup_baseline_restored") is not True or facts.get("cleanup_sessions_revoked") is not True:
            deficiencies.append("cleanup_incomplete")
        claim = facts.get("claim_id")
        expected_exchanges = {
            exchange["id"]
            for exchange in family["exchanges"]
            if exchange["count"] > 0
            and exchange.get("applies_to", "both") in {"both", "authz-only" if claim == "authorization_bypass" else "authn-only"}
        }
        executed = facts.get("executed_exchanges")
        if not isinstance(executed, list) or not expected_exchanges <= set(executed):
            deficiencies.append("binding_mismatch")

        permission_mode = family["permission_proof_required_for"]
        needs_permission_proof = permission_mode == "always" or (
            permission_mode == "authorization_claim_only" and facts.get("claim_id") == "authorization_bypass"
        )
        permission_proved = facts.get("role_a_permission") == "denied_by_fixture_policy" and _truthy(
            facts, "permission_denial_proved"
        )
        if needs_permission_proof and not permission_proved:
            deficiencies.append("missing_permission_proof")

        effect = facts.get("unauthorized_effect_observed")
        marker = facts.get("effect_marker_observed_each_trial")
        outcome = facts.get("trial_outcome_denied_or_absent")
        if record.verdict == "confirmed":
            if effect is not True or marker is not True:
                deficiencies.append("unexpected_trial_result")
            if not _truthy(facts, "identity_proof_established"):
                deficiencies.append("identity_unverified")
        elif record.verdict == "rejected":
            if effect is not False or outcome is not True:
                deficiencies.append("unexpected_trial_result")

        family_id = family["id"]
        if family_id in {"R01-OWN-READ", "R01-OWN-WRITE"} and facts.get("role_a_own_control_passed") is not True:
            deficiencies.append("positive_control_not_passed")
        if family_id == "R01-OWN-WRITE":
            if facts.get("independent_readback_as_role_b") is not True:
                deficiencies.append("insufficient_basis")
            if facts.get("negative_control_value_unchanged") is not True:
                deficiencies.append("negative_control_not_enforced")
            if facts.get("baseline_captured_before_trials") is not True:
                deficiencies.append("missing_permission_proof")
        if family_id == "R01-AUTH" and facts.get("privilege_state_changed") is not False:
            deficiencies.append("cleanup_incomplete")
        if (
            family_id == "R01-REDIRECT"
            and record.verdict == "confirmed"
            and facts.get("location_matches_sink_exactly") is not True
        ):
            deficiencies.append("unexpected_trial_result")
        if family_id == "R01-CODE":
            if facts.get("evaluation_observability_control_passed") is not True or facts.get("evaluation_demonstrated_in_safe_context") is not True:
                deficiencies.append("positive_control_not_passed")
            if facts.get("negative_control_literal_output") is not True:
                deficiencies.append("negative_control_not_enforced")
            if facts.get("marker_reflected_only") is True:
                deficiencies.append("not_evaluated")
            if record.verdict == "confirmed":
                if facts.get("observed_scalar") != facts.get("expected_scalar"):
                    deficiencies.append("unexpected_trial_result")
                for side_effect in ("network_connections", "secrets_read", "host_paths_mounted", "filesystem_mutations"):
                    if facts.get(side_effect) != 0:
                        deficiencies.append("cleanup_incomplete")
                if facts.get("container_destroyed") is not True:
                    deficiencies.append("cleanup_incomplete")
    return sorted(set(deficiencies))


def _doc_family_section(document: str, family_id: str) -> str:
    start = document.index(f"\n### {family_id} ") + 1
    nxt = document.find("\n### ", start + 1)
    return document[start:nxt if nxt != -1 else len(document)]


def _doc_exchange_rows(section: str) -> dict[str, tuple[str, bool]]:
    """exchange-id -> (claims, reserved). Reserved = parenthesized retry capacity."""
    rows: dict[str, tuple[str, bool]] = {}
    for line in section.splitlines():
        match = re.match(r"^\| `([a-z0-9-]+)` \| [^|]+ \| [^|]+ \| (both|authz-only|authn-only) \| (\(?\d+\)?) \|$", line)
        if match:
            rows[match.group(1)] = (match.group(2), match.group(3).startswith("("))
            continue
        match = re.match(r"^\| `([a-z0-9-]+)` \| [^|]+ \| [^|]+ \| (\(?\d+\)?) \|$", line)
        if match:
            rows[match.group(1)] = ("both", match.group(2).startswith("("))
    return rows


def test_all_five_verification_families_specify_required_contract_details() -> None:
    document = SPEC.read_text(encoding="utf-8")
    required_sections = {
        "R01-OWN-READ": ["Claim and scope", "Fixture and controls", "Allowed operation and limits", "Verification and verdict", "Cleanup", "Contract examples"],
        "R01-OWN-WRITE": ["Claim and scope", "Fixture and controls", "Allowed operation and limits", "Verification and verdict", "Cleanup", "Contract examples"],
        "R01-AUTH": ["Claim and scope", "Fixture and controls", "Allowed operation and limits", "Verification and verdict", "Cleanup", "Contract examples"],
        "R01-REDIRECT": ["Claim and scope", "Fixture and controls", "Allowed operation and limits", "Verification and verdict", "Cleanup", "Contract examples"],
        "R01-CODE": ["Claim and scope", "Fixture and controls", "Allowed operation and limits", "Verification and verdict", "Cleanup", "Contract examples"],
    }
    for family, headings in required_sections.items():
        section = _doc_family_section(document, family)
        for heading in headings:
            assert f"**{heading}.**" in section, (family, heading)
        assert "inconclusive" in section.lower(), family
        assert "positive control" in section.lower(), family
        assert "negative" in section.lower(), family
        assert "Positive:" in section, family
        assert "Negative:" in section, family
        assert "Uncertain:" in section, family
    assert "production" in document.lower()
    assert "sandbox_session_id" in document
    assert "policy_blocked" in document
    assert "source map" in document.lower()


def test_family_docs_declare_controls_as_distinct_requests_and_explicit_resets() -> None:
    document = SPEC.read_text(encoding="utf-8")
    assert "distinct requests from the candidate probe" in document
    assert "never unreviewed model writes" in document
    auth = _doc_family_section(document, "R01-AUTH")
    assert "auth_control_operation_id" in auth
    assert re.search(r"MUST NOT reuse\s+the\s+candidate\s+operation", auth)
    redirect = _doc_family_section(document, "R01-REDIRECT")
    assert "negative-control" in redirect, "A"
    assert "destination" in redirect, "B"
    assert re.search(r"negative-control\s+destination", redirect), "C"
    assert re.search(r"negative[-_]control\s+destination\s*[-_]?id", redirect.replace("`", ""), re.IGNORECASE), "D"
    assert "MUST NOT be the same request as the probe" in redirect
    code = _doc_family_section(document, "R01-CODE")
    assert "evaluation-observability" in code
    assert re.search(r"Literal reflection alone is never\s+sufficient", code)
    assert re.search(r"HTTP status or reflected\s+text is inconclusive", code)


def test_family_budget_schedules_match_machine_readable_specification() -> None:
    document = SPEC.read_text(encoding="utf-8")
    common = _load_family_spec()["common"]
    for family in _load_family_spec()["families"]:
        section = _doc_family_section(document, family["id"])
        doc_rows = _doc_exchange_rows(section)
        spec_ids = {exchange["id"] for exchange in family["exchanges"]}
        assert doc_rows.keys() == spec_ids, family["id"]
        for exchange in family["exchanges"]:
            claims, reserved = doc_rows[exchange["id"]]
            assert reserved == (exchange["class"] == "reserved_retry"), (family["id"], exchange["id"])
            expected = exchange.get("applies_to", "both")
            assert claims == expected, (family["id"], exchange["id"])
        claim_totals = {}
        for claim in family["claims"]:
            allowed = {"both", "authz-only"} if claim == "authorization_bypass" else {"both", "authn-only"}
            included = [
                (exchange["id"], exchange["count"], exchange.get("applies_to", "both"))
                for exchange in family["exchanges"]
                if exchange.get("applies_to", "both") in allowed
            ]
            claim_totals[claim] = sum(item[1] for item in included)
        max_http = family["budget"]["max_http_exchanges"]
        reserved_capacity = family["budget"]["reserved_capacity"]
        assert max(claim_totals.values()) + reserved_capacity == max_http, (family["id"], claim_totals)
        assert f"Budget max {max_http}" in section, family["id"]
        assert "reset_adapter" in section, family["id"]
        if max_http > common["common_max_http_exchanges"]:
            assert "explicit reviewed family budget" in section, family["id"]
        assert f"exactly {max_http}" in section or f"at most {max_http}" in section, family["id"]


def test_family_budgets_are_declared_and_never_silently_loosen_the_common_default() -> None:
    common = _load_family_spec()["common"]
    assert common["common_max_http_exchanges"] == 8
    assert len(common["mandatory_controls"]) == 2
    for family in _load_family_spec()["families"]:
        budget = family["budget"]
        assert budget["max_http_exchanges"] >= 6, family["id"]
        above = budget["max_http_exchanges"] > common["common_max_http_exchanges"]
        tightened = budget["max_http_exchanges"] < common["common_max_http_exchanges"]
        assert budget["is_family_specific_above_common"] is above, family["id"]
        if above:
            assert "explicit reviewed family budget" in budget["basis"], family["id"]
        if tightened:
            assert "tighter than the common default" in budget["basis"] or "inside the common envelope" in budget["basis"], family["id"]
        for exchange in family["exchanges"]:
            assert exchange["count"] >= 0
        if family["id"] == "R01-AUTH":
            applies = {exchange["id"]: exchange.get("applies_to", "both") for exchange in family["exchanges"]}
            assert applies["nc-a-different"] == "authz-only"
            assert applies["nc-a-anon"] == "authn-only"


def test_every_family_has_synthetic_examples_with_semantic_sufficiency() -> None:
    fixture_files = {path.name for path in R01_DIR.glob("evidence-*.synthetic.json")}
    expected = set(LEGACY_OWN_READ_FIXTURES)
    for family in _load_family_spec()["families"]:
        expected |= {family["examples"][verdict] for verdict in SYNTHETIC_VERDICTS}
    assert fixture_files == expected

    for family in _load_family_spec()["families"]:
        for verdict in SYNTHETIC_VERDICTS:
            record = _evidence(R01_DIR / family["examples"][verdict])
            assert record.verdict == verdict, (family["id"], verdict)
            assert record.observation.kind == family["observation_kind"]
            assert "SYNTHETIC ONLY" in record.summary
            assert record.source == "runtime" and record.sandbox_session_id
            assert record.action_id == record.action.id
            assert record.type == record.observation.kind
            assert record.artifact_refs == [artifact.ref for artifact in record.artifacts]
            assert record.scope.target == record.observation.facts["target_id"]
            assert record.scope.service == record.observation.facts["service_id"]
            deficiencies = _evaluate(record, family)
            if verdict in {"confirmed", "rejected"}:
                assert deficiencies == [], (family["id"], verdict, deficiencies)
            else:
                assert set(family["inconclusive_expected_deficiencies"]) <= set(deficiencies), (
                    family["id"],
                    deficiencies,
                )


@pytest.mark.parametrize("family_id", ["R01-OWN-READ", "R01-OWN-WRITE", "R01-AUTH", "R01-REDIRECT", "R01-CODE"])
def test_binding_mismatch_mutation_invalidates_confirmed_evidence(family_id: str) -> None:
    family = _family(family_id)
    record = _evidence(R01_DIR / family["examples"]["confirmed"])
    assert _evaluate(record, family) == []
    payload = json.loads((R01_DIR / family["examples"]["confirmed"]).read_text(encoding="utf-8"))
    payload["observation"]["facts"]["binding_match"] = False
    mutated = Evidence.model_validate(payload)
    assert mutated.observation.facts["binding_match"] is False
    assert _evaluate(mutated, family) != []
    assert _evaluate(record, family) == []


@pytest.mark.parametrize("family_id", ["R01-OWN-READ", "R01-OWN-WRITE", "R01-AUTH", "R01-REDIRECT", "R01-CODE"])
@pytest.mark.parametrize("mutation", ["missing_negative_control", "drop_negative_control_fact", "no_repeat", "status_or_basis"])
def test_mutations_of_required_facts_break_sufficiency(family_id: str, mutation: str) -> None:
    family = _family(family_id)
    payload = json.loads((R01_DIR / family["examples"]["confirmed"]).read_text(encoding="utf-8"))
    facts = payload["observation"]["facts"]
    if mutation == "status_or_basis":
        if family_id == "R01-CODE":
            assert "reflection_only" in family["mutations_applicable"]
            facts["marker_reflected_only"] = True
            expected = "not_evaluated"
        else:
            assert "status_only" in family["mutations_applicable"]
            facts["distinguishable_only_by_status_or_reflection"] = True
            expected = "insufficient_basis"
    else:
        assert mutation in family["mutations_applicable"]
        if mutation == "missing_negative_control":
            facts[family["negative_control_fact"]] = "not_run"
            expected = "negative_control_not_enforced"
        elif mutation == "drop_negative_control_fact":
            del facts[family["negative_control_fact"]]
            expected = "negative_control_missing"
        else:
            facts["trials_after_reset"] = 1
            expected = "trial_count_insufficient"
    mutated = Evidence.model_validate(payload)
    assert mutated.verdict == "confirmed"
    deficiencies = _evaluate(mutated, family)
    assert expected in deficiencies, (family_id, mutation, deficiencies)


@pytest.mark.parametrize(
    ("family_id", "mutation"),
    [
        ("R01-OWN-READ", "ambiguous_owner"),
        ("R01-OWN-READ", "binding_mismatch"),
        ("R01-OWN-READ", "no_repeat"),
        ("R01-OWN-READ", "missing_negative_control"),
    ],
)
def test_ownership_mutations_flag_ambiguous_owner_and_other_core_gaps(family_id: str, mutation: str) -> None:
    family = _family(family_id)
    payload = json.loads((R01_DIR / family["examples"]["confirmed"]).read_text(encoding="utf-8"))
    facts = payload["observation"]["facts"]
    if mutation == "ambiguous_owner":
        facts["object_b_owner_manifest_verified"] = False
        facts["owner_proved_from_manifest"] = False
        expected = "ambiguous_owner"
    elif mutation == "binding_mismatch":
        facts["target_id"] = "synthetic-target-somewhere-else"
        expected = "binding_mismatch"
    elif mutation == "no_repeat":
        facts["trials_after_reset"] = 1
        expected = "trial_count_insufficient"
    else:
        facts[family["negative_control_fact"]] = "not_run"
        expected = "negative_control_not_enforced"
    deficiencies = _evaluate(Evidence.model_validate(payload), family)
    assert expected in deficiencies, (family_id, mutation, deficiencies)


@pytest.mark.parametrize("verdict", ["confirmed", "rejected"])
@pytest.mark.parametrize("mutation", ["static_source", "wrong_family", "unknown_identity", "same_control"])
def test_terminal_examples_reject_provenance_and_control_mutations(verdict, mutation) -> None:
    family = _family("R01-AUTH")
    payload = json.loads((R01_DIR / family["examples"][verdict]).read_text(encoding="utf-8"))
    facts = payload["observation"]["facts"]
    if mutation == "static_source":
        payload["source"] = "static"
        expected = "runtime_provenance_missing"
    elif mutation == "wrong_family":
        payload["observation"]["kind"] = "unrelated_observation"
        payload["type"] = "unrelated_observation"
        expected = "binding_mismatch"
    elif mutation == "unknown_identity":
        facts["identity_proof_established"] = False
        expected = "identity_unverified"
    else:
        facts["auth_control_operation_id"] = facts["operation_id"]
        expected = "negative_control_not_enforced"
    assert expected in _evaluate(Evidence.model_validate(payload), family)


@pytest.mark.parametrize("verdict", ["confirmed", "rejected"])
def test_redirect_control_must_differ_from_probe(verdict) -> None:
    family = _family("R01-REDIRECT")
    payload = json.loads((R01_DIR / family["examples"][verdict]).read_text(encoding="utf-8"))
    facts = payload["observation"]["facts"]
    facts["negative_control_destination_id"] = facts["probe_destination_id"]
    assert "negative_control_not_enforced" in _evaluate(Evidence.model_validate(payload), family)


def test_missing_family_specific_evidence_fact_breaks_confirmation() -> None:
    family = _family("R01-OWN-WRITE")
    payload = json.loads((R01_DIR / family["examples"]["confirmed"]).read_text(encoding="utf-8"))
    del payload["observation"]["facts"]["independent_readback_as_role_b"]
    deficiencies = _evaluate(Evidence.model_validate(payload), family)
    assert "missing_required_facts" in deficiencies


def test_http_status_or_token_shaped_result_never_supports_a_verdict() -> None:
    for family_id in ("R01-AUTH", "R01-OWN-READ", "R01-OWN-WRITE", "R01-REDIRECT"):
        family = _family(family_id)
        payload = json.loads((R01_DIR / family["examples"]["confirmed"]).read_text(encoding="utf-8"))
        payload["observation"]["facts"]["distinguishable_only_by_status_or_reflection"] = True
        deficiencies = _evaluate(Evidence.model_validate(payload), family)
        assert "insufficient_basis" in deficiencies, family_id
    code = _family("R01-CODE")
    payload = json.loads((R01_DIR / code["examples"]["confirmed"]).read_text(encoding="utf-8"))
    payload["observation"]["facts"]["marker_reflected_only"] = True
    payload["observation"]["facts"]["observed_scalar"] = "marker_literal"
    assert "not_evaluated" in _evaluate(Evidence.model_validate(payload), code)


def test_evidence_without_owner_identity_or_repeat_proof_is_not_sufficient() -> None:
    own_read = _family("R01-OWN-READ")
    payload = json.loads((R01_DIR / own_read["examples"]["confirmed"]).read_text(encoding="utf-8"))
    payload["observation"]["facts"]["object_b_owner_manifest_verified"] = False
    assert "ambiguous_owner" in _evaluate(Evidence.model_validate(payload), own_read)

    auth = _family("R01-AUTH")
    payload = json.loads((R01_DIR / auth["examples"]["confirmed"]).read_text(encoding="utf-8"))
    payload["observation"]["facts"]["identity_proof_established"] = False
    assert "identity_unverified" in _evaluate(Evidence.model_validate(payload), auth)
    payload = json.loads((R01_DIR / auth["examples"]["confirmed"]).read_text(encoding="utf-8"))
    payload["observation"]["facts"]["server_observed_principal_id"] = "unknown"
    assert "identity_unverified" in _evaluate(Evidence.model_validate(payload), auth)
    payload = json.loads((R01_DIR / auth["examples"]["confirmed"]).read_text(encoding="utf-8"))
    payload["observation"]["facts"]["trials_after_reset"] = 1
    assert "trial_count_insufficient" in _evaluate(Evidence.model_validate(payload), auth)


def test_legacy_own_read_examples_stay_compatible_but_are_flagged_incomplete() -> None:
    family = _family("R01-OWN-READ")
    parsed = [_evidence(R01_DIR / name) for name in sorted(LEGACY_OWN_READ_FIXTURES)]
    assert {item.verdict for item in parsed} == SYNTHETIC_VERDICTS
    assert all(item.source == "runtime" and item.sandbox_session_id for item in parsed)
    assert all(item.action_id == item.action.id for item in parsed)
    assert all(item.type == item.observation.kind for item in parsed)
    assert all(item.artifact_refs == [artifact.ref for artifact in item.artifacts] for item in parsed)
    assert all(item.observation.facts["synthetic"] is True for item in parsed)
    for item in parsed:
        if item.verdict not in {"confirmed", "rejected"}:
            continue
        deficiencies = _evaluate(item, family)
        assert "missing_required_facts" in deficiencies, item.id


def test_catalog_and_rubric_templates_are_machine_readable_and_not_truth() -> None:
    catalog = yaml.safe_load((R01_DIR / "catalog-template.yaml").read_text(encoding="utf-8"))
    rubric = yaml.safe_load((R01_DIR / "rubric-template.yaml").read_text(encoding="utf-8"))

    assert catalog["template_only"] is True
    assert catalog["status"] == "draft_unreviewed"
    case = catalog["cases"][0]
    assert {
        "case_id", "family", "service_id", "source_anchors", "http_anchors",
        "root_cause_hypothesis", "expected_verdict", "controls", "prerequisites",
        "scope", "required_facts", "sources", "severity", "context_priority",
        "unknown_reason", "reviewer", "review_status", "eligible_fix",
    } <= set(case)
    assert case["prerequisites"]["production_access"] is False
    assert case["severity"]["cvss"]["status"] == "UNASSESSED"
    assert case["severity"]["cvss"]["score"] is None
    assert case["context_priority"]["status"] == "unknown"

    assert rubric["template_only"] is True
    assert rubric["verdict_rubric"]["policy_denial"]["workflow_status"] == "policy_blocked"
    assert rubric["verdict_rubric"]["policy_denial"]["finding_verdict"] is None
    assert rubric["cvss"]["derive_from_scanner_severity"] is False
    assert rubric["context_priority"]["independent_of_cvss"] is True
