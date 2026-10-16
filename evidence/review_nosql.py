"""Offline verdict for the fixed two-synthetic-row NoSQL review selector check."""
from schemas.access_verification import AccessCheckEvidence
from schemas.review_verification import NOSQL_ORDER
from security.access_verification import binding_id, registered_check


def evaluate_review_nosql(trace, action):
    registration = registered_check({"check_id": trace.check_id})
    binding = bool(action and action.verification_binding
        and action.tool == "verify_access_control"
        and action.service == "juice" and action.endpoint == registration.endpoint
        and action.parameters == {"check_id": "juice-review-nosql-selector-v1"}
        and action.verification_binding.tool == action.tool
        and action.verification_binding.check == registration.check
        and action.verification_binding.route_id == registration.route_id
        and action.verification_binding.family == "nosql-injection"
        and action.verification_binding.method == "PATCH"
        and action.verification_binding.endpoint == registration.endpoint
        and action.verification_binding.finding_id
        and trace.binding_id == binding_id(action)
        and trace.source_snapshot_digest == action.verification_binding.source_snapshot
        and trace.review_source_snapshot_digest is not None
        and trace.target == action.target and action.environment == trace.environment == "sandbox")
    controls = {"binding": binding, "cleanup": trace.cleanup_complete,
        "integrity": trace.integrity_verified, "reset": trace.reset_complete,
        "technical_success": trace.technical_error is None,
        "schedule": (trace.operation == "review_nosql_selector" and trace.method == "PATCH"
            and trace.object_ref == "review-b" and trace.endpoint_id == "review-write"
            and trace.request_budget == 26 and trace.exchange_count == 26
            and not trace.exchanges and not trace.generations and not trace.review_trials
            and len(trace.review_nosql_trials) == 2)}
    required = {"identities_verified", "same_owner_fixture", "scalar_control",
                "anonymous_control", "unrelated_records_unchanged",
                "operator_scope_is_two_fixture_ids", "owners_and_nonmessage_preserved"}
    trial_verdicts = []
    for index, trial in enumerate(trace.review_nosql_trials):
        valid = (trial.source_snapshot_digest == trace.review_source_snapshot_digest
            and trial.fixture_snapshot_digest == trace.review_source_snapshot_digest
            and trial.binding_snapshot_digest == trace.source_snapshot_digest
            and trial.request_order == NOSQL_ORDER and trial.http_exchanges == 13
            and trial.identity_a_sha256 != trial.identity_b_sha256
            and trial.session_a_sha256 != trial.session_b_sha256
            and trial.owner_identity_sha256 == trial.identity_b_sha256
            and trial.review_a_sha256 != trial.review_b_sha256
            and len({trial.initial_a_sha256, trial.initial_b_sha256,
                     trial.scalar_marker_sha256, trial.anonymous_marker_sha256,
                     trial.operator_marker_sha256}) == 5
            and set(trial.controls) == required and all(trial.controls.values())
            and trial.unrelated_baseline_sha256 == trial.unrelated_after_scalar_sha256
            and trial.unrelated_baseline_sha256 == trial.unrelated_after_anonymous_sha256
            and trial.unrelated_baseline_sha256 == trial.unrelated_after_operator_sha256
            and trial.scalar_status in {200, 204}
            and trial.scalar_a_readback_sha256 == trial.scalar_marker_sha256
            and trial.scalar_b_readback_sha256 == trial.initial_b_sha256
            and trial.anonymous_status in {401, 403}
            and trial.anonymous_b_readback_sha256 == trial.initial_b_sha256
            and 0 <= trial.operator_modified_count <= 2)
        controls[f"trial_{index + 1}"] = valid
        operator_changed_both = (trial.operator_status in {200, 204}
            and trial.operator_modified_count == 2
            and trial.operator_a_readback_sha256 == trial.operator_marker_sha256
            and trial.operator_b_readback_sha256 == trial.operator_marker_sha256)
        operator_no_effect = (
            trial.operator_modified_count == 0 and
            (400 <= trial.operator_status < 500
             or (trial.operator_status in {200, 204} and trial.operator_modified_count == 0))
            and trial.operator_a_readback_sha256 == trial.scalar_marker_sha256
            and trial.operator_b_readback_sha256 == trial.initial_b_sha256)
        trial_verdicts.append("confirmed" if valid and operator_changed_both else
                              "rejected" if valid and operator_no_effect else "inconclusive")
    if len(trace.review_nosql_trials) == 2:
        first, second = trace.review_nosql_trials
        controls["independent_generations"] = (
            first.generation_sha256 != second.generation_sha256
            and first.session_a_sha256 != second.session_a_sha256
            and first.session_b_sha256 != second.session_b_sha256
            and first.profile_sha256 == second.profile_sha256)
    valid_trace = all(controls.values()) and len(trial_verdicts) == 2
    verdict = (trial_verdicts[0] if valid_trace and trial_verdicts[0] == trial_verdicts[1]
               else "inconclusive")
    reason = {
        "confirmed": "Two isolated trials prove a bounded operator selector updates exactly two owned synthetic reviews.",
        "rejected": "Two isolated trials show the operator selector has no effect or is explicitly denied, with controls intact.",
        "inconclusive": "The NoSQL selector effect or required scope, source, identity, reset or cleanup proof is incomplete.",
    }[verdict]
    return AccessCheckEvidence(check_id=trace.check_id, verdict=verdict, reason=reason,
        binding_id=trace.binding_id, source_snapshot_digest=trace.source_snapshot_digest,
        control_results=controls, repeated_trials=2 if valid_trace else 0,
        exchange_count=trace.exchange_count, reset_complete=trace.reset_complete,
        cleanup_complete=trace.cleanup_complete, integrity_verified=trace.integrity_verified)
