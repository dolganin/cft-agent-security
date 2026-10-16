"""Offline verdict for the fixed, redacted whoami private-field protocol."""
from schemas.access_verification import AccessCheckEvidence
from schemas.user_verification import USER_FIELDS_ORDER
from security.access_verification import binding_id, registered_check


def evaluate_user_fields(trace, action):
    registration = registered_check({"check_id": trace.check_id})
    binding = bool(action and action.verification_binding
        and action.tool == "verify_access_control" and action.service == "juice"
        and action.endpoint == registration.endpoint
        and action.parameters == {"check_id": "juice-user-private-fields-v1"}
        and action.verification_binding.tool == action.tool
        and action.verification_binding.check == registration.check
        and action.verification_binding.route_id == registration.route_id
        and action.verification_binding.family == "sensitive-data-exposure"
        and action.verification_binding.method == "GET"
        and action.verification_binding.endpoint == registration.endpoint
        and bool(action.verification_binding.finding_id)
        and trace.binding_id == binding_id(action)
        and trace.source_snapshot_digest == action.verification_binding.source_snapshot
        and trace.fixture_source_snapshot_digest is not None
        and trace.target == action.target and action.environment == trace.environment == "sandbox")
    controls = {
        "binding": binding,
        "cleanup": trace.cleanup_complete,
        "integrity": trace.integrity_verified,
        "reset": trace.reset_complete,
        "technical_success": trace.technical_error is None,
        "schedule": (trace.operation == "user_private_fields" and trace.method == "GET"
            and trace.endpoint_id == "user-fields" and trace.object_ref == "user-a"
            and trace.request_budget == 20 and trace.exchange_count == 20
            and not trace.exchanges and not trace.generations and not trace.review_trials
            and not trace.review_nosql_trials and len(trace.user_fields_trials) == 2),
    }
    verdicts = []
    for index, trial in enumerate(trace.user_fields_trials):
        valid = (trial.source_snapshot_digest == trace.fixture_source_snapshot_digest
            and trial.fixture_snapshot_digest == trace.fixture_source_snapshot_digest
            and trial.binding_snapshot_digest == trace.source_snapshot_digest
            and trial.request_order == USER_FIELDS_ORDER and trial.http_exchanges == 10
            and trial.identity_a_sha256 != trial.identity_b_sha256
            and trial.session_a_sha256 != trial.session_b_sha256
            and trial.expected_private_value_sha256
            and len(trial.private_probes) == 3
            and trial.private_probes[0].status == 200
            and trial.private_probes[1].status == 200
            and trial.private_probes[0].identity_sha == trial.identity_a_sha256
            and trial.private_probes[1].identity_sha == trial.identity_a_sha256
            and trial.private_probes[2].identity_sha not in {
                trial.identity_a_sha256, trial.identity_b_sha256}
            and trial.default_private_absent and trial.allowed_identity_verified
            and trial.anonymous_private_absent and trial.unknown_field_omitted)
        controls[f"trial_{index + 1}"] = valid
        first, second, _anonymous = trial.private_probes
        leaked = (first.private_present and second.private_present
            and first.private_value_sha == trial.expected_private_value_sha256
            and second.private_value_sha == trial.expected_private_value_sha256)
        safely_omitted = (not first.private_present and not second.private_present
            and first.private_value_sha is None and second.private_value_sha is None)
        verdicts.append("confirmed" if valid and leaked else
                         "rejected" if valid and safely_omitted else "inconclusive")
    if len(trace.user_fields_trials) == 2:
        first, second = trace.user_fields_trials
        controls["independent_generations"] = (
            first.generation_sha256 != second.generation_sha256
            and first.identity_a_sha256 != second.identity_a_sha256
            and first.identity_b_sha256 != second.identity_b_sha256
            and first.session_a_sha256 != second.session_a_sha256
            and first.session_b_sha256 != second.session_b_sha256
            and first.expected_private_value_sha256 != second.expected_private_value_sha256
            and first.profile_sha256 == second.profile_sha256)
    valid_trace = all(controls.values()) and len(verdicts) == 2
    verdict = (verdicts[0] if valid_trace and verdicts[0] == verdicts[1]
               else "inconclusive")
    reason = {
        "confirmed": "Two isolated user generations return each authenticated user's own password hash for an unapproved selected field.",
        "rejected": "Two isolated user generations omit the private password field while preserving identity and field-selection controls.",
        "inconclusive": "Private-field behavior or required identity, scope, source, reset or cleanup proof is incomplete.",
    }[verdict]
    return AccessCheckEvidence(
        check_id=trace.check_id, verdict=verdict, reason=reason,
        binding_id=trace.binding_id, source_snapshot_digest=trace.source_snapshot_digest,
        control_results=controls, repeated_trials=2 if valid_trace else 0,
        exchange_count=trace.exchange_count, reset_complete=trace.reset_complete,
        cleanup_complete=trace.cleanup_complete, integrity_verified=trace.integrity_verified,
    )
