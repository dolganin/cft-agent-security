"""Offline verdict for persisted, identity-bound feedback owner evidence."""

from schemas.access_verification import AccessCheckEvidence
from schemas.feedback_verification import FEEDBACK_ORDER
from security.access_verification import binding_id, registered_check


def evaluate_feedback_owner(trace, action):
    registration = registered_check({"check_id": trace.check_id})
    binding = bool(action and action.verification_binding
        and action.tool == "verify_access_control" and action.service == "juice"
        and action.endpoint == registration.endpoint
        and action.parameters == {"check_id": "juice-feedback-owner-v1"}
        and action.verification_binding.tool == action.tool
        and action.verification_binding.check == registration.check
        and action.verification_binding.route_id == registration.route_id
        and action.verification_binding.family == "access-control"
        and action.verification_binding.method == "POST"
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
        "schedule": (trace.operation == "feedback_owner" and trace.method == "POST"
            and trace.endpoint_id == "feedback-create" and trace.object_ref == "feedback-b"
            and trace.request_budget == 20 and trace.exchange_count == 20
            and not trace.exchanges and not trace.generations and not trace.review_trials
            and not trace.review_nosql_trials and not trace.user_fields_trials
            and len(trace.feedback_trials) == 2),
    }
    verdicts = []
    for index, trial in enumerate(trace.feedback_trials):
        valid = (trial.source_snapshot_digest == trace.fixture_source_snapshot_digest
            and trial.fixture_snapshot_digest == trace.fixture_source_snapshot_digest
            and trial.binding_snapshot_digest == trace.source_snapshot_digest
            and trial.request_order == FEEDBACK_ORDER and trial.http_exchanges == 10
            and trial.identity_a_sha256 != trial.identity_b_sha256
            and trial.session_a_sha256 != trial.session_b_sha256
            and trial.control_marker_sha256 != trial.probe_marker_sha256
            and trial.captcha_control_passed
            and trial.owner_create_status in {200, 201}
            and trial.owner_readback_status == 200 and trial.owner_readback_matches)
        controls[f"trial_{index + 1}"] = valid
        forged_owner = (trial.probe_created and trial.probe_status in {200, 201}
            and trial.probe_readback_status == 200 and trial.probe_owner_role == "role-b"
            and trial.probe_comment_matches)
        enforced_owner = (trial.probe_created and trial.probe_status in {200, 201}
            and trial.probe_readback_status == 200 and trial.probe_owner_role == "role-a"
            and trial.probe_comment_matches)
        explicit_denial = (not trial.probe_created and trial.probe_status in {400, 401, 403, 422}
            and trial.probe_readback_status == 200
            and trial.control_unchanged_after_denial is True)
        verdicts.append("confirmed" if valid and forged_owner else
                         "rejected" if valid and (enforced_owner or explicit_denial)
                         else "inconclusive")
    if len(trace.feedback_trials) == 2:
        first, second = trace.feedback_trials
        controls["independent_generations"] = (
            first.generation_sha256 != second.generation_sha256
            and first.identity_a_sha256 != second.identity_a_sha256
            and first.identity_b_sha256 != second.identity_b_sha256
            and first.session_a_sha256 != second.session_a_sha256
            and first.session_b_sha256 != second.session_b_sha256
            and first.control_marker_sha256 != second.control_marker_sha256
            and first.probe_marker_sha256 != second.probe_marker_sha256
            and first.profile_sha256 == second.profile_sha256)
    valid_trace = all(controls.values()) and len(verdicts) == 2
    verdict = verdicts[0] if valid_trace and verdicts[0] == verdicts[1] else "inconclusive"
    reason = {
        "confirmed": "Two isolated trials persist an authenticated actor's feedback under the other user's ID, verified by that user's server readback.",
        "rejected": "Two isolated trials either enforce actor ownership or deny foreign attribution while preserving the owner control.",
        "inconclusive": "Feedback attribution or required CAPTCHA, source, identity, reset or cleanup evidence is incomplete.",
    }[verdict]
    return AccessCheckEvidence(
        check_id=trace.check_id, verdict=verdict, reason=reason,
        binding_id=trace.binding_id, source_snapshot_digest=trace.source_snapshot_digest,
        control_results=controls, repeated_trials=2 if valid_trace else 0,
        exchange_count=trace.exchange_count, reset_complete=trace.reset_complete,
        cleanup_complete=trace.cleanup_complete, integrity_verified=trace.integrity_verified,
    )
