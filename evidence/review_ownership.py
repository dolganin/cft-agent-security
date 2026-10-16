"""Offline property-specific verdict; HTTP success alone is never sufficient."""
from schemas.access_verification import AccessCheckEvidence
from schemas.review_verification import ORDER
from security.access_verification import binding_id, registered_check


def evaluate_review_ownership(trace, action):
    registration = registered_check({"check_id": trace.check_id})
    binding = bool(action and action.verification_binding
        and action.tool == "verify_access_control"
        and action.service == "juice" and action.endpoint == registration.endpoint
        and action.parameters == {"check_id": "juice-review-own-write-v1"}
        and action.verification_binding.tool == action.tool
        and action.verification_binding.check == registration.check
        and action.verification_binding.route_id == registration.route_id
        and action.verification_binding.family == "access-control"
        and action.verification_binding.method == "PATCH"
        and action.verification_binding.endpoint == registration.endpoint
        and action.verification_binding.method == registration.method
        and action.verification_binding.finding_id
        and trace.binding_id == binding_id(action)
        and trace.source_snapshot_digest == action.verification_binding.source_snapshot
        and trace.review_source_snapshot_digest is not None
        and trace.target == action.target and action.environment == trace.environment == "sandbox")
    controls = {"binding": binding, "cleanup": trace.cleanup_complete,
        "integrity": trace.integrity_verified, "reset": trace.reset_complete,
        "technical_success": trace.technical_error is None,
        "schedule": (trace.operation == "review_update" and trace.method == "PATCH"
            and trace.object_ref == "review-b" and trace.endpoint_id == "review-write"
            and trace.request_budget == 26 and trace.exchange_count == 26
            and not trace.exchanges and not trace.generations and not trace.review_nosql_trials
            and len(trace.review_trials) == 2)}
    required = {"identities_verified", "owned_records_distinct", "owners_preserved",
                "unrelated_records_unchanged"}
    verdicts = []
    for index, trial in enumerate(trace.review_trials):
        valid = (trial.source_snapshot_digest == trace.review_source_snapshot_digest
            and trial.fixture_snapshot_digest == trace.review_source_snapshot_digest
            and trial.binding_snapshot_digest == trace.source_snapshot_digest
            and trial.request_order == ORDER and trial.http_exchanges == 13
            and trial.identity_a_sha256 != trial.identity_b_sha256
            and trial.session_a_sha256 != trial.session_b_sha256
            and trial.object_a_sha256 != trial.object_b_sha256
            and trial.owner_a_sha256 != trial.owner_b_sha256
            and set(trial.controls) == required and all(trial.controls.values())
            and trial.initial_a_sha256 == trial.final_a_sha256
            and len({trial.baseline_b_sha256, trial.owner_marker_sha256, trial.probe_marker_sha256}) == 3
            and trial.owner_status == 200 and trial.owner_readback_sha256 == trial.owner_marker_sha256
            and trial.anonymous_status in {401, 403}
            and trial.anonymous_readback_sha256 == trial.owner_marker_sha256)
        controls[f"trial_{index + 1}"] = valid
        verdicts.append("confirmed" if valid and trial.probe_status == 200
            and trial.probe_readback_sha256 == trial.probe_marker_sha256 else
            "rejected" if valid and trial.probe_status in {401, 403}
            and trial.probe_readback_sha256 == trial.owner_marker_sha256 else "inconclusive")
    if len(trace.review_trials) == 2:
        a, b = trace.review_trials
        controls["independent_generations"] = (a.generation_sha256 != b.generation_sha256
            and a.session_a_sha256 != b.session_a_sha256 and a.session_b_sha256 != b.session_b_sha256
            and a.profile_sha256 == b.profile_sha256)
    valid = all(controls.values()) and len(verdicts) == 2
    verdict = verdicts[0] if valid and verdicts[0] == verdicts[1] else "inconclusive"
    return AccessCheckEvidence(check_id=trace.check_id, verdict=verdict,
        reason={"confirmed": "Two isolated trials prove a scalar-ID cross-owner review message update.",
                "rejected": "Two isolated trials explicitly deny the scalar-ID cross-owner update with unchanged owner data.",
                "inconclusive": "Review ownership effect or required controls/provenance were not established."}[verdict],
        binding_id=trace.binding_id, source_snapshot_digest=trace.source_snapshot_digest,
        control_results=controls, repeated_trials=2 if valid else 0, exchange_count=trace.exchange_count,
        reset_complete=trace.reset_complete, cleanup_complete=trace.cleanup_complete,
        integrity_verified=trace.integrity_verified)
