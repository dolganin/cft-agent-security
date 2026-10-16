from evidence.access_control import evaluate_access_check
from executor.access_fixture import digest
from schemas.access_verification import AccessCheckTrace
from schemas.action import ActionProposal
from schemas.feedback_verification import FEEDBACK_ORDER, FeedbackOwnershipTrial
from schemas.verification_binding import VerificationBinding
from security.access_verification import binding_id


def _action():
    binding = VerificationBinding(
        route_id="juice-feedback-owner", handler_id="juice.feedback.create",
        target="juice-access-fixture", finding_id="finding-feedback-owner",
        family="access-control", source_file="routes/verify.ts",
        line_start=1, line_end=2, anchor_sha256="b" * 64, source_snapshot="a" * 64,
        source_files={"routes/verify.ts": "c" * 64}, map_sha256="d" * 64,
        service="juice", endpoint="/api/Feedbacks", method="POST",
        tool="verify_access_control", check="own_write",
    )
    return ActionProposal(
        id="feedback-owner-test", tool="verify_access_control", target="juice-access-fixture",
        environment="sandbox", parameters={"check_id": "juice-feedback-owner-v1"},
        purpose="fixed test", expected_evidence="typed two-generation trial", service="juice",
        endpoint="/api/Feedbacks", verification_binding=binding,
    )


def _trial(index, *, verdict):
    created = verdict == "confirmed"
    denied = verdict == "rejected"
    return FeedbackOwnershipTrial(
        schema_version="b05.feedback.trial.v1",
        generation_sha256=digest(["generation", index]),
        source_snapshot_digest=digest("fixture-source"),
        fixture_snapshot_digest=digest("fixture-source"),
        binding_snapshot_digest="a" * 64,
        profile_sha256=digest("profile"),
        identity_a_sha256=digest([index, "identity-a"]),
        identity_b_sha256=digest([index, "identity-b"]),
        session_a_sha256=digest([index, "session-a"]),
        session_b_sha256=digest([index, "session-b"]),
        control_marker_sha256=digest([index, "control"]),
        probe_marker_sha256=digest([index, "probe"]),
        captcha_control_passed=True,
        owner_create_status=201, owner_readback_status=200, owner_readback_matches=True,
        probe_status=201 if created else 403, probe_created=created,
        probe_readback_status=200,
        probe_owner_role="role-b" if created else "absent",
        probe_comment_matches=created,
        control_unchanged_after_denial=True if denied else None,
        request_order=FEEDBACK_ORDER, http_exchanges=10,
    )


def _trace(action, *, verdict):
    return AccessCheckTrace(
        check_id="juice-feedback-owner-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment="sandbox", operation="feedback_owner",
        endpoint_id="feedback-create", method="POST", object_ref="feedback-b", controls={},
        generations=[], exchanges=[], feedback_trials=[_trial(i, verdict=verdict) for i in range(2)],
        fixture_source_snapshot_digest=digest("fixture-source"), exchange_count=20,
        request_budget=20, reset_complete=True, cleanup_complete=True, integrity_verified=True,
    )


def test_feedback_owner_confirms_only_when_other_users_readback_contains_probe():
    action = _action()
    evidence = evaluate_access_check(_trace(action, verdict="confirmed"), action)
    assert evidence.verdict == "confirmed"
    assert evidence.repeated_trials == 2


def test_feedback_owner_rejects_explicit_denial_with_unchanged_control():
    action = _action()
    evidence = evaluate_access_check(_trace(action, verdict="rejected"), action)
    assert evidence.verdict == "rejected"
    assert evidence.repeated_trials == 2


def test_feedback_owner_fails_closed_on_wrong_binding_or_one_disagreeing_trial():
    action = _action()
    trace = _trace(action, verdict="confirmed")
    altered_trial = _trial(1, verdict="rejected")
    altered = trace.model_copy(update={"feedback_trials": [trace.feedback_trials[0], altered_trial]})
    assert evaluate_access_check(altered, action).verdict == "inconclusive"
    assert evaluate_access_check(trace, None).verdict == "inconclusive"
