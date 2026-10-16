from evidence.access_control import evaluate_access_check
from executor.access_fixture import digest
from schemas.access_verification import AccessCheckTrace
from schemas.action import ActionProposal
from schemas.user_verification import USER_FIELDS_ORDER, UserFieldsTrial, UserPrivateProbe
from schemas.verification_binding import VerificationBinding
from security.access_verification import binding_id


def _action():
    source = "a" * 64
    binding = VerificationBinding(
        route_id="juice-user-private-fields", handler_id="juice.user.whoami",
        target="juice-access-fixture", finding_id="finding-user-private",
        family="sensitive-data-exposure", source_file="routes/currentUser.ts",
        line_start=1, line_end=2, anchor_sha256="b" * 64, source_snapshot=source,
        source_files={"routes/currentUser.ts": "c" * 64}, map_sha256="d" * 64,
        service="juice", endpoint="/rest/user/whoami", method="GET",
        tool="verify_access_control", check="private_fields",
    )
    return ActionProposal(
        id="user-fields-test", tool="verify_access_control", target="juice-access-fixture",
        environment="sandbox", parameters={"check_id": "juice-user-private-fields-v1"},
        purpose="fixed test", expected_evidence="typed trial", service="juice",
        endpoint="/rest/user/whoami", verification_binding=binding,
    )


def _trace(action, *, leaked):
    trials = []
    for index in range(2):
        identity_a, identity_b = digest([index, "a"]), digest([index, "b"])
        private_hash = digest(["private", index])
        probes = [
            UserPrivateProbe(status=200, identity_sha=identity_a,
                private_present=leaked, private_value_sha=private_hash if leaked else None),
            UserPrivateProbe(status=200, identity_sha=identity_a,
                private_present=leaked, private_value_sha=private_hash if leaked else None),
            UserPrivateProbe(status=200, identity_sha=digest([None, None]), private_present=False),
        ]
        trials.append(UserFieldsTrial(
            schema_version="user.fields.trial.v1", generation_sha256=digest(["gen", index]),
            source_snapshot_digest=digest("fixture-source"),
            fixture_snapshot_digest=digest("fixture-source"),
            binding_snapshot_digest=action.verification_binding.source_snapshot,
            profile_sha256=digest("profile"), identity_a_sha256=identity_a,
            identity_b_sha256=identity_b, session_a_sha256=digest(["session-a", index]),
            session_b_sha256=digest(["session-b", index]),
            expected_private_value_sha256=private_hash, private_probes=probes,
            default_private_absent=True, allowed_identity_verified=True,
            anonymous_private_absent=True, unknown_field_omitted=True,
            request_order=USER_FIELDS_ORDER, http_exchanges=10,
        ))
    return AccessCheckTrace(
        check_id="juice-user-private-fields-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment="sandbox", operation="user_private_fields",
        endpoint_id="user-fields", method="GET", object_ref="user-a", controls={},
        generations=[], exchanges=[], user_fields_trials=trials,
        fixture_source_snapshot_digest=digest("fixture-source"), exchange_count=20,
        request_budget=20, reset_complete=True, cleanup_complete=True,
        integrity_verified=True,
    )


def test_user_private_fields_rejected_when_private_value_is_safely_omitted():
    action = _action()
    evidence = evaluate_access_check(_trace(action, leaked=False), action)
    assert evidence.verdict == "rejected"
    assert evidence.repeated_trials == 2


def test_user_private_fields_confirmed_only_when_matching_private_value_is_returned():
    action = _action()
    evidence = evaluate_access_check(_trace(action, leaked=True), action)
    assert evidence.verdict == "confirmed"
    assert evidence.repeated_trials == 2


def test_user_private_fields_fails_closed_on_binding_or_control_mismatch():
    action = _action()
    trace = _trace(action, leaked=True)
    trial = trace.user_fields_trials[1].model_copy(update={"unknown_field_omitted": False})
    altered = trace.model_copy(update={"user_fields_trials": [trace.user_fields_trials[0], trial]})
    assert evaluate_access_check(altered, action).verdict == "inconclusive"
    assert evaluate_access_check(trace, None).verdict == "inconclusive"
