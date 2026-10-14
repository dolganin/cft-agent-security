"""Deterministic B06 interpretation. No network, execution, or model conclusions."""
from schemas.b06_verification import B06VerificationResult

AUTH_OPERATIONS = (
    "baseline_login", "baseline_identity", "positive_identity", "positive_change",
    "positive_login", "positive_readback", "anonymous_change", "wrong_password_change",
    "baseline_relogin", "baseline_reidentity", "omission_change", "new_credential_login",
    "old_credential_login", "effect_identity", "other_identity_before", "other_owner_read",
    "other_identity_after",
)
REDIRECT_OPERATIONS = ("positive_redirect", "negative_redirect", "probe_redirect")


def _identity(e):
    return (e.status_code == 200 and e.identity_id is not None
            and e.identity_id == e.expected_identity_id
            and e.identity_sha256 is not None
            and e.identity_sha256 == e.expected_identity_sha256)


def evaluate(result: B06VerificationResult) -> tuple[str, str]:
    binding = result.binding
    if (not result.original_unchanged
            or tuple(t.generation for t in result.trials) != binding.generations):
        return "inconclusive", "Source integrity or independent generation binding failed."
    expected_scope = ("runtime_redirect_destination" if binding.tool == "verify_redirect_destination"
                      else "runtime_password_reauthentication")
    if result.scope != expected_scope:
        return "inconclusive", "Capability and observation scope differ."
    outcomes = []
    for trial in result.trials:
        if (not trial.cleanup_complete or trial.error != "none" or trial.sink_requests
                or trial.redirect_followed or trial.destination_dns
                or any(e.truncated for e in trial.exchanges)):
            return "inconclusive", "Trial failed, output was incomplete, or cleanup was not verified."
        operations = AUTH_OPERATIONS if binding.tool == "verify_auth_reauthentication" else REDIRECT_OPERATIONS
        if tuple(e.operation for e in trial.exchanges) != operations:
            return "inconclusive", "Required controls, probe or readback are missing or reordered."
        obs = dict(zip(operations, trial.exchanges, strict=True))
        if binding.tool == "verify_redirect_destination":
            positive, negative, probe = trial.exchanges
            if (positive.status_code not in {301, 302, 303, 307, 308}
                    or positive.location != "approved" or positive.location_sha256 is None
                    or negative.status_code != 406 or negative.location != "none"):
                return "inconclusive", "Redirect controls did not establish the expected baseline."
            if probe.status_code in {301, 302, 303, 307, 308} and probe.location == "probe" and probe.location_sha256:
                outcomes.append("confirmed")
            elif probe.status_code == 406 and probe.location == "none":
                outcomes.append("rejected")
            else:
                return "inconclusive", "Probe destination was ambiguous or outside the protocol."
        else:
            proof = trial.preparation
            if (proof is None or proof.fixture_id != binding.fixture_id
                    or proof.generation != trial.generation or proof.source_snapshot != binding.source_snapshot
                    or proof.http_exchanges != trial.setup_http_exchanges
                    or set(proof.controls) != {"availability", "negative-control", "anonymous-identity"}
                    or len(proof.controls) != 3
                    or {r.id for r in proof.roles} != {"role-a", "role-b"}
                    or not all(r.identity_verified and r.server_role == "customer" for r in proof.roles)):
                return "inconclusive", "Independent preparation controls or identities are missing."
            roles = {r.id: r for r in proof.roles}
            identities = ("baseline_identity", "positive_identity", "positive_readback",
                          "baseline_reidentity", "effect_identity", "other_identity_before",
                          "other_identity_after")
            if (trial.setup_http_exchanges == 0 or not all(_identity(obs[k]) for k in identities)
                    or not all(obs[k].login_accepted is True for k in (
                        "baseline_login", "positive_login", "baseline_relogin"))
                    or obs["positive_change"].status_code != 200
                    or obs["anonymous_change"].denial != "auth_required"
                    or obs["wrong_password_change"].status_code != 401
                    or obs["wrong_password_change"].denial != "wrong_current"):
                return "inconclusive", "Authentication, reauthentication or identity controls failed."
            actor_a, actor_b = obs["baseline_identity"], obs["positive_identity"]
            if (actor_a.identity_id == actor_b.identity_id
                    or actor_a.identity_id != roles["role-a"].server_user_id
                    or actor_b.identity_id != roles["role-b"].server_user_id
                    or actor_a.identity_sha256 != roles["role-a"].identity_sha256
                    or actor_b.identity_sha256 != roles["role-b"].identity_sha256
                    or proof.owner_id != actor_b.identity_id
                    or proof.object_sha256 != obs["other_owner_read"].object_sha256
                    or any(obs[k].identity_id != actor_a.identity_id for k in (
                        "baseline_reidentity", "effect_identity"))
                    or any(obs[k].identity_id != actor_b.identity_id for k in (
                        "positive_readback", "other_identity_before", "other_identity_after"))
                    or obs["other_owner_read"].status_code != 200
                    or obs["other_owner_read"].owner_id != actor_b.identity_id
                    or obs["other_owner_read"].object_sha256 is None
                    or obs["other_owner_read"].object_sha256 != obs["other_owner_read"].expected_object_sha256):
                return "inconclusive", "Actors or independently owned control object did not match."
            new, old = obs["new_credential_login"], obs["old_credential_login"]
            if (obs["omission_change"].status_code == 200 and new.login_accepted is True
                    and old.login_accepted is False and old.status_code == 401):
                outcomes.append("confirmed")
            elif (obs["omission_change"].status_code == 401 and old.login_accepted is True
                  and new.login_accepted is False and new.status_code == 401):
                outcomes.append("rejected")
            else:
                return "inconclusive", "Independent credential readback did not establish an unambiguous effect."
    if len(set(outcomes)) != 1:
        return "inconclusive", "Independent trials produced inconsistent observations."
    return outcomes[0], ("Two independent trials established the mapped runtime effect."
                         if outcomes[0] == "confirmed" else
                         "Two independent trials rejected the mapped effect with working controls.")
