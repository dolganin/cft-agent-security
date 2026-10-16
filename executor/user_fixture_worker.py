"""Fixed Docker-only whoami private-field disclosure control."""

from __future__ import annotations

import copy
import json
import os
import re
import sys
import time
from pathlib import Path

from fixture import STATE, FixtureClient, digest

CHECK_ID = "juice-user-private-fields-v1"
SCHEMA_VERSION = "user.fields.trial.v1"
ROLES = ("role-a", "role-b")
USER_PATH = "/rest/user/whoami"
ALLOWED_PATH = "/rest/user/whoami?fields=id,email,role"
PRIVATE_PATH = "/rest/user/whoami?fields=id,email,password"
UNKNOWN_PATH = "/rest/user/whoami?fields=id,email,cft_fixture_unknown"
USER_FIELDS_ORDER = [
    "identity-a-before", "identity-b-before", "default-fields", "allowed-fields",
    "private-fields-first", "private-fields-second", "anonymous-private-fields",
    "unknown-field-control", "identity-a-after", "identity-b-after",
]
DEFAULT_PUBLIC_FIELDS = {"id", "email", "lastLoginIp", "profileImage"}
ALLOWED_PUBLIC_FIELDS = {"id", "email", "role"}
HASH_RE = re.compile(r"^[a-f0-9]{64}$")
FAILURE = "fixture_technical_error"


class UserFixtureFailure(ValueError):
    """Internal fixed-code failure; never expose request data."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise UserFixtureFailure(code)


def _identity_sha(user: object) -> tuple[str, bool]:
    if not isinstance(user, dict):
        return digest([None, None]), False
    user_id, email = user.get("id"), user.get("email")
    valid_shape = type(user_id) is int and isinstance(email, str) and bool(email)
    return digest([user_id, email]) if valid_shape else digest([None, None]), valid_shape


def _user(payload: object) -> dict:
    _require(isinstance(payload, dict), "user_response_shape_invalid")
    user = payload.get("user")
    _require(isinstance(user, dict), "user_response_shape_invalid")
    return user


def _probe(status: int, payload: object, expected_id: int | None, expected_email: str | None,
           private_field: str = "password") -> tuple[dict, bool, bool]:
    user = _user(payload) if isinstance(payload, dict) and isinstance(payload.get("user"), dict) else {}
    identity_sha, identity_shape = _identity_sha(user)
    identity_ok = status == 200 and identity_shape
    if expected_id is not None and expected_email is not None:
        identity_ok = identity_ok and user.get("id") == expected_id and user.get("email") == expected_email
    private_present = private_field in user
    private_value_sha = digest(user[private_field]) if private_present else None
    return {
        "status": status,
        "identity_sha": identity_sha,
        "private_present": private_present,
        "private_value_sha": private_value_sha,
    }, identity_ok, private_present


def _request(client: FixtureClient, order: list[str], label: str, path: str,
             role: str | None) -> tuple[int, object]:
    order.append(label)
    return client.request("GET", path, role=role)


def _validate_saved(saved: dict, config: dict) -> dict:
    _require(config.get("active_check_id") == CHECK_ID, "wrong_active_check")
    _require(saved.get("generation") == config.get("generation"), "stale_fixture_generation")
    roles = saved.get("roles")
    _require(isinstance(roles, dict) and all(role in roles for role in ROLES), "fixture_roles_missing")
    for role in ROLES:
        entry = roles[role]
        _require(isinstance(entry, dict) and type(entry.get("user_id")) is int,
                 "fixture_role_invalid")
        _require(isinstance(entry.get("email"), str) and entry["email"], "fixture_role_invalid")
        _require(isinstance(entry.get("token"), str) and entry["token"], "fixture_session_missing")
        _require(isinstance(entry.get("session_binding_sha256"), str)
                 and HASH_RE.fullmatch(entry["session_binding_sha256"]),
                 "fixture_session_binding_missing")
        _require(isinstance(entry.get("password_value_sha256"), str)
                 and HASH_RE.fullmatch(entry["password_value_sha256"]),
                 "fixture_password_sentinel_missing")
    _require(isinstance(config.get("profile"), dict), "profile_invalid")
    _require(isinstance(config.get("source_snapshot"), str), "source_snapshot_missing")
    _require(isinstance(config.get("binding_snapshot_digest"), str), "binding_snapshot_missing")
    return roles


def run_protocol(client: FixtureClient, saved: dict, config: dict) -> dict:
    """Run exactly ten fixed whoami requests using already provisioned roles."""
    roles = _validate_saved(saved, config)
    client.roles = copy.deepcopy(roles)
    client.limit = 10
    client.deadline = time.monotonic() + 20.0
    order: list[str] = []

    before_a = client.identity("role-a")
    order.append("identity-a-before")
    before_b = client.identity("role-b")
    order.append("identity-b-before")
    _require(before_a.get("identity_verified") is True and before_b.get("identity_verified") is True,
             "identity_bracket_failed")

    status, payload = _request(client, order, "default-fields", USER_PATH, "role-a")
    default_user = _user(payload)
    _default_sha, default_identity = _identity_sha(default_user)
    default_identity = (status == 200 and default_identity
                        and default_user.get("id") == roles["role-a"]["user_id"]
                        and default_user.get("email") == roles["role-a"]["email"])
    default_public_ok = set(default_user).issubset(DEFAULT_PUBLIC_FIELDS)
    default_private_absent = default_identity and default_public_ok \
        and "password" not in default_user and "passwordHash" not in default_user

    status, payload = _request(client, order, "allowed-fields", ALLOWED_PATH, "role-a")
    allowed_user = _user(payload)
    _allowed_sha, allowed_shape = _identity_sha(allowed_user)
    allowed_identity_verified = (status == 200 and allowed_shape
                                 and allowed_user.get("id") == roles["role-a"]["user_id"]
                                 and allowed_user.get("email") == roles["role-a"]["email"]
                                 and set(allowed_user) == ALLOWED_PUBLIC_FIELDS
                                 and allowed_user.get("role") == "customer")

    probes: list[dict] = []
    probe_identity_ok: list[bool] = []
    probe_presence: list[bool] = []
    for label in ("private-fields-first", "private-fields-second"):
        status, payload = _request(client, order, label, PRIVATE_PATH, "role-a")
        probe, identity_ok, present = _probe(
            status, payload, roles["role-a"]["user_id"], roles["role-a"]["email"])
        probes.append(probe)
        probe_identity_ok.append(identity_ok)
        probe_presence.append(present)

    status, payload = _request(client, order, "anonymous-private-fields", PRIVATE_PATH, None)
    anonymous_probe, anonymous_identity_ok, _ = _probe(status, payload, None, None)
    probes.append(anonymous_probe)
    anonymous_user = _user(payload) if isinstance(payload, dict) and isinstance(payload.get("user"), dict) else {}
    anonymous_private_absent = status == 200 and not anonymous_identity_ok \
        and "password" not in anonymous_user and "passwordHash" not in anonymous_user

    status, payload = _request(client, order, "unknown-field-control", UNKNOWN_PATH, "role-a")
    unknown_user = _user(payload)
    _unknown_sha, unknown_shape = _identity_sha(unknown_user)
    unknown_field_omitted = (status == 200 and unknown_shape
                             and unknown_user.get("id") == roles["role-a"]["user_id"]
                             and unknown_user.get("email") == roles["role-a"]["email"]
                             and "cft_fixture_unknown" not in unknown_user
                             and "password" not in unknown_user)

    client.identity("role-a")
    order.append("identity-a-after")
    client.identity("role-b")
    order.append("identity-b-after")
    _require(order == USER_FIELDS_ORDER, "request_order_invalid")
    _require(getattr(client, "operation_exchanges", 10) == 10, "request_budget_invalid")

    expected_private = roles["role-a"]["password_value_sha256"]
    authenticated_private_ok = (
        len(set(probe_presence)) == 1
        and all((not probe["private_present"] or probe["private_value_sha"] == expected_private)
                for probe in probes[:2])
        and all(probe_identity_ok)
    )
    trial = {
        "schema_version": SCHEMA_VERSION,
        "generation_sha256": digest(config["generation"]),
        "source_snapshot_digest": config["source_snapshot"],
        "fixture_snapshot_digest": config.get("fixture_snapshot_digest", config["source_snapshot"]),
        "binding_snapshot_digest": config["binding_snapshot_digest"],
        "profile_sha256": digest(config["profile"]),
        "identity_a_sha256": digest([roles["role-a"]["user_id"], roles["role-a"]["email"]]),
        "identity_b_sha256": digest([roles["role-b"]["user_id"], roles["role-b"]["email"]]),
        "session_a_sha256": roles["role-a"]["session_binding_sha256"],
        "session_b_sha256": roles["role-b"]["session_binding_sha256"],
        "expected_private_value_sha256": expected_private,
        "private_probes": probes,
        "default_private_absent": default_private_absent,
        "allowed_identity_verified": allowed_identity_verified,
        "anonymous_private_absent": anonymous_private_absent,
        "unknown_field_omitted": unknown_field_omitted,
        "request_order": list(USER_FIELDS_ORDER),
        "http_exchanges": 10,
    }
    if (default_private_absent and allowed_identity_verified and anonymous_private_absent
            and unknown_field_omitted and authenticated_private_ok):
        return {"status": "completed", "trial": trial}
    return {"status": "inconclusive", "trial": trial}


def _failure_code(error: BaseException) -> str:
    if isinstance(error, UserFixtureFailure):
        return str(error).split(":", 1)[0]
    return FAILURE


def execute(config: dict) -> dict:
    try:
        saved = json.loads(STATE.read_text(encoding="utf-8"))
        client = FixtureClient(config)
        return run_protocol(client, saved, config)
    except (UserFixtureFailure, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        return {"status": "failed", "reason": _failure_code(error)}


def main() -> int:
    if os.getenv("CFT_B04_CONTAINER") != "1" or not Path("/.dockerenv").is_file():
        print(json.dumps({"status": "failed", "reason": "docker_only"}, separators=(",", ":")))
        return 1
    try:
        if len(sys.argv) != 1:
            result = {"status": "failed", "reason": "unsupported_cli"}
        else:
            config = json.loads(Path("/input/profile.json").read_text(encoding="utf-8"))
            result = execute(config)
    except (OSError, ValueError, TypeError, AttributeError):
        result = {"status": "failed", "reason": FAILURE}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
