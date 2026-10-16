"""Fixed, Docker-only scalar review ownership probe for the pinned Juice Shop lab.

This is an operator-owned control, not a generic request runner.  The mounted
``fixture.py`` supplies the already provisioned private roles and the bounded
HTTP client; this worker only performs the fixed thirteen-request protocol.
"""

from __future__ import annotations

import copy
import json
import os
import secrets
import sys
import time
from pathlib import Path

from fixture import STATE, FixtureClient, digest

CHECK_ID = "juice-review-own-write-v1"
NOSQL_CHECK_ID = "juice-review-nosql-selector-v1"
SCHEMA_VERSION = "review.owner.trial.v1"
NOSQL_SCHEMA_VERSION = "review.nosql.trial.v1"
ROLES = ("role-a", "role-b")
REQUEST_ORDER = [
    "identity-a-before", "identity-b-before", "create-a", "create-b",
    "baseline-read", "owner-write", "owner-readback", "anonymous-write",
    "anonymous-readback", "cross-write", "cross-readback", "identity-a-after",
    "identity-b-after",
]
BASELINE_PATH = "/rest/products/1/reviews"
UPDATE_PATH = "/rest/products/reviews"
FAILURE = "fixture_technical_error"


class ReviewFixtureFailure(ValueError):
    """Internal failure; public output is always a fixed code."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise ReviewFixtureFailure(code)


def _scalar(value: object) -> bool:
    return (isinstance(value, (str, int, float, bool)) or value is None) and not isinstance(value, (dict, list))


def _records(payload: object) -> list[dict]:
    if not isinstance(payload, dict) or payload.get("status") != "success":
        raise ReviewFixtureFailure("review_read_failed")
    rows = payload.get("data")
    _require(isinstance(rows, list), "review_read_shape_invalid")
    if not all(isinstance(row, dict) for row in rows):
        raise ReviewFixtureFailure("review_read_shape_invalid")
    return rows


def _review_id(row: dict) -> object:
    value = row.get("_id", row.get("id"))
    _require(_scalar(value) and value is not None, "review_id_not_scalar")
    return value


def _without_message(row: dict) -> dict:
    return {key: copy.deepcopy(value) for key, value in row.items() if key != "message"}


def _snapshot(rows: list[dict]) -> dict[str, dict]:
    result: dict[str, dict] = {}
    for row in rows:
        key = json.dumps(_review_id(row), sort_keys=True, separators=(",", ":"))
        _require(key not in result, "review_ids_not_unique")
        result[key] = copy.deepcopy(row)
    return result


def _find_marker(rows: list[dict], marker: str, email: str) -> dict:
    matches = [row for row in rows if row.get("message") == marker]
    _require(len(matches) == 1, "review_marker_not_unique")
    row = matches[0]
    _require(row.get("author") == email, "review_author_mismatch")
    _review_id(row)
    return row


def _same_nonmessage(before: dict, after: dict) -> bool:
    return _without_message(before) == _without_message(after)


def _read(client: FixtureClient, order: list[str], label: str) -> list[dict]:
    order.append(label)
    status, payload = client.request("GET", BASELINE_PATH)
    _require(status == 200, "review_read_failed")
    return _records(payload)


def _write(client: FixtureClient, order: list[str], label: str, role: str | None,
           review_id: object, message: str) -> int:
    _require(_scalar(review_id) and review_id is not None, "review_id_not_scalar")
    order.append(label)
    status, _ = client.request("PATCH", UPDATE_PATH,
                               {"id": review_id, "message": message}, role=role,
                               json_response=False)
    return status


def run_protocol(client: FixtureClient, saved: dict, config: dict) -> dict:
    """Run the fixed protocol against an already prepared fixture client."""
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
        _require(isinstance(entry.get("session_binding_sha256"), str), "fixture_session_binding_missing")
    client.roles = copy.deepcopy(roles)
    client.limit = 13
    client.deadline = time.monotonic() + 20.0

    order: list[str] = []
    client.identity("role-a")
    order.append("identity-a-before")
    client.identity("role-b")
    order.append("identity-b-before")

    marker_a = "cft-review-a-" + secrets.token_hex(16)
    marker_b = "cft-review-b-" + secrets.token_hex(16)
    owner_marker = "cft-review-owner-" + secrets.token_hex(16)
    anonymous_marker = "cft-review-anonymous-" + secrets.token_hex(16)
    probe_marker = "cft-review-probe-" + secrets.token_hex(16)

    for label, role, marker in (("create-a", "role-a", marker_a), ("create-b", "role-b", marker_b)):
        order.append(label)
        status, _ = client.request("PUT", BASELINE_PATH,
                                   {"message": marker, "author": roles[role]["email"]}, role=role,
                                   json_response=False)
        _require(status in {200, 201}, "review_create_failed")

    baseline_rows = _read(client, order, "baseline-read")
    row_a = _find_marker(baseline_rows, marker_a, roles["role-a"]["email"])
    row_b = _find_marker(baseline_rows, marker_b, roles["role-b"]["email"])
    review_a_id, review_b_id = _review_id(row_a), _review_id(row_b)
    _require(review_a_id != review_b_id, "review_ids_not_distinct")
    baseline = _snapshot(baseline_rows)
    baseline_b = copy.deepcopy(row_b)

    owner_status = _write(client, order, "owner-write", "role-b", review_b_id, owner_marker)
    owner_rows = _read(client, order, "owner-readback")
    owner_b = _find_marker(owner_rows, owner_marker, roles["role-b"]["email"])

    anonymous_status = _write(client, order, "anonymous-write", None, review_b_id, anonymous_marker)
    anonymous_rows = _read(client, order, "anonymous-readback")
    anonymous_b = next((row for row in anonymous_rows if _review_id(row) == review_b_id), None)
    _require(isinstance(anonymous_b, dict), "review_readback_missing")

    probe_status = _write(client, order, "cross-write", "role-a", review_b_id, probe_marker)
    probe_rows = _read(client, order, "cross-readback")
    probe_b = next((row for row in probe_rows if _review_id(row) == review_b_id), None)
    _require(isinstance(probe_b, dict), "review_readback_missing")

    client.identity("role-a")
    order.append("identity-a-after")
    client.identity("role-b")
    order.append("identity-b-after")
    _require(order == REQUEST_ORDER, "request_order_invalid")
    _require(getattr(client, "operation_exchanges", 13) == 13, "request_budget_invalid")

    final_a = next((row for row in probe_rows if _review_id(row) == review_a_id), None)
    _require(isinstance(final_a, dict), "review_readback_missing")
    final_a_message = final_a.get("message")
    _require(isinstance(final_a_message, str), "review_message_invalid")

    snapshots = [_snapshot(rows) for rows in (owner_rows, anonymous_rows, probe_rows)]
    owned_a_key = json.dumps(review_a_id, sort_keys=True, separators=(",", ":"))
    owned_b_key = json.dumps(review_b_id, sort_keys=True, separators=(",", ":"))
    _require(all(key in snapshot for snapshot in snapshots for key in (owned_a_key, owned_b_key)),
             "review_readback_missing")
    unrelated_unchanged = all(
        snapshot.keys() == baseline.keys()
        and all(snapshot.get(key) == baseline.get(key)
                for key in baseline if key not in {owned_a_key, owned_b_key})
        for snapshot in snapshots
    )
    ownership_preserved = all(
        snapshot[owned_a_key].get("author") == roles["role-a"]["email"]
        and snapshot[owned_b_key].get("author") == roles["role-b"]["email"]
        for snapshot in snapshots
    )
    a_unchanged = all(
        snapshot[owned_a_key].get("message") == marker_a
        and _same_nonmessage(baseline[owned_a_key], snapshot[owned_a_key])
        for snapshot in snapshots
    )
    b_nonmessage_unchanged = all(
        _same_nonmessage(baseline_b, snapshot[owned_b_key]) for snapshot in snapshots
    )
    owner_control = owner_status in {200, 204} and owner_b.get("message") == owner_marker
    anonymous_control = anonymous_status in {401, 403}
    controls = {
        "identities_verified": True,
        "owned_records_distinct": review_a_id != review_b_id,
        "owners_preserved": ownership_preserved and a_unchanged and b_nonmessage_unchanged,
        "unrelated_records_unchanged": unrelated_unchanged,
    }
    trial = {
        "schema_version": SCHEMA_VERSION,
        "generation_sha256": digest(config["generation"]),
        "source_snapshot_digest": config["source_snapshot"],
        "fixture_snapshot_digest": config["source_snapshot"],
        "binding_snapshot_digest": config["binding_snapshot_digest"],
        "profile_sha256": digest(config["profile"]),
        "identity_a_sha256": digest([roles["role-a"]["user_id"], roles["role-a"]["email"]]),
        "identity_b_sha256": digest([roles["role-b"]["user_id"], roles["role-b"]["email"]]),
        "session_a_sha256": roles["role-a"]["session_binding_sha256"],
        "session_b_sha256": roles["role-b"]["session_binding_sha256"],
        "object_a_sha256": digest([1, review_a_id]),
        "object_b_sha256": digest([1, review_b_id]),
        "owner_a_sha256": digest(roles["role-a"]["email"]),
        "owner_b_sha256": digest(roles["role-b"]["email"]),
        "initial_a_sha256": digest(marker_a),
        "final_a_sha256": digest(final_a_message),
        "baseline_b_sha256": digest(baseline_b),
        "owner_marker_sha256": digest(owner_marker),
        "probe_marker_sha256": digest(probe_marker),
        "owner_readback_sha256": digest(owner_b.get("message")),
        "anonymous_readback_sha256": digest(anonymous_b.get("message")),
        "probe_readback_sha256": digest(probe_b.get("message")),
        "owner_status": owner_status,
        "anonymous_status": anonymous_status,
        "probe_status": probe_status,
        "controls": controls,
        "http_exchanges": 13,
        "request_order": list(REQUEST_ORDER),
    }
    if all(controls.values()) and owner_control and anonymous_control:
        return {"status": "completed", "trial": trial}
    return {"status": "inconclusive", "reason": "review_ownership_controls_failed", "trial": trial}


def run_nosql_protocol(client: FixtureClient, saved: dict, config: dict) -> dict:
    """Probe only a two-ID operator selector over two synthetic reviews owned by role B."""
    _require(config.get("active_check_id") == NOSQL_CHECK_ID, "wrong_active_check")
    _require(saved.get("generation") == config.get("generation"), "stale_fixture_generation")
    roles = saved.get("roles")
    _require(isinstance(roles, dict) and all(role in roles for role in ROLES), "fixture_roles_missing")
    for role in ROLES:
        entry = roles[role]
        _require(isinstance(entry, dict) and type(entry.get("user_id")) is int,
                 "fixture_role_invalid")
        _require(isinstance(entry.get("email"), str) and entry["email"], "fixture_role_invalid")
        _require(isinstance(entry.get("token"), str) and entry["token"], "fixture_session_missing")
        _require(isinstance(entry.get("session_binding_sha256"), str), "fixture_session_binding_missing")
    client.roles = copy.deepcopy(roles)
    client.limit = 13
    client.deadline = time.monotonic() + 20.0

    order: list[str] = []
    client.identity("role-a")
    order.append("identity-a-before")
    client.identity("role-b")
    order.append("identity-b-before")
    marker_a = "cft-nosql-review-a-" + secrets.token_hex(16)
    marker_b = "cft-nosql-review-b-" + secrets.token_hex(16)
    scalar_marker = "cft-nosql-scalar-" + secrets.token_hex(16)
    anonymous_marker = "cft-nosql-anonymous-" + secrets.token_hex(16)
    operator_marker = "cft-nosql-operator-" + secrets.token_hex(16)

    # Both rows belong to B: the operator-shaped probe does not test cross-owner access.
    for label, marker in (("create-a", marker_a), ("create-b", marker_b)):
        order.append(label)
        status, _ = client.request("PUT", BASELINE_PATH,
            {"message": marker, "author": roles["role-b"]["email"]}, role="role-b",
            json_response=False)
        _require(status in {200, 201}, "review_create_failed")
    baseline_rows = _read(client, order, "baseline-read")
    row_a = _find_marker(baseline_rows, marker_a, roles["role-b"]["email"])
    row_b = _find_marker(baseline_rows, marker_b, roles["role-b"]["email"])
    review_a_id, review_b_id = _review_id(row_a), _review_id(row_b)
    _require(review_a_id != review_b_id, "review_ids_not_distinct")
    baseline = _snapshot(baseline_rows)
    key_a = json.dumps(review_a_id, sort_keys=True, separators=(",", ":"))
    key_b = json.dumps(review_b_id, sort_keys=True, separators=(",", ":"))
    _require(key_a in baseline and key_b in baseline, "review_snapshot_missing")

    order.append("scalar-owner-write")
    scalar_status, _ = client.request("PATCH", UPDATE_PATH,
        {"id": review_a_id, "message": scalar_marker}, role="role-b", json_response=False)
    scalar_rows = _read(client, order, "scalar-owner-readback")
    scalar = _snapshot(scalar_rows)
    _require(key_a in scalar and key_b in scalar, "review_readback_missing")

    order.append("anonymous-write")
    anonymous_status, _ = client.request("PATCH", UPDATE_PATH,
        {"id": review_b_id, "message": anonymous_marker}, role=None, json_response=False)
    anonymous_rows = _read(client, order, "anonymous-readback")
    anonymous = _snapshot(anonymous_rows)
    _require(key_a in anonymous and key_b in anonymous, "review_readback_missing")

    # The selector is fixed to exactly these two fixture-generated scalar IDs.
    order.append("operator-write")
    operator_status, operator_result = client.request("PATCH", UPDATE_PATH,
        {"id": {"$in": [review_a_id, review_b_id]}, "message": operator_marker},
        role="role-b")
    operator_rows = _read(client, order, "operator-readback")
    operator = _snapshot(operator_rows)
    _require(key_a in operator and key_b in operator, "review_readback_missing")

    client.identity("role-a")
    order.append("identity-a-after")
    client.identity("role-b")
    order.append("identity-b-after")
    _require(order == ["identity-a-before", "identity-b-before", "create-a", "create-b",
        "baseline-read", "scalar-owner-write", "scalar-owner-readback", "anonymous-write",
        "anonymous-readback", "operator-write", "operator-readback", "identity-a-after",
        "identity-b-after"], "request_order_invalid")
    _require(getattr(client, "operation_exchanges", 13) == 13, "request_budget_invalid")

    def unrelated_digest(snapshot):
        return digest({key: value for key, value in snapshot.items() if key not in {key_a, key_b}})

    operator_count = operator_result.get("modified") if isinstance(operator_result, dict) else None
    _require(type(operator_count) is int and 0 <= operator_count <= 2,
             "operator_result_shape_invalid")
    scalar_probe = scalar[key_a]
    scalar_other = scalar[key_b]
    anonymous_probe = anonymous[key_b]
    operator_a = operator[key_a]
    operator_b = operator[key_b]
    scalar_control = (scalar_status in {200, 204}
        and scalar_probe.get("message") == scalar_marker
        and scalar_other.get("message") == marker_b)
    anonymous_control = (anonymous_status in {401, 403}
        and anonymous_probe.get("message") == marker_b)
    unrelated_unchanged = all(unrelated_digest(snapshot) == unrelated_digest(baseline)
        for snapshot in (scalar, anonymous, operator))
    owner = roles["role-b"]
    owner_digest = digest([owner["user_id"], owner["email"]])
    controls = {
        "identities_verified": True,
        "same_owner_fixture": row_a.get("author") == row_b.get("author") == owner["email"],
        "owners_and_nonmessage_preserved": all(
            snapshot.keys() == baseline.keys()
            and all(_same_nonmessage(baseline[key], snapshot[key])
                    and snapshot[key].get("author") == owner["email"] for key in (key_a, key_b))
            for snapshot in (scalar, anonymous, operator)),
        "scalar_control": scalar_control,
        "anonymous_control": anonymous_control,
        "unrelated_records_unchanged": unrelated_unchanged,
        "operator_scope_is_two_fixture_ids": key_a != key_b and operator_count <= 2,
    }
    trial = {
        "schema_version": NOSQL_SCHEMA_VERSION,
        "generation_sha256": digest(config["generation"]),
        "source_snapshot_digest": config["source_snapshot"],
        "fixture_snapshot_digest": config["source_snapshot"],
        "binding_snapshot_digest": config["binding_snapshot_digest"],
        "profile_sha256": digest(config["profile"]),
        "identity_a_sha256": digest([roles["role-a"]["user_id"], roles["role-a"]["email"]]),
        "identity_b_sha256": owner_digest,
        "session_a_sha256": roles["role-a"]["session_binding_sha256"],
        "session_b_sha256": roles["role-b"]["session_binding_sha256"],
        "owner_identity_sha256": owner_digest,
        "review_a_sha256": digest([1, review_a_id]),
        "review_b_sha256": digest([1, review_b_id]),
        "unrelated_baseline_sha256": unrelated_digest(baseline),
        "unrelated_after_scalar_sha256": unrelated_digest(scalar),
        "unrelated_after_anonymous_sha256": unrelated_digest(anonymous),
        "unrelated_after_operator_sha256": unrelated_digest(operator),
        "initial_a_sha256": digest(marker_a),
        "initial_b_sha256": digest(marker_b),
        "scalar_marker_sha256": digest(scalar_marker),
        "scalar_a_readback_sha256": digest(scalar_probe.get("message")),
        "scalar_b_readback_sha256": digest(scalar_other.get("message")),
        "anonymous_marker_sha256": digest(anonymous_marker),
        "anonymous_b_readback_sha256": digest(anonymous_probe.get("message")),
        "operator_marker_sha256": digest(operator_marker),
        "operator_a_readback_sha256": digest(operator_a.get("message")),
        "operator_b_readback_sha256": digest(operator_b.get("message")),
        "scalar_status": scalar_status,
        "anonymous_status": anonymous_status,
        "operator_status": operator_status,
        "operator_modified_count": operator_count,
        "controls": controls,
        "http_exchanges": 13,
        "request_order": order,
    }
    if all(controls.values()):
        return {"status": "completed", "trial": trial}
    return {"status": "inconclusive", "reason": "review_nosql_controls_failed", "trial": trial}


def _failure_code(error: BaseException) -> str:
    if isinstance(error, ReviewFixtureFailure):
        return str(error).split(":", 1)[0]
    return FAILURE


def execute(config: dict) -> dict:
    try:
        _require(config.get("active_check_id") in {CHECK_ID, NOSQL_CHECK_ID}, "wrong_active_check")
        saved = json.loads(STATE.read_text(encoding="utf-8"))
        client = FixtureClient(config)
        if config["active_check_id"] == NOSQL_CHECK_ID:
            return run_nosql_protocol(client, saved, config)
        return run_protocol(client, saved, config)
    except (ReviewFixtureFailure, OSError, ValueError, TypeError, KeyError, AttributeError,
            json.JSONDecodeError) as error:
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
    except (OSError, ValueError, TypeError, AttributeError, json.JSONDecodeError):
        result = {"status": "failed", "reason": FAILURE}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
