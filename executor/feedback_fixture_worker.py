"""Fixed, redacted B05 feedback owner-assignment probe inside Docker only."""

from __future__ import annotations

import ast
import json
import os
import sys
import time
from pathlib import Path

from fixture import STATE, FixtureClient, digest, integer

CHECK_ID = "juice-feedback-owner-v1"
ORDER = [
    "identity-a-before", "identity-b-before", "captcha-owner", "owner-feedback-create",
    "owner-feedback-readback", "captcha-probe", "foreign-feedback-create",
    "post-probe-readback", "identity-a-after", "identity-b-after",
]
_OPS = {ast.Add: lambda a, b: a + b, ast.Sub: lambda a, b: a - b, ast.Mult: lambda a, b: a * b}


class FeedbackFixtureFailure(ValueError):
    """Internal fixed-code failure; only constant diagnostics may leave worker."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise FeedbackFixtureFailure(code)


def _captcha_answer(expression: object) -> str:
    _require(isinstance(expression, str) and len(expression) <= 32, "captcha_expression_invalid")
    try:
        node = ast.parse(expression, mode="eval").body
    except SyntaxError:
        raise FeedbackFixtureFailure("captcha_expression_invalid") from None

    def calculate(item):
        if isinstance(item, ast.Constant) and type(item.value) is int and 0 <= item.value <= 99:
            return item.value
        if isinstance(item, ast.BinOp) and type(item.op) in _OPS:
            return _OPS[type(item.op)](calculate(item.left), calculate(item.right))
        raise FeedbackFixtureFailure("captcha_expression_invalid")

    return str(calculate(node))


def _captcha_id(value: object) -> int:
    # Juice Shop's in-memory CAPTCHA counter starts at zero; resource IDs elsewhere
    # still use the shared strictly-positive integer validator.
    _require(type(value) is int and 0 <= value < 1_000_000_000, "captcha_id_invalid")
    return value


def _roles(saved: dict, config: dict) -> dict:
    roles = saved.get("roles")
    _require(config.get("active_check_id") == CHECK_ID, "wrong_active_check")
    _require(saved.get("generation") == config.get("generation"), "stale_fixture_generation")
    _require(isinstance(roles, dict) and {"role-a", "role-b"}.issubset(roles), "fixture_roles_missing")
    for role in ("role-a", "role-b"):
        entry = roles[role]
        _require(type(entry.get("user_id")) is int and isinstance(entry.get("email"), str),
                 "fixture_role_invalid")
        _require(isinstance(entry.get("token"), str) and entry["token"], "fixture_session_missing")
        _require(isinstance(entry.get("session_binding_sha256"), str), "fixture_session_binding_missing")
    return roles


def _get_captcha(client: FixtureClient, order: list[str], label: str) -> tuple[int, str]:
    order.append(label)
    status, payload = client.request("GET", "/rest/captcha")
    _require(status == 200 and isinstance(payload, dict), "captcha_unavailable")
    captcha_id = _captcha_id(payload.get("captchaId"))
    answer = _captcha_answer(payload.get("captcha"))
    return captcha_id, answer


def _created_id(payload: object) -> int:
    _require(isinstance(payload, dict), "feedback_response_invalid")
    data = payload.get("data")
    if isinstance(data, dict):
        return integer(data.get("id"))
    return integer(payload.get("id"))


def _read_feedback(client: FixtureClient, order: list[str], label: str, feedback_id: int,
                   role: str) -> tuple[int, dict]:
    order.append(label)
    status, payload = client.request("GET", f"/api/Feedbacks/{integer(feedback_id)}", role=role)
    _require(status == 200 and isinstance(payload, dict) and isinstance(payload.get("data"), dict),
             "feedback_readback_unavailable")
    return status, payload["data"]


def run_protocol(client: FixtureClient, saved: dict, config: dict) -> dict:
    roles = _roles(saved, config)
    client.roles = roles
    client.limit = 10
    client.deadline = time.monotonic() + 25.0
    order: list[str] = []

    client.identity("role-a")
    order.append("identity-a-before")
    client.identity("role-b")
    order.append("identity-b-before")

    owner_captcha_id, owner_answer = _get_captcha(client, order, "captcha-owner")
    control_comment = f"CFT-B05-feedback-control-{config['generation']}"
    control_hash = digest(control_comment)
    order.append("owner-feedback-create")
    owner_status, owner_response = client.request("POST", "/api/Feedbacks", {
        "UserId": roles["role-b"]["user_id"], "comment": control_comment, "rating": 4,
        "captchaId": owner_captcha_id, "captcha": owner_answer,
    }, role="role-b")
    _require(owner_status in {200, 201}, "owner_feedback_control_failed")
    control_id = _created_id(owner_response)
    owner_read_status, owner_row = _read_feedback(
        client, order, "owner-feedback-readback", control_id, "role-b")
    owner_matches = (integer(owner_row.get("UserId")) == roles["role-b"]["user_id"]
                     and owner_row.get("comment") == control_comment and owner_row.get("rating") == 4)
    _require(owner_matches, "owner_feedback_readback_mismatch")

    probe_captcha_id, probe_answer = _get_captcha(client, order, "captcha-probe")
    probe_comment = f"CFT-B05-feedback-probe-{config['generation']}"
    probe_hash = digest(probe_comment)
    order.append("foreign-feedback-create")
    probe_status, probe_response = client.request("POST", "/api/Feedbacks", {
        "UserId": roles["role-b"]["user_id"], "comment": probe_comment, "rating": 3,
        "captchaId": probe_captcha_id, "captcha": probe_answer,
    }, role="role-a", allow_error_response=True)
    probe_created = probe_status in {200, 201}
    owner_role = "absent"
    marker_matches = False
    unchanged_after_denial = None
    if probe_created:
        probe_id = _created_id(probe_response)
        probe_read_status, probe_row = _read_feedback(
            client, order, "post-probe-readback", probe_id, "role-b")
        observed_owner = probe_row.get("UserId")
        if observed_owner == roles["role-b"]["user_id"]:
            owner_role = "role-b"
        elif observed_owner == roles["role-a"]["user_id"]:
            owner_role = "role-a"
        elif type(observed_owner) is int:
            owner_role = "other"
        marker_matches = probe_row.get("comment") == probe_comment and probe_row.get("rating") == 3
    else:
        probe_read_status, control_after = _read_feedback(
            client, order, "post-probe-readback", control_id, "role-b")
        unchanged_after_denial = (
            integer(control_after.get("UserId")) == roles["role-b"]["user_id"]
            and control_after.get("comment") == control_comment
            and control_after.get("rating") == 4
        )
    client.identity("role-a")
    order.append("identity-a-after")
    client.identity("role-b")
    order.append("identity-b-after")
    _require(order == ORDER and client.operation_exchanges == 10, "feedback_request_schedule_invalid")

    trial = {
        "schema_version": "b05.feedback.trial.v1",
        "generation_sha256": digest(config["generation"]),
        "source_snapshot_digest": config["source_snapshot"],
        "fixture_snapshot_digest": config.get("fixture_snapshot_digest", config["source_snapshot"]),
        "binding_snapshot_digest": config["binding_snapshot_digest"],
        "profile_sha256": digest(config["profile"]),
        "identity_a_sha256": digest([roles["role-a"]["user_id"], roles["role-a"]["email"]]),
        "identity_b_sha256": digest([roles["role-b"]["user_id"], roles["role-b"]["email"]]),
        "session_a_sha256": roles["role-a"]["session_binding_sha256"],
        "session_b_sha256": roles["role-b"]["session_binding_sha256"],
        "control_marker_sha256": control_hash,
        "probe_marker_sha256": probe_hash,
        "captcha_control_passed": True,
        "owner_create_status": owner_status,
        "owner_readback_status": owner_read_status,
        "owner_readback_matches": owner_matches,
        "probe_status": probe_status,
        "probe_created": probe_created,
        "probe_readback_status": probe_read_status,
        "probe_owner_role": owner_role,
        "probe_comment_matches": marker_matches,
        "control_unchanged_after_denial": unchanged_after_denial,
        "request_order": list(ORDER),
        "http_exchanges": 10,
    }
    return {"status": "completed", "trial": trial}


def main() -> int:
    if os.getenv("CFT_B04_CONTAINER") != "1" or not Path("/.dockerenv").is_file():
        print(json.dumps({"status": "failed", "reason": "docker_only"}, separators=(",", ":")))
        return 1
    try:
        if len(sys.argv) != 1:
            result = {"status": "failed", "reason": "unsupported_cli"}
        else:
            config = json.loads(Path("/input/profile.json").read_text(encoding="utf-8"))
            saved = json.loads(STATE.read_text(encoding="utf-8"))
            client = FixtureClient(config)
            result = run_protocol(client, saved, config)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        reason = str(error) if isinstance(error, FeedbackFixtureFailure) else "fixture_technical_error"
        result = {"status": "failed", "reason": reason}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result.get("status") == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
