import importlib.util
import json
import sys
import types

from schemas.feedback_verification import FeedbackOwnershipTrial


def _digest(value):
    import hashlib

    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class FakeClient:
    def __init__(self, config):
        self.roles = {}
        self.calls = []
        self.operation_exchanges = 0
        self.rows = {}
        self.next_id = 701
        self.deny_probe = False

    def identity(self, role):
        self.calls.append(("GET", "/rest/user/whoami?fields=id,email,role", role))
        self.operation_exchanges += 1
        expected = self.roles[role]
        return {"id": role, "server_user_id": expected["user_id"], "identity_verified": True}

    def request(self, method, path, data=None, role=None, **kwargs):
        self.calls.append((method, path, role, data))
        self.operation_exchanges += 1
        if path == "/rest/captcha":
            return 200, {"captchaId": self.operation_exchanges, "captcha": "2 * 3"}
        if method == "POST" and path == "/api/Feedbacks":
            if role == "role-a" and self.deny_probe:
                return 403, None
            row_id = self.next_id
            self.next_id += 1
            self.rows[row_id] = dict(data)
            return 201, {"data": {"id": row_id}}
        if method == "GET" and path.startswith("/api/Feedbacks/"):
            row_id = int(path.rsplit("/", 1)[1])
            return 200, {"data": self.rows[row_id]}
        raise AssertionError((method, path, role))


def _load_worker(monkeypatch, tmp_path):
    fixture = types.ModuleType("fixture")
    fixture.FixtureClient = FakeClient
    fixture.STATE = tmp_path / "session.json"
    fixture.digest = _digest
    fixture.integer = lambda value: value if type(value) is int and 0 < value < 1_000_000_000 else 0
    monkeypatch.setitem(sys.modules, "fixture", fixture)
    name = "feedback_fixture_worker_test_module"
    spec = importlib.util.spec_from_file_location(name, "executor/feedback_fixture_worker.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _config():
    return {"active_check_id": "juice-feedback-owner-v1", "generation": "generation-1",
            "source_snapshot": "a" * 64, "binding_snapshot_digest": "b" * 64,
            "profile": {"wall_time_seconds": 20}}


def _saved():
    return {"generation": "generation-1", "roles": {
        "role-a": {"user_id": 10, "email": "a@example.test", "token": "secret-token-a",
                   "session_binding_sha256": "c" * 64},
        "role-b": {"user_id": 11, "email": "b@example.test", "token": "secret-token-b",
                   "session_binding_sha256": "d" * 64},
    }}


def test_feedback_probe_is_redacted_and_schema_valid(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    client = FakeClient(_config())
    result = worker.run_protocol(client, _saved(), _config())

    assert result["status"] == "completed"
    trial = FeedbackOwnershipTrial.model_validate(result["trial"])
    assert trial.probe_created and trial.probe_owner_role == "role-b"
    assert trial.http_exchanges == len(client.calls) == 10
    serialized = json.dumps(result)
    for private in ("secret-token-a", "secret-token-b", "a@example.test", "b@example.test",
                    "CFT-B05-feedback-probe-generation-1", "CFT-B05-feedback-control-generation-1"):
        assert private not in serialized


def test_denied_foreign_feedback_checks_owner_control_stays_readable(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    client = FakeClient(_config())
    client.deny_probe = True
    result = worker.run_protocol(client, _saved(), _config())

    assert result["status"] == "completed"
    trial = FeedbackOwnershipTrial.model_validate(result["trial"])
    assert not trial.probe_created and trial.control_unchanged_after_denial is True
    assert trial.probe_status == 403 and trial.probe_readback_status == 200


def test_stale_generation_and_invalid_captcha_expression_fail_closed(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    config = _config()
    saved = _saved()
    saved["generation"] = "stale"
    client = FakeClient(config)
    try:
        worker.run_protocol(client, saved, config)
    except worker.FeedbackFixtureFailure as error:
        assert str(error) == "stale_fixture_generation"
    else:
        raise AssertionError("stale fixture was accepted")
    assert not client.calls

    assert worker._captcha_id(0) == 0
    try:
        worker._captcha_id(-1)
    except worker.FeedbackFixtureFailure as error:
        assert str(error) == "captcha_id_invalid"
    else:
        raise AssertionError("negative CAPTCHA identifier was accepted")

    try:
        worker._captcha_answer("__import__('os').system('id')")
    except worker.FeedbackFixtureFailure:
        pass
    else:
        raise AssertionError("non-arithmetic CAPTCHA expression was accepted")
