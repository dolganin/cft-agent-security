import importlib.util
import json
import sys
import types

from schemas.user_verification import UserFieldsTrial


def _digest(value):
    import hashlib

    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class FakeClient:
    def __init__(self, config):
        self.roles = {}
        self.calls = []
        self.operation_exchanges = 0
        self.private_value = "raw-private-value-xyz"
        self.identity_ok = True

    def identity(self, role):
        self.calls.append(("GET", "/rest/user/whoami?fields=id,email,role", role))
        self.operation_exchanges += 1
        if not self.identity_ok:
            raise RuntimeError("identity unavailable")
        return {"identity_verified": True}

    def request(self, method, path, role=None, **kwargs):
        assert method == "GET"
        self.calls.append((method, path, role))
        self.operation_exchanges += 1
        if path == "/rest/user/whoami" and role == "role-a":
            return 200, {"user": {"id": 10, "email": "a@example", "lastLoginIp": "127.0.0.1",
                                   "profileImage": "default.svg"}}
        if path.endswith("fields=id,email,role") and role == "role-a":
            return 200, {"user": {"id": 10, "email": "a@example", "role": "customer"}}
        if path.endswith("fields=id,email,password") and role == "role-a":
            user = {"id": 10, "email": "a@example"}
            if self.private_value is not None:
                user["password"] = self.private_value
            return 200, {"user": user}
        if path.endswith("fields=id,email,password") and role is None:
            return 200, {"user": {}}
        if path.endswith("fields=id,email,cft_fixture_unknown") and role == "role-a":
            return 200, {"user": {"id": 10, "email": "a@example"}}
        raise AssertionError((path, role))


def _load_worker(monkeypatch, tmp_path):
    fixture = types.ModuleType("fixture")
    fixture.FixtureClient = FakeClient
    fixture.STATE = tmp_path / "session.json"
    fixture.digest = _digest
    monkeypatch.setitem(sys.modules, "fixture", fixture)
    name = "user_fixture_worker_test_module"
    spec = importlib.util.spec_from_file_location(name, "executor/user_fixture_worker.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _config():
    return {"active_check_id": "juice-user-private-fields-v1", "generation": "g1",
            "source_snapshot": "a" * 64, "binding_snapshot_digest": "b" * 64,
            "profile": {"wall_time_seconds": 20}}


def _saved(worker):
    sentinel = _digest("raw-private-value-xyz")
    return {"generation": "g1", "roles": {
        "role-a": {"user_id": 10, "email": "a@example", "token": "token-a",
                    "session_binding_sha256": "c" * 64, "password_value_sha256": sentinel},
        "role-b": {"user_id": 11, "email": "b@example", "token": "token-b",
                    "session_binding_sha256": "d" * 64, "password_value_sha256": "e" * 64},
    }}


def test_safe_omission_is_completed_and_schema_valid(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    client = FakeClient(_config())
    client.private_value = None
    result = worker.run_protocol(client, _saved(worker), _config())
    assert result["status"] == "completed"
    trial = UserFieldsTrial.model_validate(result["trial"])
    assert trial.http_exchanges == 10
    assert trial.request_order == worker.USER_FIELDS_ORDER
    assert all(not probe.private_present for probe in trial.private_probes)


def test_matching_private_value_is_completed_but_redacted(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    result = worker.run_protocol(FakeClient(_config()), _saved(worker), _config())
    assert result["status"] == "completed"
    serialized = json.dumps(result)
    assert "a@example" not in serialized and "b@example" not in serialized
    assert "token-a" not in serialized and "token-b" not in serialized
    assert "raw-private-value-xyz" not in serialized
    assert result["trial"]["private_probes"][0]["private_value_sha"] == result["trial"]["expected_private_value_sha256"]


def test_wrong_private_value_is_inconclusive(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    client = FakeClient(_config())
    client.private_value = "wrong-private-value"
    result = worker.run_protocol(client, _saved(worker), _config())
    assert result["status"] == "inconclusive"


def test_identity_loss_is_inconclusive_without_raw_identity(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)

    class WrongIdentityClient(FakeClient):
        def request(self, method, path, role=None, **kwargs):
            result = super().request(method, path, role=role, **kwargs)
            if path == "/rest/user/whoami" and role == "role-a":
                return 200, {"user": {"id": 999, "email": "wrong@example", "lastLoginIp": "x",
                                       "profileImage": "x"}}
            return result

    result = worker.run_protocol(WrongIdentityClient(_config()), _saved(worker), _config())
    assert result["status"] == "inconclusive"
    assert "wrong@example" not in json.dumps(result)


def test_exact_budget_and_generation_guard(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    client = FakeClient(_config())
    saved = _saved(worker)
    saved["generation"] = "old"
    try:
        worker.run_protocol(client, saved, _config())
    except worker.UserFixtureFailure as error:
        assert str(error) == "stale_fixture_generation"
    else:
        raise AssertionError("stale generation accepted")
    assert client.calls == []
