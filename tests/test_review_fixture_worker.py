import importlib.util
import json
import sys
import types


def _digest(value):
    import hashlib

    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class FakeClient:
    def __init__(self, config):
        self.config = config
        self.roles = {}
        self.calls = []
        self.operation_exchanges = 0
        self.records = [
            {"_id": "existing", "product": "1", "message": "keep", "author": "other@example"},
        ]
        self.next_id = 101

    def identity(self, role):
        self.calls.append(("GET", "/rest/user/whoami?fields=id,email,role", role, None))
        self.operation_exchanges += 1
        entry = self.roles[role]
        return {"id": role, "server_user_id": entry["user_id"], "identity_verified": True}

    def request(self, method, path, data=None, role=None, *, json_response=True, raw_body=None):
        self.calls.append((method, path, role, data))
        self.operation_exchanges += 1
        if method == "PUT":
            self.records.append({"_id": str(self.next_id), "product": "1", "message": data["message"],
                                 "author": data["author"], "likesCount": 0})
            self.next_id += 1
            return 201, None
        if method == "GET":
            return 200, {"status": "success", "data": [dict(row) for row in self.records]}
        if method == "PATCH":
            if role == "role-b":
                selector = data["id"]
                if isinstance(selector, dict) and set(selector) == {"$in"}:
                    allowed_ids = selector["$in"]
                else:
                    allowed_ids = [selector]
                for row in self.records:
                    if row["_id"] in {str(value) for value in allowed_ids}:
                        row["message"] = data["message"]
                return 200, {"modified": len(allowed_ids)} if isinstance(selector, dict) else None
            return (401 if role is None else 403), None
        raise AssertionError(method)


def _load_worker(monkeypatch, tmp_path):
    fixture = types.ModuleType("fixture")
    fixture.FixtureClient = FakeClient
    fixture.STATE = tmp_path / "session.json"
    fixture.digest = _digest
    monkeypatch.setitem(sys.modules, "fixture", fixture)
    name = "review_fixture_worker_test_module"
    spec = importlib.util.spec_from_file_location(name, "executor/review_fixture_worker.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _config():
    return {"active_check_id": "juice-review-own-write-v1", "generation": "g1",
            "source_snapshot": "source-digest", "binding_snapshot_digest": "binding-digest",
            "profile": {"wall_time_seconds": 20}}


def _saved():
    return {"generation": "g1", "roles": {
        "role-a": {"user_id": 10, "email": "a@example", "token": "token-a", "session_binding_sha256": "sa"},
        "role-b": {"user_id": 11, "email": "b@example", "token": "token-b", "session_binding_sha256": "sb"},
    }}


def _nosql_config():
    return {**_config(), "active_check_id": "juice-review-nosql-selector-v1"}


def test_protocol_uses_exact_thirteen_calls_and_exports_no_credentials(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    client = FakeClient(_config())
    result = worker.run_protocol(client, _saved(), _config())

    assert result["status"] == "completed"
    trial = result["trial"]
    assert trial["http_exchanges"] == 13
    assert trial["request_order"] == worker.REQUEST_ORDER
    assert trial["controls"] == {
        "identities_verified": True, "owned_records_distinct": True,
        "owners_preserved": True, "unrelated_records_unchanged": True,
    }
    serialized = json.dumps(result)
    for secret in ("token-a", "token-b", "a@example", "b@example"):
        assert secret not in serialized
    assert len(client.calls) == 13
    assert all(call[1] in {worker.BASELINE_PATH, worker.UPDATE_PATH,
                           "/rest/user/whoami?fields=id,email,role"} for call in client.calls)
    assert all(not isinstance(call[3].get("id"), (dict, list))
               for call in client.calls if call[0] == "PATCH")


def test_cross_owner_scalar_update_requires_and_records_persistent_readback(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)

    class VulnerableClient(FakeClient):
        def request(self, method, path, data=None, role=None, **kwargs):
            if method == "PATCH" and role in {"role-a", "role-b"}:
                self.calls.append((method, path, role, data))
                self.operation_exchanges += 1
                for row in self.records:
                    if row["_id"] == str(data["id"]):
                        row["message"] = data["message"]
                return 200, None
            return super().request(method, path, data, role, **kwargs)

    client = VulnerableClient(_config())
    result = worker.run_protocol(client, _saved(), _config())
    assert result["status"] == "completed"
    trial = result["trial"]
    assert trial["probe_status"] == 200
    assert trial["probe_readback_sha256"] == trial["probe_marker_sha256"]
    assert trial["controls"]["owners_preserved"] is True
    assert trial["controls"]["unrelated_records_unchanged"] is True


def test_anonymous_and_cross_write_controls_are_inconclusive(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)

    class UnsafeClient(FakeClient):
        def request(self, method, path, data=None, role=None, **kwargs):
            if method == "PATCH" and role is None:
                for row in self.records:
                    if row["_id"] == str(data["id"]):
                        row["message"] = data["message"]
                self.calls.append((method, path, role, data))
                self.operation_exchanges += 1
                return 200, None
            return super().request(method, path, data, role, **kwargs)

    client = UnsafeClient(_config())
    result = worker.run_protocol(client, _saved(), _config())
    assert result["status"] == "inconclusive"


def test_nosql_probe_uses_only_the_two_generated_same_owner_ids(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    config = _nosql_config()
    client = FakeClient(config)
    result = worker.run_nosql_protocol(client, _saved(), config)

    assert result["status"] == "completed"
    trial = result["trial"]
    assert trial["schema_version"] == "review.nosql.trial.v1"
    assert trial["operator_modified_count"] == 2
    assert trial["controls"]["same_owner_fixture"] is True
    assert trial["controls"]["unrelated_records_unchanged"] is True
    probe = next(call for call in client.calls if call[0] == "PATCH" and isinstance(call[3]["id"], dict))
    assert set(probe[3]["id"]) == {"$in"}
    assert len(probe[3]["id"]["$in"]) == 2
    assert set(probe[3]["id"]["$in"]) == {"101", "102"}
    serialized = json.dumps(result)
    for secret in ("token-a", "token-b", "a@example", "b@example"):
        assert secret not in serialized
    assert all(value not in {"101", "102"}
               for key, value in trial.items() if key.endswith("_sha256"))


def test_stale_generation_fails_before_http(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)
    client = FakeClient(_config())
    saved = _saved()
    saved["generation"] = "old"
    try:
        worker.run_protocol(client, saved, _config())
    except worker.ReviewFixtureFailure as error:
        assert str(error) == "stale_fixture_generation"
    else:
        raise AssertionError("stale generation was accepted")
    assert client.calls == []


def test_nosql_owner_or_other_field_mutation_invalidates_controls(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)

    class CorruptOwnerClient(FakeClient):
        def request(self, method, path, data=None, role=None, **kwargs):
            result = super().request(method, path, data, role, **kwargs)
            if method == "PATCH" and isinstance(data["id"], dict):
                self.records[-1]["author"] = "unexpected@example"
            return result

    result = worker.run_nosql_protocol(CorruptOwnerClient(_nosql_config()), _saved(), _nosql_config())
    assert result["status"] == "inconclusive"
    assert result["trial"]["controls"]["owners_and_nonmessage_preserved"] is False


def test_nosql_operator_denial_keeps_working_scalar_controls(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)

    class ScalarOnlyClient(FakeClient):
        def request(self, method, path, data=None, role=None, **kwargs):
            if method == "PATCH" and isinstance(data["id"], dict):
                self.calls.append((method, path, role, data))
                self.operation_exchanges += 1
                return 400, {"modified": 0}
            return super().request(method, path, data, role, **kwargs)

    result = worker.run_nosql_protocol(ScalarOnlyClient(_nosql_config()), _saved(), _nosql_config())
    assert result["status"] == "completed"
    trial = result["trial"]
    assert all(trial["controls"].values())
    assert trial["operator_modified_count"] == 0
    assert trial["operator_a_readback_sha256"] == trial["scalar_marker_sha256"]
    assert trial["operator_b_readback_sha256"] == trial["initial_b_sha256"]


def test_lost_identity_fails_without_exporting_session_material(monkeypatch, tmp_path):
    worker = _load_worker(monkeypatch, tmp_path)

    class LostIdentityClient(FakeClient):
        def identity(self, role):
            if len([call for call in self.calls if call[0] == "GET" and "whoami" in call[1]]) == 2:
                raise worker.ReviewFixtureFailure("server_identity_missing_or_changed")
            return super().identity(role)

    client = LostIdentityClient(_config())
    try:
        worker.run_protocol(client, _saved(), _config())
    except worker.ReviewFixtureFailure as error:
        assert str(error) == "server_identity_missing_or_changed"
        result = {"status": "failed", "reason": worker._failure_code(error)}
    else:
        raise AssertionError("lost identity was accepted")
    assert "token-a" not in json.dumps(result)
