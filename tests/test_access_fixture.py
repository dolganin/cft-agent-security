"""B04: credentials isolation, real identity/ownership semantics and safe lifecycle."""
import json
import subprocess
from copy import deepcopy
from types import SimpleNamespace

import pytest

from executor import access_fixture_worker as worker
from executor.access_fixture import AccessFixtureLab, digest
from schemas.access_fixture import AccessFixtureContext, AccessFixtureProfile
from schemas.target import TargetProfile


class FakeServer:
    def __init__(self):
        self.users = {}
        self.sessions = {}
        self.baskets = {}
        self.addresses = {}
        self.mode = None
        self.events = []

    def request(self, client, method, path, data, role):
        self.events.append((method, path, role))
        if client.exchanges >= client.limit:
            raise worker.FixtureFailure("fixture_budget_exhausted")
        client.exchanges += 1
        actor = self.sessions.get(client.roles[role]["token"]) if role else None
        if path == "/":
            if self.mode == "unavailable":
                raise worker.FixtureFailure("target_unavailable")
            return 200, None
        if path == "/api/Users":
            uid = 21 + len(self.users)
            self.users[data["email"]] = {"id": uid, "email": data["email"], "role": "customer",
                                          "password": data["password"], "bid": uid + 100}
            return 201, {"data": {"id": uid}}
        if path == "/rest/user/login":
            user = self.users[data["email"]]
            token = "private-test-session-" + str(user["id"])
            self.sessions[token] = user
            self.baskets[user["bid"]] = {"id": user["bid"], "UserId": user["id"], "Products": []}
            return 200, {"authentication": {"token": token, "umail": user["email"], "bid": user["bid"]}}
        if path.startswith("/rest/user/whoami"):
            if self.mode == "empty-identity":
                return 200, {"user": {}}
            if not actor:
                return 200, {"user": {}}
            value = {k: actor[k] for k in ("id", "email", "role")}
            if self.mode == "wrong-role":
                value["role"] = "admin"
            if self.mode == "lost-after-read" and any(e[1].startswith("/rest/basket/") for e in self.events):
                value = {}
            return 200, {"user": value}
        if path == "/api/BasketItems":
            basket = self.baskets[data["BasketId"]]
            basket["Products"] = [{"id": 1, "BasketItem": {"quantity": data["quantity"], "BasketId": basket["id"]}}]
            return 201, {"data": {"id": len(self.baskets)}}
        if path == "/api/Addresss":
            object_id = 1000 + len(self.addresses)
            self.addresses[object_id] = dict(data, id=object_id, UserId=actor["id"])
            return 201, {"data": {"id": object_id}}
        if path.startswith("/rest/basket/"):
            value = deepcopy(self.baskets[int(path.rsplit("/", 1)[1])])
            if self.mode == "wrong-owner":
                value["UserId"] = 999
            if self.mode == "wrong-marker":
                value["Products"][0]["BasketItem"]["quantity"] = 99
            return 200, {"data": value}
        if path.startswith("/api/Addresss/"):
            value = deepcopy(self.addresses[int(path.rsplit("/", 1)[1])])
            if actor and value["UserId"] == actor["id"]:
                if self.mode == "control-disappeared" and any(
                    e[1] == path and e[2] == "role-a" for e in self.events
                ):
                    return 400, {"status": "error", "data": "Malicious activity detected."}
                return 200, {"data": value}
            if self.mode == "denial-is-404":
                return 404, {"status": "error"}
            if self.mode == "negative-leaks":
                return 200, {"data": value}
            return 400, {"status": "error", "data": "Malicious activity detected."}
        pytest.fail("Unexpected operation: " + method + " " + path)


@pytest.fixture
def simulated(tmp_path, monkeypatch):
    server = FakeServer()
    original = worker.FixtureClient

    class Client(original):
        def request(self, method, path, data=None, role=None, **kwargs):
            return server.request(self, method, path, data, role)

    monkeypatch.setattr(worker, "FixtureClient", Client)
    monkeypatch.setattr(worker, "STATE", tmp_path / "private-state.json")
    profile = TargetProfile.from_yaml("targets/juice-access-fixture.yaml").access_fixture
    config = {"fixture_id": "test-fixture", "generation": "generation-1", "source_snapshot": "a" * 64,
              "profile": profile.model_dump(mode="json")}
    return config, server


def test_preparation_proves_two_server_identities_and_all_five_owners(simulated):
    config, server = simulated
    result = AccessFixtureContext.model_validate(worker.execute(config, "prepare"))
    assert result.status == "ready"
    assert len({r.server_user_id for r in result.roles}) == 2
    assert all(r.server_role == "customer" and r.identity_verified for r in result.roles)
    assert len(result.objects) == 5 and all(o.ownership_verified for o in result.objects)
    assert result.http_exchanges == 39
    text = result.model_dump_json()
    for user in server.users.values():
        assert user["password"] not in text and user["email"] not in text
    assert all(token not in text for token in server.sessions)
    assert not {"token", "password", "email", "url", "credentials"} & json.loads(text).keys()
    assert worker.STATE.exists()  # private container state, never an artifact contract


@pytest.mark.parametrize("operation", ["lost-session", "changed-identity"])
def test_http_200_without_expected_server_identity_is_inconclusive(simulated, operation):
    config, server = simulated
    assert worker.execute(config, "prepare")["status"] == "ready"
    event_count = len(server.events)
    result = AccessFixtureContext.model_validate(worker.execute(config, operation))
    assert result.status == "inconclusive" and "identity" in result.reason
    assert not any(r.identity_verified for r in result.roles)
    assert not any(o.ownership_verified for o in result.objects)
    assert not any("/basket/" in path for _, path, _ in server.events[event_count:])
    assert worker.execute(config, "control")["status"] == "ready"


@pytest.mark.parametrize("mode", ["empty-identity", "wrong-role", "wrong-owner", "wrong-marker",
                                 "denial-is-404", "negative-leaks", "control-disappeared", "unavailable",
                                 "lost-after-read"])
def test_failed_controls_never_become_safe_results(simulated, mode):
    config, server = simulated
    assert worker.execute(config, "prepare")["status"] == "ready"
    server.mode = mode
    result = worker.execute(config, "control")
    assert result["status"] == "inconclusive"
    assert any(not c["passed"] for c in result["controls"])


def test_unknown_operation_and_stale_generation_do_not_run_requests(simulated):
    config, server = simulated
    assert worker.execute(config, "prepare")["status"] == "ready"
    before = len(server.events)
    assert worker.execute(config, "arbitrary-write")["status"] == "inconclusive"
    config["generation"] = "other-generation"
    assert worker.execute(config, "control")["status"] == "inconclusive"
    assert len(server.events) == before


def test_profile_rejects_credentials_urls_incomplete_or_shared_permissions():
    profile = TargetProfile.from_yaml("targets/juice-access-fixture.yaml").access_fixture.model_dump()
    for key in ["credentials", "url", "password", "argv"]:
        with pytest.raises(ValueError):
            AccessFixtureProfile.model_validate(dict(profile, **{key: "arbitrary"}))
    broken = deepcopy(profile)
    broken["permissions"][1]["read"] = True
    with pytest.raises(ValueError):
        AccessFixtureProfile.model_validate(broken)
    broken = deepcopy(profile)
    broken["roles"] = ["role-a", "role-a"]
    with pytest.raises(ValueError):
        AccessFixtureProfile.model_validate(broken)


@pytest.mark.parametrize("mutation", ["unverified-role", "wrong-owner", "missing-control", "duplicate-object"])
def test_public_schema_rejects_fake_ready(simulated, mutation):
    config, _ = simulated
    result = worker.execute(config, "prepare")
    if mutation == "unverified-role":
        result["roles"][0]["identity_verified"] = False
    elif mutation == "wrong-owner":
        result["objects"][0]["server_owner_id"] = 999
    elif mutation == "missing-control":
        result["controls"] = [c for c in result["controls"] if c["id"] != "negative-control"]
    else:
        result["objects"][1]["server_object_id"] = result["objects"][0]["server_object_id"]
    with pytest.raises(ValueError):
        AccessFixtureContext.model_validate(result)


@pytest.fixture
def lab(tmp_path, monkeypatch):
    repository = tmp_path / "repo"
    repository.mkdir()
    instance = AccessFixtureLab(repository, tmp_path / "out")
    instance.generation = "unit-generation"
    instance.source_files = {"source": "a" * 64}
    instance.resources = {"worker": "unit-worker", "target": "unit-target", "network": "unit-net"}
    monkeypatch.setattr(instance, "_snapshot", lambda: dict(instance.source_files))
    return instance


def test_closed_and_old_generation_handles_never_call_docker(lab, monkeypatch):
    context = lab._inconclusive("fixture-not-ready").model_copy(update={"status": "ready", "generation": "old"})
    monkeypatch.setattr(lab, "_docker", lambda *a, **k: pytest.fail("Stale fixture must not execute"))
    assert lab.controls(context).status == "inconclusive"
    lab.resources = None
    context = context.model_copy(update={"generation": lab.generation})
    assert lab.controls(context).status == "inconclusive"
    with pytest.raises(ValueError):
        lab.controls(context, diagnostic="prepare")


def test_cleanup_is_limited_to_owned_resources_and_uses_volume_removal(lab, monkeypatch):
    calls = []

    def docker(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(lab, "_docker", docker)
    assert lab.close() is True and lab.resources is None
    assert ["rm", "-f", "-v", "unit-worker"] in calls
    assert ["rm", "-f", "-v", "unit-target"] in calls
    assert not any("prune" in args for args in calls)
    assert lab.records[-1]["original_unchanged"] is True


def test_unknown_cleanup_prevents_reset(lab, monkeypatch):
    monkeypatch.setattr(lab, "_docker", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("unavailable")))
    with pytest.raises(RuntimeError, match="cleanup"):
        lab.reset()
    assert lab.records[-1]["cleanup_complete"] is False
    assert lab.resources is not None


def test_malformed_worker_output_cannot_persist_credentials(lab, monkeypatch):
    private = "private-credential-never-persist"
    monkeypatch.setattr(lab, "_docker", lambda *a, **k: SimpleNamespace(
        stdout=json.dumps({"token": private}), returncode=0))
    context = lab._operation("control")
    assert context.status == "inconclusive"
    assert private not in (lab.output / "lifecycle.jsonl").read_text()


def test_worker_timeout_destroys_lab_and_returns_inconclusive(lab, monkeypatch):
    calls = []

    def docker(args, **kwargs):
        calls.append(args)
        if args[0] == "exec":
            raise subprocess.TimeoutExpired("docker", 1)
        return SimpleNamespace(stdout="", returncode=0)

    monkeypatch.setattr(lab, "_docker", docker)
    assert lab._operation("control").status == "inconclusive"
    assert lab.resources is None and any(args[0] == "rm" for args in calls)


def test_source_mutation_blocks_fixture_operation(lab, monkeypatch):
    monkeypatch.setattr(lab, "_snapshot", lambda: {"source": "changed"})
    monkeypatch.setattr(lab, "_docker", lambda args, **kwargs: (
        pytest.fail("Changed source must not execute") if args[0] == "exec"
        else SimpleNamespace(stdout="", returncode=0)))
    assert lab._operation("control").status == "inconclusive"


def test_controller_minimal_environment_excludes_provider_credentials(lab, monkeypatch):
    monkeypatch.setenv("NSU_API_KEY", "private-provider-key")
    monkeypatch.setenv("OPENAI_API_KEY", "private-openai-key")
    captured = {}

    def fake(argv, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(subprocess, "run", fake)
    lab._docker(["info"])
    assert "NSU_API_KEY" not in captured["env"] and "OPENAI_API_KEY" not in captured["env"]


def test_worker_is_docker_only(monkeypatch):
    monkeypatch.delenv("CFT_B04_CONTAINER", raising=False)
    with pytest.raises(RuntimeError, match="Docker-only"):
        worker.main()


def test_budgets_are_bounded_and_include_all_exchanges(simulated):
    config, _ = simulated
    assert worker.execute(config, "prepare")["http_exchanges"] == 39
    result = worker.execute(config, "control")
    assert result["http_exchanges"] == 25
    config["profile"]["control_http_budget"] = 2
    assert worker.execute(config, "control")["status"] == "inconclusive"


def test_public_profile_digest_matches_config(simulated):
    config, _ = simulated
    result = worker.execute(config, "prepare")
    assert result["profile_sha256"] == digest(config["profile"])


@pytest.mark.parametrize("mutation", ["identity", "owner", "bracket", "availability-after-denial"])
def test_observed_server_facts_cannot_be_replaced_by_ready_flags(simulated, mutation):
    config, _ = simulated
    result = worker.execute(config, "prepare")
    if mutation == "identity":
        next(o for o in result["observations"] if o["kind"] == "identity")["served_user_id"] = 999
    elif mutation == "owner":
        next(o for o in result["observations"] if o["kind"] == "owner-read")["served_owner_id"] = 999
    elif mutation == "bracket":
        own = next(o for o in result["observations"] if o["kind"] == "owner-read")
        result["observations"] = [o for o in result["observations"] if o["exchange"] != own["exchange"] + 1]
    else:
        negative = next(o for o in result["observations"] if o["kind"] == "negative-read")
        result["observations"] = [o for o in result["observations"] if not (
            o["kind"] == "owner-read" and o["object_id"] == "negative-control-b"
            and o["exchange"] > negative["exchange"])]
    with pytest.raises(ValueError):
        AccessFixtureContext.model_validate(result)


@pytest.mark.parametrize("mode", ["redirect", "oversized", "malformed", "not-json", "unavailable"])
def test_http_transport_errors_are_explicit_without_response_body_leaks(simulated, monkeypatch, mode):
    config, _ = simulated
    # Use the actual bounded transport, not the synthetic target implementation.
    client = worker.FixtureClient.__mro__[1](config)

    class Response:
        status = 302 if mode == "redirect" else 200

        def __init__(self):
            self.headers = {"Content-Type": "text/html" if mode == "not-json" else "application/json"}

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, count):
            if mode == "oversized":
                return b"x" * count
            return b"private-unparseable-body" if mode == "malformed" else b"{}"

    def open_response(*args, **kwargs):
        if mode == "unavailable":
            raise OSError("private-network-exception")
        return Response()

    monkeypatch.setattr(client.opener, "open", open_response)
    with pytest.raises(worker.FixtureFailure) as error:
        client.request("GET", "/rest/user/whoami")
    assert "private-" not in str(error.value)


def test_existing_output_is_never_overwritten(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    (output / "keep.txt").write_text("preserve")
    with pytest.raises(ValueError):
        AccessFixtureLab(repository, output)
    assert (output / "keep.txt").read_text() == "preserve"


def test_prepare_uses_private_tmpfs_and_internal_network_without_secrets_on_host(lab, monkeypatch):
    import executor.access_fixture as module
    calls = []
    lab.resources = None
    monkeypatch.setattr(module, "validate_target", lambda *a: None)

    def docker(args, **kwargs):
        calls.append(args)
        return SimpleNamespace(stdout="ready" if args[0] == "exec" else "", returncode=0)

    monkeypatch.setattr(lab, "_docker", docker)
    monkeypatch.setattr(lab, "_operation", lambda *a: lab._inconclusive("mock").model_copy(update={"status": "ready"}))
    assert lab.prepare().status == "ready"
    runs = [args for args in calls if args[0] == "run"]
    assert len(runs) == 2
    assert all("--pull=never" in args and "--cap-drop=ALL" in args for args in runs)
    worker_run = next(args for args in runs if "--read-only" in args)
    assert "--user=65532:65532" in worker_run
    assert any("/state:rw,noexec,nosuid" in arg and "mode=0700" in arg for arg in worker_run)
    assert any(args[:3] == ["network", "create", "--internal"] for args in calls)
    assert not any(any(arg in {"--privileged", "--network=host", "-p", "--publish"} for arg in args) for args in runs)
    assert not any("docker.sock" in arg or "password=" in arg for args in runs for arg in args)
    config = json.loads((lab.output / lab.generation / "profile.json").read_text())
    assert not {"password", "token", "credentials", "url"} & config.keys()


def test_operator_preparation_adapter_is_not_an_agent_capability():
    from executor.executor import CAPABILITY_NETWORK_ACCESS
    from schemas.action import ActionProposal
    from validator.validator import PolicyValidator
    assert "juice_access_v1" not in CAPABILITY_NETWORK_ACCESS
    profile = TargetProfile.from_yaml("targets/juice-access-fixture.yaml")
    action = ActionProposal(id="model-prepare", target=profile.id, tool="juice_access_v1",
                            environment="sandbox", purpose="Prepare", expected_evidence="users")
    assert not PolicyValidator.from_yaml("policies/default.yaml", target_profile=profile).validate(action).approved


@pytest.mark.parametrize("mutation", ["production", "external-url"])
def test_operator_profile_cannot_select_production_or_arbitrary_runtime(tmp_path, mutation):
    profile = TargetProfile.from_yaml("targets/juice-access-fixture.yaml").model_dump(mode="json")
    if mutation == "production":
        profile["environment"] = "production"
    else:
        profile["runtime"]["base_url"] = "https://external.invalid"
    file = tmp_path / "profile.json"
    file.write_text(json.dumps(profile))
    with pytest.raises(ValueError):
        AccessFixtureLab(tmp_path / "repo", tmp_path / "out", profile_file=file)
    assert not (tmp_path / "out").exists()
