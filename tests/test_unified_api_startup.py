"""The public entrypoint must isolate the built-in preset from imported projects."""
import argparse
from threading import Event
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from api.app import create_app
from api.startup import build_default_service
from app import ci_pipeline, demo
from app.config import settings
from app.profile_pipeline import STORE_PROFILE, run_project_pipeline
from schemas.api import ImportedProjectFile, ImportProjectFilesRequest


@pytest.fixture
def api_config(tmp_path, monkeypatch):
    for field, value in {
        "api_database_path": tmp_path / "api.sqlite3",
        "api_artifact_root": tmp_path / "runs",
        "api_project_root": tmp_path / "projects",
        "api_target_profiles": "",
        "api_builtin_store_enabled": True,
    }.items():
        monkeypatch.setattr(settings, field, value)


@pytest.mark.parametrize("fails", [False, True])
def test_store_preset_is_restored_before_another_project(tmp_path, monkeypatch, fails):
    fields = ("scout_max_turns", "scout_max_candidates", "scout_wall_clock_seconds",
              "llm_reasoning_effort", "llm_max_output_tokens", "llm_timeout_seconds",
              "llm_routes", "policy_file")
    baseline = {field: getattr(settings, field) for field in fields}
    seen = []

    def store_runner(args):
        seen.append((settings.scout_max_turns, settings.scout_wall_clock_seconds))
        assert args.reasoning_prefetch_workers == 2
        assert args.coalesce_bound_scout
        assert settings.policy_file.name == "demo-order-store.yaml"
        if fails:
            raise RuntimeError("simulated pipeline failure")
        return 0

    def ordinary_runner(args):
        assert {field: getattr(settings, field) for field in fields} == baseline
        assert args.sast_config == "auto"
        assert not hasattr(args, "reasoning_prefetch_workers")
        return 1

    monkeypatch.setattr(demo, "run_ci_pipeline", store_runner)
    monkeypatch.setattr(ci_pipeline, "run_ci_pipeline", ordinary_runner)
    args = argparse.Namespace(profile=str(STORE_PROFILE), output_dir=str(tmp_path / "store"),
                              agent_mode="stub", max_iterations=1)
    if fails:
        with pytest.raises(RuntimeError, match="simulated"):
            run_project_pipeline(args)
    else:
        assert run_project_pipeline(args) == 0
    assert seen == [(1, 18.0)]
    # An upload may copy the exact profile contents and id, but not its trusted path.
    uploaded = tmp_path / "demo-order-store.yaml"
    uploaded.write_bytes(STORE_PROFILE.read_bytes())
    assert run_project_pipeline(argparse.Namespace(profile=uploaded, sast_config="auto")) == 1


def test_failed_store_artifact_creation_restores_settings(tmp_path):
    before = settings.model_dump()
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("occupied")
    with pytest.raises(FileExistsError):
        run_project_pipeline(argparse.Namespace(profile=STORE_PROFILE, output_dir=blocked,
                                              agent_mode="stub", max_iterations=1))
    assert settings.model_dump() == before


def test_default_api_registers_store_and_accepts_an_unrelated_project(api_config):
    import base64

    service, example = build_default_service()
    repository = example.repository
    try:
        assert repository.is_dir()
        assert [p.id for p in service.list_projects()] == ["demo-order-store"]
        assert service.registry.get("demo-order-store").profile_path == STORE_PROFILE
        project = service.import_project_files(ImportProjectFilesRequest(name="Another project", files=[
            ImportedProjectFile(path="app.py", content_base64=base64.b64encode(b"print('ok')\n").decode()),
            ImportedProjectFile(path="Dockerfile", content_base64=base64.b64encode(
                b"FROM python:3.12-alpine\nCOPY app.py /app.py\nEXPOSE 8000\nCMD [\"python\", \"/app.py\"]\n"
            ).decode()),
        ]))
        target = service.registry.get(project.id)
        assert target.profile_path != STORE_PROFILE
        assert target.profile.id.startswith("upload-")
        assert len(service.list_projects()) == 2
    finally:
        service.close()
        example.close()
    assert not repository.exists()


def test_api_serves_requests_during_store_startup_and_joins_cleanup(api_config, monkeypatch):
    from api import startup

    starting, cancelled, closed = Event(), Event(), Event()

    class PendingStore(startup.BuiltinStore):
        def start(self):
            starting.set()
            assert cancelled.wait(timeout=5)

        def cancel(self):
            cancelled.set()
            super().cancel()

        def close(self):
            super().close()
            closed.set()

    monkeypatch.setattr(startup, "BuiltinStore", PendingStore)
    with TestClient(create_app()) as client:
        assert starting.wait(timeout=2)
        assert client.get("/health").json() == {"status": "ok"}
        assert client.get("/examples/order-store/status").json()["status"] == "starting"
        assert len(client.get("/projects").json()) == 1
    assert cancelled.is_set() and closed.is_set()


def test_api_remains_available_when_preview_is_unavailable(api_config, monkeypatch):
    from app.demo_preview import OrderStorePreview

    def unavailable(self):
        self._status = "unavailable"

    monkeypatch.setattr(OrderStorePreview, "start", unavailable)
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/projects").json()[0]["id"] == "demo-order-store"


def test_store_can_be_disabled_without_a_static_target(api_config, monkeypatch):
    monkeypatch.setattr(settings, "api_builtin_store_enabled", False)
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/projects").json() == []
        assert client.get("/examples/order-store/status").json() == {"status": "disabled"}


def test_server_drains_sse_before_lifespan_cleanup(monkeypatch):
    import sys

    from api import app as app_module

    captured = {}
    monkeypatch.setattr(sys, "argv", ["cft-security-api"])
    monkeypatch.setattr(app_module, "create_app", lambda: "test-app")
    monkeypatch.setattr(app_module.uvicorn, "run", lambda app, **kwargs: captured.update(kwargs))
    app_module.main()
    assert captured["timeout_graceful_shutdown"] == 5


def test_cancelled_preview_start_still_cleans_partially_created_resources(monkeypatch):
    from app.demo_preview import OrderStorePreview
    from app.profile_pipeline import STORE_TEMPLATE
    from pipeline.cancellation import CancellationToken, cancellation_scope, check_cancelled

    preview = OrderStorePreview(STORE_TEMPLATE)
    token = CancellationToken()
    calls = []

    def compose(*args, **kwargs):
        calls.append(args[0])
        if args[0] == "up":
            token.cancel()
        check_cancelled()

    monkeypatch.setattr(preview, "_compose", compose)
    with cancellation_scope(token):
        preview.start()
    assert calls == ["up", "down"]
    assert not preview._started


def test_chat_uses_frozen_general_options_and_scoped_store_options(api_config, monkeypatch):
    from api import service as service_module

    captured = []

    class Client:
        def __init__(self, **kwargs):
            captured.append(kwargs)

        def complete_model(self, **kwargs):
            return SimpleNamespace(answer="Ответ")

    monkeypatch.setattr(service_module, "ProviderFailoverClient", Client)
    monkeypatch.setattr(settings, "llm_reasoning_effort", "high")
    monkeypatch.setattr(settings, "llm_max_output_tokens", 12000)
    service, example = build_default_service()
    try:
        # Simulate an in-flight compact store workflow changing process settings.
        monkeypatch.setattr(settings, "llm_reasoning_effort", "low")
        monkeypatch.setattr(settings, "llm_max_output_tokens", 4096)
        assert service.chat_answerer("Вопрос", {"run": {"target_id": "upload-123"}}) == "Ответ"
        assert service.chat_answerer("Вопрос", {"target_id": "demo-order-store"}) == "Ответ"
    finally:
        service.close()
        example.close()
    assert captured[0]["reasoning_effort"] == "high"
    assert captured[0]["max_output_tokens"] == 6000
    assert captured[1]["reasoning_effort"] == "low"
    assert captured[1]["max_output_tokens"] == 4096
