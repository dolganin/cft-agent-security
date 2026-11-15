"""First-run checks must fail early and preserve local credentials and isolation."""
import socket
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from app import demo_preview, setup

IMAGE = "python@sha256:" + "a" * 64


def test_image_update_preserves_key_and_other_settings(tmp_path):
    path = tmp_path / ".env"
    path.write_text("# local\nNSU_OPENWEBUI_KEY=not-a-real-key\nCFT_SANDBOX_IMAGE=\nCFT_LLM_ROUTES=custom\n")
    setup.env_image(path, IMAGE)
    assert path.read_text() == ("# local\nNSU_OPENWEBUI_KEY=not-a-real-key\n"
        f"CFT_SANDBOX_IMAGE={IMAGE}\nCFT_LLM_ROUTES=custom\n")
    with pytest.raises(setup.SetupError, match="SHA-256"):
        setup.env_image(path, "python:latest")


def test_unprepared_image_stops_before_any_demo_start(monkeypatch):
    monkeypatch.setattr(setup, "check_tools", lambda: None)
    config = SimpleNamespace(sandbox_image="", nsu_openwebui_key=SecretStr("fake"))
    with pytest.raises(setup.SetupError, match="prepare-demo"):
        setup.check_demo(config=config)


def test_duplicate_ports_fail_with_actionable_message():
    with pytest.raises(setup.SetupError, match="два разных порта"):
        setup.check_demo(config=None, port=8080, preview_port=8080)


def test_listening_port_is_still_rejected(monkeypatch):
    monkeypatch.setattr(setup, "check_tools", lambda: None)
    monkeypatch.setattr(setup, "command", lambda *a, **k: "image")
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        config = SimpleNamespace(sandbox_image=IMAGE, nsu_openwebui_key=SecretStr("fake"))
        with pytest.raises(setup.SetupError, match="занят"):
            setup.check_demo(config=config, port=port, preview_port=port + 1 if port < 65535 else port - 1)


def test_missing_model_key_is_not_silently_treated_as_live_analysis():
    with pytest.raises(setup.SetupError, match="NSU_OPENWEBUI_KEY"):
        setup.check_model(SimpleNamespace(nsu_openwebui_key=None))


def test_docker_failure_does_not_print_private_subprocess_output(monkeypatch):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k:
        subprocess.CompletedProcess(a[0], 1, "private-value", "private-value"))
    with pytest.raises(setup.SetupError) as exc:
        setup.command(["docker", "version"])
    assert "Docker Desktop" in str(exc.value) and "private-value" not in str(exc.value)


def test_operator_commands_do_not_inherit_exported_nsu_key(monkeypatch):
    captured = {}

    def run(argv, **kwargs):
        captured.update(kwargs["env"])
        return subprocess.CompletedProcess(argv, 0, "ready", "")

    monkeypatch.setenv("NSU_OPENWEBUI_KEY", "not-a-real-key")
    monkeypatch.setattr(subprocess, "run", run)
    setup.command(["docker", "version"])
    assert "NSU_OPENWEBUI_KEY" not in captured


def test_preview_projects_are_separate_and_port_stays_on_loopback(tmp_path, monkeypatch):
    folders = [tmp_path / "first", tmp_path / "second"]
    for folder in folders:
        folder.mkdir()
        (folder / "compose.yaml").write_text("services: {}")
    first = demo_preview.OrderStorePreview(folders[0], port=8091)
    second = demo_preview.OrderStorePreview(folders[1], port=8092)
    assert first.project_name != second.project_name
    assert first.preview_url == "http://127.0.0.1:8091"
    captured = {}

    def run(argv, **kwargs):
        captured.update(argv=argv, **kwargs)
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(demo_preview, "run_cancellable_process", run)
    first._compose("up", "--detach")
    assert captured["environment"]["CFT_DEMO_PREVIEW_PORT"] == "8091"
    assert first.project_name in captured["argv"]
    compose = Path("demo-target/order-store/compose.preview.yaml").read_text()
    assert "127.0.0.1:${CFT_DEMO_PREVIEW_PORT:-8090}:3000" in compose


def test_demo_cleanup_runs_in_api_lifespan_before_uvicorn_reraises_signal():
    from fastapi.testclient import TestClient

    from app.demo import create_demo_app

    events = []
    service = SimpleNamespace(close=lambda: events.append("service_closed"))
    app = create_demo_app(service, on_shutdown=lambda: events.append("preview_stopped"))
    with TestClient(app) as client:
        assert client.get("/health").status_code == 200
        assert events == []
    assert events == ["service_closed", "preview_stopped"]
