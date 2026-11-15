import json

import pytest
from pydantic import SecretStr

from app import demo_check
from app.config import settings
from app.setup import DEMO_ROUTES


def test_cli_keeps_canonical_pipeline_exit_code_and_disposable_target(tmp_path, monkeypatch):
    output = tmp_path / "result"
    captured = {}
    monkeypatch.setattr(settings, "llm_routes", "")
    monkeypatch.setattr(settings, "nsu_openwebui_key", SecretStr("not-a-real-key"))

    def pipeline(args):
        from pathlib import Path

        captured["target"] = Path(args.target)
        assert captured["target"].is_dir() and captured["target"] != demo_check.ORDER_TEMPLATE
        assert args.profile == str(demo_check.ORDER_PROFILE)
        assert settings.llm_routes == DEMO_ROUTES
        output.mkdir()
        (output / "gate.json").write_text(json.dumps({
            "decision": "fail", "confirmed": 4, "inconclusive": 0,
        }))
        return 1

    monkeypatch.setattr(demo_check, "run_demo_pipeline", pipeline)
    assert demo_check.main(["--output-dir", str(output)]) == 1
    assert not captured["target"].exists()
    assert settings.llm_routes == ""
    assert (output / "gate.json").is_file()


def test_cli_never_overwrites_saved_evidence(tmp_path):
    evidence = tmp_path / "gate.json"
    evidence.write_text("keep")
    with pytest.raises(SystemExit) as exc:
        demo_check.main(["--output-dir", str(tmp_path)])
    assert exc.value.code == 2 and evidence.read_text() == "keep"


def test_live_cli_requires_key_but_stub_is_explicit(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(settings, "nsu_openwebui_key", None)
    monkeypatch.setattr(settings, "llm_routes", "nsu:example")
    with pytest.raises(SystemExit) as exc:
        demo_check.main(["--output-dir", str(tmp_path / "live")])
    assert exc.value.code == 2
    original = settings.llm_routes

    def broken_pipeline(args):
        assert args.agent_mode == "stub"
        raise RuntimeError("test interruption")

    monkeypatch.setattr(demo_check, "run_demo_pipeline", broken_pipeline)
    with pytest.raises(RuntimeError, match="test interruption"):
        demo_check.main(["--agent-mode", "stub", "--output-dir", str(tmp_path / "stub")])
    assert settings.llm_routes == original
    assert "качество поиска не измеряется" in capsys.readouterr().out


def test_cli_uses_selected_provider_without_nsu_credentials(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "llm_routes", "mistral:selected-model")
    monkeypatch.setattr(type(settings), "llm_provider_credentials",
                        lambda self: {"MISTRAL_API_KEY": "fake"})

    def pipeline(args):
        assert settings.llm_routes == "mistral:selected-model"
        return 0

    monkeypatch.setattr(demo_check, "run_demo_pipeline", pipeline)
    assert demo_check.main(["--output-dir", str(tmp_path / "result")]) == 0
    assert settings.llm_routes == "mistral:selected-model"
