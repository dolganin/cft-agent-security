"""Offline regression checks; never start the target or call a provider."""
import json
from types import SimpleNamespace

import pytest

from scripts import a07_series


def configuration():
    return {
        "agent": {
            "settings": {"llm_routes": "nsu:Qwen3.8-27B", "scout_max_turns": 2,
                         "llm_allow_external_fallbacks": False},
            "policy": "policies/default.yaml", "max_iterations": 2,
            "transport": {"provider": "nsu", "model": "Qwen3.8-27B"},
        },
        "project": {"commit": "a" * 40},
        "dataset": {"id": "test", "lock_sha256": "b" * 64},
        "matcher": {"sha256": "c" * 64},
        "target": {"image": "test@sha256:" + "d" * 64},
        "configuration_digest": "e" * 64,
    }


def test_frozen_settings_override_inherited_environment(monkeypatch):
    monkeypatch.setenv("CFT_LLM_ROUTES", "nsu:wrong-model")
    monkeypatch.setenv("CFT_SCOUT_MAX_TURNS", "8")
    monkeypatch.setenv("NSU_OPENWEBUI_KEY", "disposable-test-placeholder")
    env = a07_series.producer_environment(configuration())
    assert env["CFT_LLM_ROUTES"] == "nsu:Qwen3.8-27B"
    assert env["CFT_SCOUT_MAX_TURNS"] == "2"
    assert env["CFT_LLM_ALLOW_EXTERNAL_FALLBACKS"] == "false"
    assert env["NSU_OPENWEBUI_KEY"] == "disposable-test-placeholder"
    assert a07_series.os.environ["CFT_LLM_ROUTES"] == "nsu:wrong-model"


def test_actual_provider_statuses_are_counted():
    rows = [{"status": s} for s in ("ok", "request_failed", "auth_or_access",
                                   "schema_validation_failed", "timeout", "fallback")]
    assert a07_series.llm_statistics(rows) == {
        "llm_request_count": 5, "llm_success_count": 1, "llm_failure_count": 4,
        "timeout_count": 1, "fallback_count": 1,
    }


def test_run_passes_frozen_environment_and_preserves_retry(monkeypatch, tmp_path):
    monkeypatch.setattr(a07_series, "ARTIFACTS", tmp_path)
    monkeypatch.setattr(a07_series, "verify_freeze", configuration)
    calls = []

    def fake_command(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=2, stdout="", stderr="")

    monkeypatch.setattr(a07_series, "command", fake_command)
    result = a07_series.run_one("agent-run-02-retry-01")
    argv, kwargs = calls[0]
    assert kwargs["env"]["CFT_LLM_ROUTES"] == "nsu:Qwen3.8-27B"
    assert argv[argv.index("--max-iterations") + 1] == "2"
    manifest = json.loads((tmp_path / result["run_id"] / "manifest.json").read_text())
    assert manifest["retry_of"] == "agent-run-02"
    assert result["status"] == "technically_invalid"
    assert result["seal_valid"]


@pytest.mark.parametrize("remaining,dirty,expected", [
    ("", "", "completed"),
    ("leftover-container", "", "technically_invalid"),
    ("", " M target.ts", "technically_invalid"),
])
def test_completed_status_requires_cleanup_and_integrity(monkeypatch, tmp_path, remaining, dirty, expected):
    monkeypatch.setattr(a07_series, "ARTIFACTS", tmp_path)
    monkeypatch.setattr(a07_series, "verify_freeze", configuration)

    def fake_command(argv, **kwargs):
        if "app.ci_pipeline" in argv:
            pipeline = tmp_path / "agent-run-03" / "pipeline"
            (pipeline / "audit").mkdir(parents=True)
            (pipeline / "audit/llm-attempts.jsonl").write_text('{"status":"ok"}\n')
            (pipeline / "ci-summary.json").write_text(json.dumps({
                "status": "completed", "session_id": "test-session",
            }))
            (pipeline / "gate.json").write_text('{"technical_errors":[]}')
            return SimpleNamespace(returncode=1, stdout="", stderr="")
        return SimpleNamespace(returncode=0, stdout=remaining if argv[0] == "docker" else dirty, stderr="")

    monkeypatch.setattr(a07_series, "command", fake_command)
    assert a07_series.run_one("agent-run-03")["status"] == expected
