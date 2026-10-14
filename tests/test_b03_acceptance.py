import subprocess
from pathlib import Path

import pytest

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.b03_acceptance import RecordingClient, snapshot
from schemas.scout import ScoutTurn


def test_provider_tokens_are_validated_and_no_full_usage_payload_is_retained(monkeypatch):
    monkeypatch.setattr("agent.llm._post_json", lambda *_a, **_k: {
        "choices": [{"message": {"content": '{"candidates":[]}'}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12,
                  "unknown_field": "private", "invalid": -1},
    })
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next"),
                                   credentials={"NSU_OPENWEBUI_KEY": "synthetic-test-value"})
    result = client.complete_model(output_model=ScoutTurn, system_prompt="test",
                                   user_payload={}, operation="test")
    assert not result.candidates
    assert client.last_usage == {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12}


def test_recording_client_cannot_execute_or_save_credentials(tmp_path):
    class Client:
        def complete_model(self, **_kwargs):
            return ScoutTurn()

    record = RecordingClient(Client(), tmp_path)
    payload = {k: [] for k in (
        "source_snippets", "previous_context", "search_results", "related_files", "route_inventory",
    )}
    record.complete_model(user_payload={**payload, "remaining_turns": 1,
                                        "remaining_candidate_budget": 32,
                                        "credentials": "must-not-be-published"})
    assert "must-not-be-published" not in (tmp_path / "turn-01-input.json").read_text()
    assert (tmp_path / "turn-01-output.json").exists()


def test_non_repository_target_fails_before_scanner(tmp_path):
    with pytest.raises(subprocess.CalledProcessError):
        snapshot(tmp_path)


def test_target_snapshot_is_pinned_read_only():
    target = Path("artifacts/benchmark-target/juice-shop").resolve()
    if not target.exists():
        pytest.skip("Operator pinned source checkout required")
    first = snapshot(target)
    assert first == snapshot(target)
