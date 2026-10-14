import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.b03_acceptance import RecordingClient, snapshot
from schemas.discovery import ProjectDiscoveryResult
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


def test_producer_passes_cwd_and_keeps_both_modes_sealed(tmp_path, monkeypatch):
    from app import b03_acceptance as producer

    target = tmp_path / "target"
    target.mkdir()
    (target / "a.ts").write_text("query(req.query.q)\n")
    monkeypatch.setattr(producer, "snapshot", lambda _p: {
        "commit": producer.TARGET_COMMIT, "files": {"a.ts": "test-digest"}, "digest": "test",
    })
    monkeypatch.setattr(producer.ProjectDiscovery, "discover", lambda _s, _p:
                        ProjectDiscoveryResult(repository_root=target, project_files=["a.ts"]))

    def scanner(_command, *, cwd, timeout):
        assert cwd == target and timeout == 600
        assert "--network" in _command and "none" in _command
        return SimpleNamespace(returncode=0, stdout='{"results":[],"errors":[]}')

    class Client:
        def __init__(self):
            self.credentials = {}
        def complete_model(self, **_kwargs):
            return ScoutTurn()

    monkeypatch.setattr(producer, "run_cancellable_process", scanner)
    monkeypatch.setattr(producer.FallbackLLMAgentModel, "from_settings",
                        lambda _cfg: SimpleNamespace(client=Client()))
    output = tmp_path / "measurement"
    producer.run(target, output, "qwen3.8-flash-next", max_turns=1)
    assert (output / "seal.json").exists()
    assert (output / "handlers/summary.json").exists()
    assert (output / "round_robin/summary.json").exists()
