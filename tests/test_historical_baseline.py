import pytest

from evaluation.benchmark_protocol import ROOT, load_protocol
from evaluation.historical_baseline import historical_input


def test_historical_baseline_survives_b03_but_legacy_live_replay_refuses():
    assert load_protocol(baseline_mode="historical")
    with pytest.raises(ValueError, match="Frozen baseline input mismatch"):
        load_protocol(baseline_mode="live")


def test_unavailable_history_never_falls_back_to_live_bytes(tmp_path):
    with pytest.raises(ValueError, match="Frozen baseline input"):
        historical_input(tmp_path, "app/config.py")


def test_no_host_path_or_revision_injection():
    for path in ("../outside", "/etc/passwd", "app/../config.py"):
        with pytest.raises(ValueError, match="unsafe path"):
            historical_input(ROOT, path)


def test_modified_historical_input_fails_closed(monkeypatch):
    monkeypatch.setattr("evaluation.benchmark_protocol.historical_input",
                        lambda *_args: b"corrupted")
    with pytest.raises(ValueError, match="historical mismatch"):
        load_protocol()
