import pytest

from app.b09_score import compare_previous, normalize_fixture_evidence


def test_fixture_normalization_preserves_bytes_and_is_idempotent(tmp_path):
    execution = tmp_path / "b06-runtime/3/execution"
    execution.mkdir(parents=True)
    record = execution / "execution-example.json"
    record.write_bytes(b'{"id":"example"}\n')
    (execution.parent / "audit.jsonl").write_text('{"event":"complete"}\n')
    first = normalize_fixture_evidence(tmp_path)
    assert (tmp_path / "evidence" / record.name).read_bytes() == record.read_bytes()
    assert first == normalize_fixture_evidence(tmp_path)
    assert (tmp_path / "audit/executor.jsonl").read_text() == '{"event":"complete"}\n'
    assert record.read_bytes() == b'{"id":"example"}\n'


def test_fixture_reference_collision_is_rejected(tmp_path):
    execution = tmp_path / "b06-runtime/3/execution"
    execution.mkdir(parents=True)
    (execution / "execution-example.json").write_text("original")
    (tmp_path / "evidence").mkdir()
    (tmp_path / "evidence/execution-example.json").write_text("different")
    with pytest.raises(ValueError, match="collision"):
        normalize_fixture_evidence(tmp_path)


def test_previous_metrics_require_verified_seal(tmp_path):
    previous = tmp_path / "previous"
    previous.mkdir()
    (previous / "seal.json").write_text('{"score.json":"bad"}')
    (previous / "score.json").write_text("changed")
    with pytest.raises(ValueError, match="seal mismatch"):
        compare_previous(tmp_path / "run", previous)
