import json
from hashlib import sha256

import pytest

from app.research_score import observation, validate_seal
from schemas.finding import Finding


def test_sealed_input_mutation_is_rejected(tmp_path):
    source = tmp_path / "result.json"
    source.write_text('{"completed":true}')
    (tmp_path / "seal.json").write_text(json.dumps({"result.json": sha256(source.read_bytes()).hexdigest()}))
    assert validate_seal(tmp_path) == 1
    source.write_text('{"completed":false}')
    with pytest.raises(ValueError, match="seal mismatch"):
        validate_seal(tmp_path)


def test_seal_cannot_reference_outside_input(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    source = tmp_path / "outside.json"
    source.write_text("{}")
    (run / "seal.json").write_text(json.dumps({"../outside.json": sha256(source.read_bytes()).hexdigest()}))
    with pytest.raises(ValueError, match="seal mismatch"):
        validate_seal(run)


def test_source_confirmation_does_not_become_runtime_confirmation():
    finding = Finding(id="digest", source="model_scout", rule_id="weak-cryptography",
                      title="Weak hash", description="Source condition", file="lib/hash.ts", line_start=1)
    row = observation(finding, report={"status": "confirmed", "stop_reason": "terminal_evidence"})
    assert row.reported_verdict == "confirmed"
    assert row.verification == "inconclusive"
    assert row.evidence_backed is False
