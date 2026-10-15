"""Producer/evaluator separation, deterministic replay and tamper rejection."""
import json
from hashlib import sha256
from pathlib import Path

import pytest

from app.juice_source_scan import scan
from evaluation.juice_source_progress import evaluate

TARGET = Path(__file__).resolve().parents[1] / "artifacts/benchmark-target/juice-shop"


@pytest.mark.skipif(not TARGET.exists(), reason="Pinned Juice Shop source checkout required")
def test_source_scan_replays_offline_without_runtime_decisions(tmp_path):
    run = tmp_path / "scan"
    result = scan(TARGET, run)
    assert result["detector_findings"] > 0 and result["source_unchanged"]
    first = evaluate(run, tmp_path / "score-first")
    second = evaluate(run, tmp_path / "score-second")
    assert first == second
    assert first["runtime_confirmed"] is None and first["runtime_recall"] is None
    assert first["runtime_fpr"] is None
    assert first["views"]["source_detector"]["positive_denominator"] == 27
    manifest = json.loads((run / "manifest.json").read_text())
    assert "cases" not in manifest and "expected" not in manifest
    (run / "source-findings.json").write_text("[]\n")
    with pytest.raises(ValueError, match="digest mismatch"):
        evaluate(run, tmp_path / "tampered-score")


@pytest.mark.skipif(not TARGET.exists(), reason="Pinned Juice Shop source checkout required")
def test_source_evaluator_rejects_self_consistent_but_wrong_target_manifest(tmp_path):
    run = tmp_path / "scan"
    scan(TARGET, run)
    manifest_path = run / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["target"]["commit"] = "a" * 40
    manifest_path.write_text(json.dumps(manifest))
    seal_path = run / "seal.json"
    seal = json.loads(seal_path.read_text())
    seal["manifest.json"] = sha256(manifest_path.read_bytes()).hexdigest()
    seal_path.write_text(json.dumps(seal))
    with pytest.raises(ValueError, match="target or integrity"):
        evaluate(run, tmp_path / "wrong-target-score")
