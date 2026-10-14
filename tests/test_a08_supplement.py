from pathlib import Path

import pytest

from scripts.a08_supplement import family_metrics, stage_accounting, supplement, truth


def row(**changes):
    return {"case_id": "test", "split": "development", "sample_kind": "original",
            "family": "sql-injection", "expected": "vulnerable", "detected": "True",
            "confirmation_supported": "True", "verification": "confirmed",
            "loss_stage": "confirmed_evidence", "scout_fully_read_anchors": "a.ts:1-2",
            **changes}


def test_denominators_and_safe_abstention_are_separate():
    metrics, = family_metrics([row(), row(case_id="second", detected="False",
                                           confirmation_supported="False", verification="not_detected"),
                              row(case_id="safe", expected="safe", detected="False",
                                  confirmation_supported="False", verification="not_detected")])
    assert metrics["confirmation_recall"] == 0.5
    assert metrics["precision"] == 1
    assert metrics["false_positive_rate"] == 0
    assert metrics["safe_decision_coverage"] == 0


def test_unexecuted_controls_and_empty_denominators_are_null():
    metric, = family_metrics([row(sample_kind="patched", expected="safe", detected="False",
                                  confirmation_supported="False", verification="not_detected")])
    assert metric["status"] == "not_executed"
    assert metric["precision"] is None
    assert metric["false_positive_rate"] is None


def test_unknown_causes_are_not_invented():
    stages, = stage_accounting([row(loss_stage="discovery_no_candidate_no_full_anchor_read",
                                    detected="False", confirmation_supported="False",
                                    scout_fully_read_anchors="")])
    assert stages["policy"] == stages["llm"] == stages["limits"] == "unknown"
    assert stages["binding"] == "no_case_match"
    assert stages["causal_attribution"] == "not_established"


def test_bad_boolean_is_not_silently_false():
    with pytest.raises(ValueError):
        truth("unknown")


def test_published_a08_reproduces_and_recovery_closes_seals(tmp_path):
    root = Path(__file__).resolve().parents[1]
    source = root / "artifacts/a08-final-2026-10-13-v3"
    handoff = root / "artifacts/a08-handoff-2026-10-13/artifacts"
    first = supplement(source, handoff, tmp_path / "first")
    second = supplement(source, handoff, tmp_path / "second")
    assert first == second
    assert first["status"] == "analysis_complete_with_measurement_limits"
    assert first["source_output_integrity"]["sealed_files"] == 29
    assert all(r["full_seal_verified"] for r in first["a06_integrity"].values())
    originals = [r for r in first["family_metrics"] if r["sample_kind"] == "original"]
    assert sum(r["positive_cases"] for r in originals) == 27
    assert sum(r["confirmed_positive"] for r in originals) == 3
    assert sum(first["stage_counts"]["policy"].values()) == 41
    with pytest.raises(ValueError, match="fresh"):
        supplement(source, handoff, tmp_path / "first")
