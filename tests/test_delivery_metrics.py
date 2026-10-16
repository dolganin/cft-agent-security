"""Delivery accounting must preserve denominators, abstentions and input boundaries."""
import json
import zipfile
from hashlib import sha256

import pytest

from app.delivery_metrics import aggregate_search, extract_run, verify_files


def split(positive, negative, confirmed, false, rejected, detected, detected_safe):
    counts = {"positive_cases": positive, "negative_cases": negative,
              "labeled_cases": positive + negative, "confirmed_cases": confirmed + false,
              "correct_confirmations": confirmed, "false_confirmations": false,
              "correct_rejections": rejected, "false_rejections": 0,
              "decided_cases": confirmed + false + rejected,
              "correct_decisions": confirmed + rejected,
              "outside_ground_truth": 100}
    detection = {"tp": detected, "fp": detected_safe, "fn": positive - detected,
                 "tn": negative - detected_safe}
    return {"verification": {"counts": counts}, "detection": detection,
            "sast_detection": detection}


def test_unequal_splits_are_pooled_without_excluding_abstentions_or_counting_outside():
    result = aggregate_search({"metrics": {
        "development": split(20, 2, 7, 0, 0, 20, 0),
        "holdout": split(7, 6, 6, 0, 0, 7, 1),
    }, "severity_accuracy": None, "context_priority_accuracy": None})
    assert result["confirmed_recall"] == {"numerator": 13, "denominator": 27, "value": 13 / 27}
    assert result["confirmed_precision"]["denominator"] == 13
    assert result["false_confirmation_rate"]["denominator"] == 8
    assert result["decided_safe_fpr"]["value"] is None
    assert result["decision_coverage"]["value"] == 13 / 35
    assert result["detection_precision"]["value"] == 27 / 28
    assert result["severity_accuracy"] is result["context_priority_accuracy"] is None


def test_false_confirmations_and_safe_rejections_remain_in_their_denominators():
    result = aggregate_search({"metrics": {"development": split(3, 4, 2, 1, 2, 3, 1)},
                               "severity_accuracy": None, "context_priority_accuracy": None})
    assert result["confirmed_precision"]["value"] == 2 / 3
    assert result["false_confirmation_rate"]["value"] == 1 / 4
    assert result["decided_safe_fpr"]["value"] == 1 / 3
    assert result["verdict_accuracy_on_decisions"]["value"] == 4 / 5


def test_sealed_projection_mutation_and_symlink_escape_rejected(tmp_path):
    directory = tmp_path / "projection"
    directory.mkdir()
    file = directory / "measurement.json"
    file.write_text(json.dumps({"mean": 1}))
    expected = {file.name: sha256(file.read_bytes()).hexdigest()}
    verify_files(directory, expected)
    file.write_text(json.dumps({"mean": 0}))
    with pytest.raises(ValueError, match="seal mismatch"):
        verify_files(directory, expected)
    link = directory / "outside.json"
    outside = tmp_path / "outside.json"
    outside.write_text("{}")
    link.symlink_to(outside)
    with pytest.raises(ValueError, match="seal mismatch"):
        verify_files(directory, {link.name: sha256(outside.read_bytes()).hexdigest()})


def test_archive_traversal_rejected_before_any_member_is_extracted(tmp_path):
    archive = tmp_path / "proof.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("valid.json", "{}")
        zipped.writestr("../escape.json", "{}")
    destination = tmp_path / "extracted"
    with pytest.raises(ValueError, match="Unsafe repair ZIP"):
        extract_run(archive, destination)
    assert not destination.exists()
    assert not (tmp_path / "escape.json").exists()
