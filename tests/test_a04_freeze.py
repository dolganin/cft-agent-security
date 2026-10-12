"""A04 lock tampering, scope, split and read-only interface regression tests."""
import copy
import json

import pytest

from evaluation import benchmark_freeze as freeze
from evaluation.benchmark_protocol import load_protocol


def bundle():
    return tuple(freeze.read_yaml(freeze.DIRECTORY / name)
                 for name in ("ground_truth.yaml", "scope.yaml", "rubric.yaml"))


def test_checked_in_freeze_valid():
    result = freeze.validate()
    assert result["case_count"] == 41
    assert result["positive_count"] == 27
    assert result["negative_count"] == 14
    assert result["new_runtime_cycles"] == 0


def test_membership_and_slices():
    data, scope, rubric = bundle()
    freeze.validate_membership(data, scope, rubric, load_protocol())
    assert len(scope["default_original_detection_case_ids"]) == 35
    assert len(scope["default_original_runtime_case_ids"]) == 24
    assert sum(c["sample_kind"] == "synthetic" for c in data["cases"]) == 4
    assert sum(c["expected_severity"] is not None for c in data["cases"]) == 4
    assert all(c["expected_context_priority"] is None for c in data["cases"])


@pytest.mark.parametrize("mutation", ["duplicate", "split", "rubric", "scope", "empty_anchor"])
def test_semantic_mutations_fail_closed(mutation):
    data, scope, rubric = copy.deepcopy(bundle())
    if mutation == "duplicate":
        data["cases"].append(data["cases"][0])
    elif mutation == "split":
        data["cases"][0]["split"] = "holdout" if data["cases"][0]["split"] == "development" else "development"
    elif mutation == "rubric":
        rubric["cases"][0]["severity"] = "LOW"
    elif mutation == "scope":
        scope["default_original_runtime_case_ids"].clear()
    else:
        data["cases"][0]["source_anchors"].clear()
        data["cases"][0]["http_anchors"].clear()
    with pytest.raises(ValueError):
        freeze.validate_membership(data, scope, rubric, load_protocol())


def test_existing_freeze_cannot_be_overwritten(tmp_path):
    with pytest.raises(ValueError, match="Freeze exists"):
        freeze.render(tmp_path)


@pytest.mark.parametrize("relative", ["../secret", "/etc/passwd", "./schemas/benchmark.py"])
def test_input_path_rejected(relative):
    with pytest.raises(ValueError):
        freeze.safe_input(relative)


@pytest.mark.parametrize("mutation", ["digest", "drop_input", "add_input", "protocol"])
def test_lock_tampering_rejected(tmp_path, mutation):
    lock = json.loads((freeze.DIRECTORY / "dataset.lock.json").read_text())
    if mutation == "digest":
        lock["input_sha256"][next(iter(lock["input_sha256"]))] = "0" * 64
    elif mutation == "drop_input":
        del lock["input_sha256"][next(iter(lock["input_sha256"]))]
    elif mutation == "add_input":
        lock["input_sha256"]["../outside"] = "0" * 64
    else:
        lock["protocol_sha256"] = "0" * 64
    (tmp_path / "dataset.lock.json").write_text(json.dumps(lock))
    with pytest.raises(ValueError):
        freeze.validate(tmp_path)


def test_function_level_synthetic_anchors():
    data, _, _ = bundle()
    anchors = [c["source_anchors"][0] for c in data["cases"] if c["sample_kind"] == "synthetic"]
    assert len({(a["line_start"], a["line_end"]) for a in anchors}) == 4
    for a in anchors:
        assert a["line_end"] - a["line_start"] < 15


def test_ftp_case_and_patch_versions_are_narrow():
    data, scope, _ = bundle()
    ftp = next(c for c in data["cases"] if c["id"] == "JS-FILE-001")
    assert [a["endpoint"] for a in ftp["http_anchors"]] == ["/ftp"]
    assert ftp["source_anchors"][0]["line_end"] < 295
    for id_ in ("JS-SAFE-REDIRECT-101", "JS-SAFE-NOSQL-101"):
        c = next(c for c in data["cases"] if c["id"] == id_)
        assert c["source_anchors"][0]["line_end"] - c["source_anchors"][0]["line_start"] < 10
        assert next(c for c in scope["cases"] if c["id"] == id_)["anchor_version"] == "patched_application_source"
