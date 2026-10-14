from __future__ import annotations

import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

from scripts import b02_sast_development as b02

SAVED = b02.ROOT / "artifacts/b02-sast-development-2026-10-13-final"
COMMIT = "a" * 40
RUNS = ("a06_before", "b02_agent", "b02_baseline")


def digests(root: Path) -> dict[str, str]:
    return {p.relative_to(root).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def dataset_files(tmp_path, monkeypatch):
    relative = "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml"
    dataset = tmp_path / relative
    dataset.parent.mkdir(parents=True)
    value = {
        "schema_version": "benchmark.dataset.v2", "id": "unit-b02", "status": "frozen_a04",
        "target_commit": COMMIT, "cases": [{
            "id": "UNIT-ONE", "expected": "safe", "family": "path-traversal",
            "independence_group": "unit-one", "sample_kind": "original", "split": "development",
            "source_anchors": [{"file": "app.js", "line_start": 1, "line_end": 1}],
        }],
    }

    def write(status="frozen_a04"):
        value["status"] = status
        raw = json.dumps(value).encode()
        dataset.write_bytes(raw)
        dataset.with_name("dataset.lock.json").write_text(json.dumps({
            "input_sha256": {relative: hashlib.sha256(raw).hexdigest()},
        }))

    write()
    monkeypatch.setattr(b02, "ROOT", tmp_path)
    monkeypatch.setattr(b02, "DATASET", dataset)
    # The canonical freeze validator has its own integrity tests. These cases
    # exercise the bytes and semantics loaded after that preflight succeeds.
    monkeypatch.setattr(b02, "validate_frozen_dataset", lambda: None)
    return dataset, write


def test_dataset_rejects_changed_bytes_after_freeze_preflight(dataset_files):
    dataset, _ = dataset_files
    dataset.write_bytes(dataset.read_bytes() + b" ")
    with pytest.raises(ValueError, match="ground truth digest mismatch"):
        b02.development_dataset(COMMIT)


@pytest.mark.parametrize("status", ["draft", "synthetic"])
def test_dataset_never_promotes_unfrozen_status(dataset_files, status):
    _, write = dataset_files
    write(status)
    with pytest.raises(ValueError, match="frozen A04"):
        b02.development_dataset(COMMIT)


def test_dataset_must_match_scan_profile_target(dataset_files):
    with pytest.raises(ValueError, match="target commit"):
        b02.development_dataset("b" * 40)


def test_dataset_requires_canonical_freeze_validation(monkeypatch):
    def invalid_freeze():
        raise ValueError("Frozen input digest mismatch")

    monkeypatch.setattr(b02, "validate_frozen_dataset", invalid_freeze)
    with pytest.raises(ValueError, match="Frozen input digest mismatch"):
        b02.development_dataset(COMMIT)


def invoke(monkeypatch, target, output, inputs=None):
    args = ["b02", "--target", str(target), "--output", str(output)]
    if inputs is not None:
        args.extend(["--reuse-raw", str(inputs)])
    monkeypatch.setattr(sys, "argv", args)
    return b02.main()


@pytest.fixture
def offline_only(monkeypatch):
    manifest = json.loads((SAVED / "manifest.json").read_text())
    monkeypatch.setattr(b02, "validate_target_snapshot", lambda *_: manifest["target_snapshot"])

    def unexpected_scan(*_args, **_kwargs):
        pytest.fail("Offline rescoring must not execute Semgrep")

    monkeypatch.setattr(b02, "run_semgrep_scan", unexpected_scan)


@pytest.mark.parametrize("reuse", [False, True])
def test_existing_output_is_never_overwritten(tmp_path, monkeypatch, reuse):
    output = tmp_path / "existing"
    output.mkdir()
    (output / "manifest.json").write_text("original results")
    before = digests(output)
    with pytest.raises(SystemExit, match="new directory"):
        invoke(monkeypatch, tmp_path / "target", output, SAVED if reuse else None)
    assert digests(output) == before


def test_rescore_output_cannot_be_inside_saved_inputs(tmp_path, monkeypatch):
    inputs = tmp_path / "inputs"
    inputs.mkdir()
    output = inputs / "new"
    with pytest.raises(SystemExit, match="outside the saved input"):
        invoke(monkeypatch, tmp_path / "target", output, inputs)
    assert not output.exists()


def test_saved_rescore_preserves_inputs_and_reproduces_scores(tmp_path, monkeypatch, offline_only):
    before = digests(SAVED)
    for name in ("first", "second"):
        output = tmp_path / name
        assert invoke(monkeypatch, tmp_path / "target", output, SAVED) == 0
        for run in RUNS:
            assert (output / f"{run}-score.json").read_bytes() == (SAVED / f"{run}-score.json").read_bytes()
        assert digests(output / "raw") == digests(SAVED / "raw")
    assert digests(SAVED) == before


@pytest.mark.parametrize("filename", ["a06_before.json", "a06_before.stderr.txt"])
def test_rescore_rejects_tampered_raw_or_stderr(tmp_path, monkeypatch, offline_only, filename):
    inputs = tmp_path / "inputs"
    shutil.copytree(SAVED, inputs)
    path = inputs / "raw" / filename
    path.write_bytes(path.read_bytes() + b" ")
    before = digests(inputs)
    output = tmp_path / "new"
    with pytest.raises(SystemExit, match="digest mismatch"):
        invoke(monkeypatch, tmp_path / "target", output, inputs)
    assert digests(inputs) == before
    assert not (output / "report.md").exists()
