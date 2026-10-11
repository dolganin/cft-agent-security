"""Synthetic operator provisioning tests; no target scripts or Docker runs."""

import json
from pathlib import Path

import pytest

from app import lab_prepare


def fake_clone(monkeypatch, *, commit=lab_prepare.COMMIT):
    calls = []

    def command(argv, **kwargs):
        calls.append(argv)
        if "clone" in argv:
            target = Path(argv[-1])
            (target / ".git/info").mkdir(parents=True)
            (target / "routes").mkdir()
            (target / "routes/search.ts").write_text("synthetic LF source\n")
        if "rev-parse" in argv:
            return commit
        return ""

    monkeypatch.setattr(lab_prepare, "command", command)
    return calls


def test_clone_excludes_only_operator_compose_and_preserves_lf(tmp_path, monkeypatch):
    calls = fake_clone(monkeypatch)
    compose = tmp_path / "compose.yaml"
    compose.write_text("services: {}\n")
    target = tmp_path / "target"
    result = lab_prepare.clone_target("synthetic-cache", target, compose=compose)
    assert result["commit"] == lab_prepare.COMMIT
    assert result["git_status"] == ""
    assert (target / lab_prepare.COMPOSE_NAME).read_bytes() == compose.read_bytes()
    assert (target / ".git/info/exclude").read_text() == "\n/docker-compose.presentation.yml\n"
    assert "--no-local" in calls[0] and "core.autocrlf=false" in calls[0]
    assert (target / "routes/search.ts").read_bytes().endswith(b"\n")
    with pytest.raises(FileExistsError):
        lab_prepare.clone_target("synthetic-cache", target, compose=compose)


def test_wrong_source_version_fails_without_copying_compose(tmp_path, monkeypatch):
    fake_clone(monkeypatch, commit="a" * 40)
    with pytest.raises(ValueError, match="commit mismatch"):
        lab_prepare.clone_target("synthetic-cache", tmp_path / "target", compose=tmp_path / "missing")
    assert not (tmp_path / "target" / lab_prepare.COMPOSE_NAME).exists()


def test_output_is_fresh_and_bounded_to_artifacts(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_prepare, "ROOT", tmp_path)
    with pytest.raises(ValueError, match="fresh child"):
        lab_prepare.prepare(tmp_path / "artifacts")
    with pytest.raises(ValueError, match="fresh child"):
        lab_prepare.prepare(tmp_path / "outside")
    output = tmp_path / "artifacts/previous"
    output.mkdir(parents=True)
    with pytest.raises(FileExistsError):
        lab_prepare.prepare(output)


def test_preparation_failure_is_saved_before_successful_clone(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_prepare, "ROOT", tmp_path)

    def fail(*args, **kwargs):
        raise RuntimeError("synthetic clone failed")

    monkeypatch.setattr(lab_prepare, "clone_target", fail)
    output = tmp_path / "artifacts/failed"
    with pytest.raises(RuntimeError):
        lab_prepare.prepare(output)
    manifest = json.loads((output / "preparation.json").read_text())
    assert manifest["status"] == "FAILED" and manifest["targets"] == {}
    assert manifest["started_at"] and manifest["finished_at"]


def test_ready_preparation_uses_separate_clones_and_never_pulls_implicitly(tmp_path, monkeypatch):
    monkeypatch.setattr(lab_prepare, "ROOT", tmp_path)
    seen = []
    monkeypatch.setattr(lab_prepare, "clone_target", lambda source, target, **kw: seen.append(target) or {"commit": lab_prepare.COMMIT})
    monkeypatch.setattr(lab_prepare, "digest_pinned_worker_image", lambda value: "worker@sha256:" + "b" * 64)
    monkeypatch.setattr(lab_prepare, "pinned_image", lambda value: "sha256:" + "a" * 64)
    monkeypatch.setattr(lab_prepare, "command", lambda *args, **kwargs: pytest.fail("No implicit provisioning"))
    output = tmp_path / "artifacts/ready"
    assert lab_prepare.prepare(output)["status"] == "READY"
    assert seen == [output / "analysis/juice-shop", output / "fix/juice-shop"]
