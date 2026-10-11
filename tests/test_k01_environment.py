"""K01 immutable image pinning and environment passport checks.

These are unit checks over operator-owned resolution logic and the passport
document. They are not live runs and create no Docker resources.
"""

import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from app import stage1_e2e
from schemas.target import TargetFixConfig

REPO_DIGEST = "example.invalid/fix@sha256:" + "a" * 64
IMAGE_ID = "sha256:" + "b" * 64
ROOT = Path(__file__).resolve().parents[1]
PASSPORT = ROOT / "docs/k01-environment-passport.md"


def fake_inspect(record):
    def _command(argv):
        assert argv[:3] == ["docker", "image", "inspect"], argv
        assert "pull" not in argv
        if isinstance(record, Exception):
            raise record
        return json.dumps([record])

    return _command


def make_fix_config(image: str) -> TargetFixConfig:
    return TargetFixConfig(image=image, service="juice", source_commit="c" * 40)


def test_target_fix_config_accepts_valid_repository_digest() -> None:
    assert make_fix_config(REPO_DIGEST).image == REPO_DIGEST


def test_target_fix_config_accepts_valid_full_image_id() -> None:
    assert make_fix_config(IMAGE_ID).image == IMAGE_ID


@pytest.mark.parametrize(
    "image",
    [
        "cft-fix-juice:stage1",
        "python:3.12-alpine",
        "example.invalid/fix:latest",
        "example.invalid/fix@sha256:" + "a" * 63,
        "sha256:" + "b" * 63,
        "sha256:" + "b" * 65,
        "sha256:" + "B" * 64,
        "sha256:" + "z" * 64,
        "example.invalid/fix@sha256:short",
        "  ",
    ],
)
def test_target_fix_config_denies_mutable_or_malformed_reference(image: str) -> None:
    with pytest.raises(ValidationError, match="immutable"):
        make_fix_config(image)


def test_pinned_image_returns_an_already_pinned_digest_without_change(monkeypatch) -> None:
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect({"Id": IMAGE_ID, "RepoDigests": [REPO_DIGEST]}))
    assert stage1_e2e.pinned_image(REPO_DIGEST) == REPO_DIGEST


def test_pinned_image_confirms_a_full_image_id_against_actual_inspect(monkeypatch) -> None:
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect({"Id": IMAGE_ID, "RepoDigests": []}))
    assert stage1_e2e.pinned_image(IMAGE_ID) == IMAGE_ID


def test_pinned_image_rejects_an_image_id_that_inspect_does_not_confirm(monkeypatch) -> None:
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect({"Id": "sha256:" + "c" * 64, "RepoDigests": []}))
    with pytest.raises(ValueError, match="does not match"):
        stage1_e2e.pinned_image(IMAGE_ID)


def test_local_build_without_repo_digests_resolves_to_real_immutable_id(monkeypatch) -> None:
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect({"Id": IMAGE_ID, "RepoDigests": []}))
    assert stage1_e2e.pinned_image("cft-fix-juice:stage1") == IMAGE_ID


def test_local_build_prefers_reported_repo_digest_over_mutable_tag(monkeypatch) -> None:
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect({"Id": IMAGE_ID, "RepoDigests": [REPO_DIGEST]}))
    resolved = stage1_e2e.pinned_image("cft-fix-juice:stage1")
    assert resolved == REPO_DIGEST
    assert ":stage1" not in resolved


def test_pinned_image_refuses_reference_with_neither_digest_nor_image_id(monkeypatch) -> None:
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect({"Id": "image-id-without-sha256", "RepoDigests": []}))
    with pytest.raises(ValueError, match="immutable"):
        stage1_e2e.pinned_image("cft-fix-juice:stage1")


@pytest.mark.parametrize("record", [{"RepoDigests": []}, {"Id": None, "RepoDigests": []}])
def test_malformed_inspect_record_is_a_preflight_error_not_a_type_error(monkeypatch, record) -> None:
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect(record))
    with pytest.raises(ValueError, match="immutable"):
        stage1_e2e.pinned_image("cft-fix-juice:stage1")


def test_missing_image_raises_from_inspect_and_never_pulls(monkeypatch) -> None:
    calls = []

    def _command(argv):
        calls.append(argv)
        raise RuntimeError("Error: No such image: cft-fix-juice:stage1")

    monkeypatch.setattr(stage1_e2e, "_command", _command)
    with pytest.raises(RuntimeError, match="No such image"):
        stage1_e2e.pinned_image("cft-fix-juice:stage1")
    assert all("pull" not in argv and argv[:3] == ["docker", "image", "inspect"] for argv in calls)


@pytest.mark.parametrize("candidate", ["sha256:" + "b" * 63, "example.invalid/fix@sha256:zz"])
def test_malformed_immutable_reference_is_rejected_before_docker_is_called(monkeypatch, candidate: str) -> None:
    def _command(argv):  # pragma: no cover - must never run
        raise AssertionError("Docker must not be consulted for a malformed reference")

    monkeypatch.setattr(stage1_e2e, "_command", _command)
    with pytest.raises(ValueError):
        stage1_e2e.pinned_image(candidate)


def test_worker_image_still_requires_repository_digest_for_sandbox_policy(monkeypatch) -> None:
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect({"Id": IMAGE_ID, "RepoDigests": []}))
    with pytest.raises(ValueError, match="repository digest"):
        stage1_e2e.digest_pinned_worker_image("local-worker:build")
    monkeypatch.setattr(stage1_e2e, "_command", fake_inspect({"Id": IMAGE_ID, "RepoDigests": [REPO_DIGEST]}))
    assert stage1_e2e.digest_pinned_worker_image("local-worker:build") == REPO_DIGEST


def test_pinned_image_rejects_blank_and_multi_token_references() -> None:
    for candidate in ["", "   ", "img A", "img\nrm -rf /"]:
        with pytest.raises(ValueError, match="non-empty operator token"):
            stage1_e2e.pinned_image(candidate)


def test_environment_passport_exists_and_covers_verified_facts() -> None:
    text = PASSPORT.read_text(encoding="utf-8")
    lowered = text.lower()
    for anchor in (
        "macos",
        "arm64",
        "python",
        "docker",
        "semgrep",
        "node",
        "a6ca5db6a1a5aae3c27735c82d1ad41fdd68934e",
        "5658473cf8814459bf89000ce373b20ed0b4eb37",
        "sha256:",
        "preflight",
        "model probe",
        "prepare",
        "health",
        "reset",
        "stop",
        "leftover",
        "not verified",
    ):
        assert anchor in lowered, anchor
    assert "windows" in lowered
    assert not re.search(r"(?i)(api[_-]?key|token|secret)\s*[=:]\s*[A-Za-z0-9._~+/=-]{8,}", text)
