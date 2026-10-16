"""Pure C04 edit binding and isolated source-copy regressions; no live targets."""
import difflib
import os
import subprocess

import pytest
from pydantic import ValidationError

from fix_verification import repair_loop
from fix_verification.repair_replay import edit_operations
from fix_verification.review import validate_review_diff
from fix_verification.workspace import original_commit
from schemas.fix import ProposedPatch
from schemas.repair_loop import RepairLimits
from tools.repository_source import _safe_line

FILE = "routes/search.ts"


def test_original_commit_fails_closed_on_non_ascii_git_output(tmp_path, monkeypatch):
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(
        "fix_verification.workspace.subprocess.run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, stdout=b"\xff\n", stderr=b""),
    )

    assert original_commit(tmp_path) is None


def diff(before, after, *, context=3):
    return "".join(difflib.unified_diff(before.splitlines(True), after.splitlines(True),
        fromfile="a/" + FILE, tofile="b/" + FILE, n=context))


def test_model_n0_and_canonical_n3_have_identical_actual_edits():
    source = "// before\nconst unsafe = true\n// after\n"
    proposed = diff(source, source.replace("true", "false"), context=0)
    canonical = diff(source, source.replace("true", "false"), context=3)
    assert proposed != canonical
    assert edit_operations(proposed, FILE) == edit_operations(canonical, FILE)
    assert edit_operations(proposed, FILE) == [
        ("remove", 2, "const unsafe = true"), ("add", 3, "const unsafe = false")]


def test_c02_restored_annotation_comments_preserve_model_edit_binding():
    source = "// before\nconst unsafe = true // vuln-code-snippet vuln-line example\n// after\n"
    projected = "\n".join(_safe_line(line) for line in source.splitlines()) + "\n"
    response = diff(projected, projected.replace("true ", "false"), context=0)
    canonical = validate_review_diff(ProposedPatch(finding_id="unit", rationale="unit",
        unified_diff=response), file=FILE, source=source, editable_start=2, editable_end=2)
    assert "vuln-code-snippet" not in response
    assert "vuln-code-snippet" in canonical
    assert edit_operations(response, FILE) == edit_operations(canonical, FILE)


def test_optional_exact_git_diff_header_is_equivalent():
    patch = diff("old\n", "new\n")
    assert edit_operations("diff --git a/" + FILE + " b/" + FILE + "\n" + patch, FILE) == (
        edit_operations(patch, FILE))


@pytest.mark.parametrize("mutation", [
    lambda patch: patch.replace("--- a/" + FILE, "--- a/routes/other.ts"),
    lambda patch: patch + "diff --git a/other.ts b/other.ts\n--- a/other.ts\n+++ b/other.ts\n@@ -1 +1 @@\n-x\n+y\n",
    lambda patch: patch + "index abcdef..123456 100644\n",
    lambda patch: "index abcdef..123456 100644\n" + patch,
    lambda patch: patch.replace("@@ -1 +1 @@", "@@ -1,2 +1,1 @@"),
    lambda patch: patch.replace("@@ -1 +1 @@", "@@ -1,1 +1,2 @@"),
    lambda patch: patch.replace("@@ -1 +1 @@", "@@ -one +one @@"),
    lambda patch: patch + "@@ -4,2 +4,2 @@\n a\n",
    lambda patch: patch.replace("-old\n+new\n", " old\n"),
])
def test_edit_binding_rejects_extra_files_metadata_and_malformed_counts(mutation):
    with pytest.raises(ValueError):
        edit_operations(mutation(diff("old\n", "new\n")), FILE)


def test_changed_added_code_and_source_coordinates_cannot_match():
    original = diff("old\n", "new\n")
    assert edit_operations(original, FILE) != edit_operations(original.replace("+new", "+other"), FILE)
    assert edit_operations(original, FILE) != edit_operations(
        original.replace("@@ -1 +1 @@", "@@ -2 +2 @@"), FILE)


def test_fresh_copy_uses_clean_git_source_without_checkout_hooks(tmp_path, monkeypatch):
    source = tmp_path / "original"
    source.mkdir()

    def git(root, *args):
        return subprocess.run(["git", "-C", str(root), *args], check=True,
            capture_output=True, text=True, timeout=20).stdout.strip()

    git(source, "init")
    git(source, "config", "user.name", "C04 Unit")
    git(source, "config", "user.email", "c04-unit@example.invalid")
    git(source, "config", "core.autocrlf", "false")
    file = source / "source.ts"
    original = b"// data only; target code is never executed\nexport const value = 1\n"
    file.write_bytes(original)
    git(source, "add", "source.ts")
    git(source, "-c", "commit.gpgsign=false", "commit", "-m", "unit source")
    commit = git(source, "rev-parse", "HEAD")
    (source / ".git/info/exclude").write_text("/docker-compose.presentation.yml\n")
    (source / "docker-compose.presentation.yml").write_text("# operator data only\n")
    monkeypatch.setattr(repair_loop, "SOURCE_COMMIT", commit)
    expected = repair_loop.validate_target_snapshot(source, commit)
    destination = tmp_path / "first-copy"
    repair_loop.fresh_copy(source, destination, expected)
    assert repair_loop.validate_target_snapshot(destination, commit) == expected
    assert git(destination, "status", "--porcelain", "--untracked-files=all") == ""
    assert git(destination, "config", "--get", "core.hooksPath") == os.devnull
    assert git(destination, "config", "--get", "core.autocrlf") == "false"
    assert (destination / "docker-compose.presentation.yml").read_bytes() == (
        source / "docker-compose.presentation.yml").read_bytes()
    copied = destination / "source.ts"
    assert copied.read_bytes() == file.read_bytes() == original
    assert copied.stat().st_ino != file.stat().st_ino
    copied.write_bytes(b"// first attempt mutation\n")
    second = tmp_path / "second-copy"
    repair_loop.fresh_copy(source, second, expected)
    assert (second / "source.ts").read_bytes() == original
    assert file.read_bytes() == original
    assert repair_loop.validate_target_snapshot(source, commit) == expected


@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf"), 0, -1, 14401])
def test_repair_wall_limit_must_be_finite_positive_and_bounded(value):
    with pytest.raises(ValidationError):
        RepairLimits(wall_clock_seconds=value)


@pytest.mark.parametrize("value", [True, False, 0, -1, 6, 1.5, "3", None])
def test_attempt_limit_requires_bounded_strict_integer(value):
    with pytest.raises(ValidationError):
        RepairLimits(max_attempts=value)


def test_repair_limit_defaults_and_supported_boundary_values():
    assert RepairLimits().max_attempts == 3
    assert RepairLimits().wall_clock_seconds == 3600
    assert RepairLimits(max_attempts=1, wall_clock_seconds=1).max_attempts == 1
    assert RepairLimits(max_attempts=5, wall_clock_seconds=14400).wall_clock_seconds == 14400
