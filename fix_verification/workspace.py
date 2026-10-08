"""Bounded data-only snapshot and strict patch application; no target execution."""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
from pathlib import Path, PurePosixPath

from fix_verification.review import validate_review_diff, validate_sequelize_search_proposal
from schemas.fix import PatchReviewArtifact

IGNORED = {".git", ".venv", "node_modules", "build", "dist", "__pycache__"}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def tree_digest(manifest: dict) -> str:
    return digest(json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode())


def safe_file(root: Path, file: str) -> Path:
    path = PurePosixPath(file)
    if not file or path.is_absolute() or ".." in path.parts or "\\" in file or ":" in file:
        raise ValueError("Unsafe patch path")
    current = root
    for part in path.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Linked or reparse paths are not accepted")
    if not current.resolve().is_relative_to(root.resolve()) or not current.is_file():
        raise ValueError("Patch path escaped the snapshot")
    return current


def snapshot(root: Path, destination: Path | None = None) -> dict:
    manifest = {}
    total = 0
    for directory, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(name for name in dirs if name not in IGNORED)
        for name in dirs + sorted(files):
            if name in IGNORED:
                continue
            path = Path(directory) / name
            relative = path.relative_to(root).as_posix()
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Snapshot contains a linked or reparse path")
            if stat.S_ISDIR(info.st_mode):
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                raise ValueError("Snapshot contains a special or hardlinked file")
            if info.st_size > 32 * 1024 * 1024 or total + info.st_size > 512 * 1024 * 1024 or len(manifest) >= 30_000:
                raise ValueError("Snapshot exceeds the source budget")
            raw = path.read_bytes()
            total += len(raw)
            manifest[relative] = (digest(raw), stat.S_IMODE(info.st_mode))
            if destination is not None:
                copied = destination / relative
                copied.parent.mkdir(parents=True, exist_ok=True)
                copied.write_bytes(raw)
                copied.chmod(stat.S_IMODE(info.st_mode))
    return manifest


def original_commit(root: Path) -> str | None:
    if not (root / ".git").exists():
        return None
    result = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"],
                            capture_output=True, text=True, timeout=10, check=False)
    return result.stdout.strip() if result.returncode == 0 else None


def check_review(review: PatchReviewArtifact, root: Path, finding_id: str, run_id: str, file: str) -> str:
    if (review.status != "ready_for_review" or review.finding_id != finding_id
            or review.run_id != run_id or review.file != file
            or review.proposal.finding_id != finding_id):
        raise ValueError("Patch review does not match this completed finding/run")
    if digest(review.proposal.model_dump_json().encode()) != review.proposal_sha256:
        raise ValueError("Proposal digest changed after review")
    raw = safe_file(root, file).read_bytes()
    if digest(raw) != review.source_sha256:
        raise ValueError("Source digest changed after review")
    if review.editable_start is None or review.editable_end is None:
        raise ValueError("Patch review lacks an operator-owned editable window; review again")
    canonical = validate_review_diff(review.proposal, file=file, source=raw.decode("utf-8"),
                                    editable_start=review.editable_start, editable_end=review.editable_end)
    if canonical != review.proposal.unified_diff:
        raise ValueError("Only the canonical reviewed patch can be applied")
    if review.validation_policy == "sequelize_search_review_v1":
        validate_sequelize_search_proposal(canonical)
    elif review.validation_policy != "single_file_scope_v1":
        raise ValueError("Unknown patch review policy")
    return canonical


def apply_patch(root: Path, diff: str, file: str) -> str:
    before = snapshot(root)
    # git apply is a fixed data transformation. No hooks, scripts, shell or target code.
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_CEILING_DIRECTORIES=str(root.parent), GIT_TERMINAL_PROMPT="0")
    for check in (True, False):
        argv = ["git", "apply", "--no-index", "--whitespace=error"]
        if check:
            argv.append("--check")
        result = subprocess.run(argv + ["-"], input=diff.encode(), cwd=root, env=environment,
                                capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise ValueError("git apply check/application rejected the reviewed patch")
    after = snapshot(root)
    changed = {p for p in before.keys() | after.keys() if before.get(p) != after.get(p)}
    if before.keys() != after.keys() or changed != {file} or before[file][1] != after[file][1]:
        raise ValueError("Patch changed unauthorized files or modes")
    return digest(safe_file(root, file).read_bytes())
