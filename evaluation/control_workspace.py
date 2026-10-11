"""Evaluator-only disposable data patches; reuse Stage 1's patch engine."""
from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from fix_verification.workspace import apply_patch, digest, safe_file, snapshot


@contextmanager
def patched_snapshot(source: Path, file: str, diff: str, source_sha256: str, patch_sha256: str):
    before = snapshot(source)
    if digest(safe_file(source, file).read_bytes()) != source_sha256 or digest(diff.encode()) != patch_sha256:
        raise ValueError("Source/patch digest mismatch")
    try:
        with TemporaryDirectory(prefix="cft-a03-") as directory:
            root = Path(directory) / "target"
            root.mkdir()
            snapshot(source, root)
            apply_patch(root, diff, file)
            yield root
    finally:
        if snapshot(source) != before:
            raise ValueError("Original target changed")
