"""Read a fixed historical baseline without executing its code or changing locks."""

import re
import subprocess
from functools import lru_cache
from pathlib import Path, PurePosixPath

BASELINE_REVISION = "b8132589b0c21483b335e1529f8b81250dfb9b59"

_SCORING_PRESENTATION = frozenset({
    "docs/a04-benchmark-freeze.md",
    "benchmarks/juice-shop-v20.2.0-v2/rubric.yaml",
})


def frozen_presentation_input(root: Path, relative: str, current: bytes) -> bytes:
    """Allow only CVSS-version typography; every label and other byte stays frozen.

    The archived original is still checked against the existing lock. Live replay
    remains strict; current prose is never treated as old measured output.
    """
    if relative not in _SCORING_PRESENTATION:
        return current
    original = historical_input(root, relative)
    pattern = rb"(CVSS\s*)\d+(?:\.\d+)?"
    migrated = re.sub(pattern, lambda match: match[1] + b"3.1", original)
    if current in {original, migrated}:
        return original
    return current


@lru_cache(maxsize=512)
def historical_input(root: Path, relative: str) -> bytes:
    # Content-addressed fixed Git objects are immutable; working-tree inputs are
    # never cached and remain checked by the protocol/dataset validators.
    path = PurePosixPath(relative)
    if path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
        raise ValueError("Frozen baseline input has unsafe path")
    try:
        top = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--show-toplevel"],
            capture_output=True, check=True, timeout=10,
        ).stdout.decode().strip()
        if Path(top).resolve() != root.resolve():
            raise ValueError("Frozen baseline input requires repository root")
        return subprocess.run(
            ["git", "-C", str(root), "show", f"{BASELINE_REVISION}:{relative}"],
            capture_output=True, check=True, timeout=10,
        ).stdout
    except (subprocess.SubprocessError, OSError) as exc:
        raise ValueError("Frozen baseline input historical revision unavailable") from exc
