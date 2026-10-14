"""Read a fixed historical baseline without executing its code or changing locks."""

import subprocess
from functools import lru_cache
from pathlib import Path, PurePosixPath

BASELINE_REVISION = "b8132589b0c21483b335e1529f8b81250dfb9b59"


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
