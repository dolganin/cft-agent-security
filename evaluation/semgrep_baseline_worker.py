"""Fixed Docker-only source stager. No target code is executed."""
import json
import os
import tarfile
from pathlib import Path, PurePosixPath


def run():
    if os.getenv("CFT_A06_CONTAINER") != "1" or not Path("/.dockerenv").exists():
        raise RuntimeError("A06 Semgrep worker is Docker-only")
    root = Path("/src")
    with tarfile.open("/input/source.tar", "r") as archive:
        members = archive.getmembers()
        if len(members) > 20000 or sum(m.size for m in members) > 512 * 1024 * 1024:
            raise ValueError("Source snapshot limit exceeded")
        for member in members:
            path = PurePosixPath(member.name)
            if (not member.isfile() or path.is_absolute() or ".." in path.parts
                    or ":" in member.name or "\\" in member.name):
                raise ValueError("Unsafe snapshot member")
            destination = root.joinpath(*path.parts)
            destination.parent.mkdir(parents=True, exist_ok=True)
            stream = archive.extractfile(member)
            if stream is None:
                raise ValueError("Missing snapshot member content")
            destination.write_bytes(stream.read())
            destination.chmod(0o444)
    print(json.dumps({"staged_files": len(members), "target_execution": False}))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
