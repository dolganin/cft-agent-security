"""Portable, checksummed B09 results, including explicitly invalid attempts."""
from __future__ import annotations

import argparse
import json
import os
import zipfile
from hashlib import sha256
from pathlib import Path


def package(run: Path, attempts: list[Path], output: Path):
    if output.exists():
        raise FileExistsError("Choose a fresh archive path")
    files = {}
    for directory in [run, *attempts]:
        directory = directory.resolve(strict=True)
        for path in sorted(directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("Symlink in result archive")
            if not path.is_file():
                continue
            relative = path.relative_to(directory)
            if any(part in {".git", ".venv", "venv", "node_modules", "__pycache__", "session.json"}
                   or part == ".env" or part.startswith(".env.") for part in relative.parts):
                raise ValueError("Environment/private file in result archive")
            data = path.read_bytes()
            credential = os.environ.get("NSU_OPENWEBUI_KEY", "")
            if credential and credential.encode() in data:
                raise ValueError("Credential found in result artifact")
            files[(Path(directory.name) / relative).as_posix()] = data
    manifest = {name: sha256(data).hexdigest() for name, data in sorted(files.items())}
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
        archive.writestr("MANIFEST-SHA256.json", json.dumps(manifest, indent=2) + "\n")
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError("ZIP integrity failure")
        if set(archive.namelist()) != {*manifest, "MANIFEST-SHA256.json"}:
            raise ValueError("ZIP membership mismatch")
        for name, digest in manifest.items():
            if sha256(archive.read(name)).hexdigest() != digest:
                raise ValueError("ZIP checksum mismatch")
    digest = sha256(output.read_bytes()).hexdigest()
    output.with_suffix(output.suffix + ".sha256").write_text(digest + "  " + output.name + "\n")
    return {"files": len(files), "bytes": output.stat().st_size, "sha256": digest}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", type=Path, required=True)
    parser.add_argument("--attempt", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(args.run, args.attempt, args.output), indent=2))


if __name__ == "__main__":
    main()
