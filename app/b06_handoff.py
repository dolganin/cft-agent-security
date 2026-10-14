"""Build a portable B06 evidence archive with checksums and no environments."""
import argparse
import json
import zipfile
from hashlib import sha256
from pathlib import Path

from app.b06_replay import replay
from executor.access_fixture import ROOT


def package(acceptance, pipeline, summary, output):
    acceptance, pipeline, summary, output = (Path(p).resolve() for p in (acceptance, pipeline, summary, output))
    if output.exists():
        raise FileExistsError("Use a new handoff ZIP path")
    recomputed = replay(acceptance)
    if recomputed["status"] != "passed":
        raise ValueError("Only a verified B06 acceptance can be published")
    if any(json.loads((summary / name).read_text()) != recomputed for name in ("replay-one.json", "replay-two.json")):
        raise ValueError("Both offline replay files must match the acceptance")
    reports = [json.loads(p.read_text()) for p in (pipeline / "reports").glob("*.json")]
    if sorted(r["status"] for r in reports) != ["confirmed", "confirmed", "inconclusive"]:
        raise ValueError("Pipeline handoff needs the two verified claims and unsupported code report")
    files = {}
    for name, directory in (("acceptance", acceptance), ("pipeline", pipeline), ("summary", summary)):
        for p in directory.rglob("*"):
            if p.is_symlink():
                raise ValueError("Handoff cannot include symlinks")
            if p.is_file():
                relative = p.relative_to(directory)
                if any(part in {".env", ".venv", "node_modules", ".git", "__pycache__", "session.json"} for part in relative.parts):
                    raise ValueError("Handoff contains an excluded path")
                files[(Path(name) / relative).as_posix()] = p.read_bytes()
    for name in ("docs/b06-runtime-report-2026-10-14.md", "docs/b06-verification-specification.md",
                 "policies/b06.yaml", "targets/juice-b06-verification.yaml"):
        files[name] = (ROOT / name).read_bytes()
    membership = {name: sha256(data).hexdigest() for name, data in sorted(files.items())}
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in sorted(files.items()):
            archive.writestr(name, data)
        archive.writestr("MANIFEST-SHA256.json", json.dumps(membership, indent=2) + "\n")
        archive.writestr("README.md", "B06 handoff: auth/redirect runtime acceptance and code support gate.\n"
            "Extract to any directory. Verify MANIFEST-SHA256.json before review.\n"
            "In an up-to-date agent checkout: python -m app.b06_replay --input <extracted>/acceptance --output artifacts/b06-replay-new.json\n"
            "This package is capability acceptance, not a full Juice Shop discovery benchmark.\n")
    with zipfile.ZipFile(output) as archive:
        if archive.testzip() is not None:
            raise ValueError("Handoff ZIP failed integrity check")
        for name, expected in membership.items():
            if sha256(archive.read(name)).hexdigest() != expected:
                raise ValueError("Handoff ZIP manifest mismatch")
    checksum = sha256(output.read_bytes()).hexdigest()
    with output.with_suffix(output.suffix + ".sha256").open("x", encoding="utf-8") as stream:
        stream.write(checksum + "  " + output.name + "\n")
    return {"files": len(files), "bytes": output.stat().st_size, "sha256": checksum}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("acceptance", "pipeline", "summary", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(package(args.acceptance, args.pipeline, args.summary, args.output), indent=2))


if __name__ == "__main__":
    main()
