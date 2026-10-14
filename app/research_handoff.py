"""Package sealed R00-R03 outputs, source digests and reconstruction instructions."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
import zipfile
from hashlib import sha256
from pathlib import Path

from app.b09_package import package
from schemas.research import relative_file

ROOT = Path(__file__).resolve().parents[1]


def verify_seal(directory):
    seal = json.loads((directory / "seal.json").read_text())
    actual = {p.relative_to(directory).as_posix() for p in directory.rglob("*")
              if p.is_file() and p != directory / "seal.json"}
    if set(seal) != actual:
        raise ValueError("Result seal membership mismatch")
    for name, digest in seal.items():
        relative_file(name)
        path = directory / name
        if path.is_symlink() or sha256(path.read_bytes()).hexdigest() != digest:
            raise ValueError("Result seal digest mismatch")
        if re.search(rb"\bsk-[A-Za-z0-9_-]{16,}|\beyJ[\w-]+\.[\w-]+\.[\w-]+", path.read_bytes()):
            raise ValueError("Credential-shaped data in published result")
    return len(seal)


def handoff(directories: list[Path], output: Path, base_ref="40f6633", *,
            report="docs/research-foundation-report-2026-10-15.md",
            bundle_name="research-foundation-2026-10-15"):
    counts = {directory.name: verify_seal(directory) for directory in directories}
    with tempfile.TemporaryDirectory(prefix="cft-research-handoff-") as temporary:
        relative_file(bundle_name)
        relative_file(report)
        bundle = Path(temporary) / bundle_name
        bundle.mkdir()
        for directory in directories:
            shutil.copytree(directory, bundle / directory.name)
        shutil.copyfile(ROOT / report, bundle / "README.md")
        # Source snapshot is represented by hashes and Git refs, not environment/code copies.
        names = subprocess.check_output(["git", "diff", "--name-only", base_ref], cwd=ROOT,
                                        text=True).splitlines()
        names.extend(subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"],
                                             cwd=ROOT, text=True).splitlines())
        source_hashes = {name: sha256((ROOT / name).read_bytes()).hexdigest()
                         for name in names if not name.endswith(".pyc") and (ROOT / name).is_file()
                         and (name == "AGENTS.md" or name.split("/")[0] in {
                             "agent", "app", "docs", "executor", "evidence", "policies", "schemas",
                             "security", "tools", "validator", "tests", "pipeline", "reporting", "sast"})}
        (bundle / "source-provenance.json").write_text(json.dumps({
            "development_base_commit": subprocess.check_output(["git", "rev-parse", base_ref], cwd=ROOT, text=True).strip(),
            "implementation_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_files": source_hashes, "sealed_output_files": counts,
            "benchmark_measurement": False,
        }, indent=2) + "\n")
        result = package(bundle, [], output)
        with zipfile.ZipFile(output) as archive:
            manifest = json.loads(archive.read("MANIFEST-SHA256.json"))
        return {**result, "output_sets": counts, "manifest_files": len(manifest)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--base-ref", default="40f6633")
    parser.add_argument("--report", default="docs/research-foundation-report-2026-10-15.md")
    parser.add_argument("--bundle-name", default="research-foundation-2026-10-15")
    args = parser.parse_args()
    print(json.dumps(handoff([p.resolve() for p in args.results], args.output.resolve(), args.base_ref,
                            report=args.report, bundle_name=args.bundle_name), indent=2))


if __name__ == "__main__":
    main()
