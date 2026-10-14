"""Seal retained development diagnostics without changing any original result."""
import json
from hashlib import sha256
from pathlib import Path


def seal_diagnostics(directory):
    directory = Path(directory).resolve(strict=True)
    if (directory / "seal.json").exists():
        raise FileExistsError("Existing result seals are immutable")
    summary = directory / "development-attempt.json"
    with summary.open("x") as stream:
        json.dump({"kind":"development_diagnostics", "benchmark_measurement":False,
                   "acceptance_passed":False, "original_files_unchanged":True}, stream, indent=2)
    hashes = {p.relative_to(directory).as_posix():sha256(p.read_bytes()).hexdigest()
              for p in sorted(directory.rglob("*")) if p.is_file()}
    with (directory / "seal.json").open("x") as stream:
        json.dump(hashes, stream, indent=2)
    return len(hashes)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directories", type=Path, nargs="+")
    args = parser.parse_args()
    print(json.dumps({str(path):seal_diagnostics(path) for path in args.directories}, indent=2))
