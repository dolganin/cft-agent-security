"""Freeze current implementation/configuration identity; never run a benchmark."""

import argparse
import hashlib
import json
import subprocess
from pathlib import Path

from app.config import settings
from evaluation.benchmark_protocol import ROOT, load_protocol


def manifest(config=settings):
    protocol = load_protocol()
    paths = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "--cached", "--others", "--exclude-standard"],
        capture_output=True, text=True, check=True, timeout=10,
    ).stdout.splitlines()
    components = {"agent", "app", "discovery", "evaluation", "executor", "schemas",
                  "scoring", "security", "tools", "validator", "scripts"}
    selected = sorted({p for p in paths if p.endswith(".py") and p.split("/")[0] in components})
    hashes = {p: hashlib.sha256((ROOT / p).read_bytes()).hexdigest() for p in selected}
    allowed = [*protocol.baseline.settings, "scout_schedule_mode"]
    config_values = {k: getattr(config, k) for k in allowed}
    commit = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    identity = {"implementation_sha256": hashes, "settings": config_values,
                "dataset_lock_sha256": hashlib.sha256(
                    (ROOT / "benchmarks/juice-shop-v20.2.0-v2/dataset.lock.json").read_bytes(),
                ).hexdigest(), "target_commit": protocol.target_commit}
    try:
        load_protocol(baseline_mode="live")
        compatible = True
    except ValueError:
        compatible = False
    return {"schema_version": "stage-b.measurement-manifest.v1",
            "status": "manifest_only_no_measurement", "checkout_commit": commit,
            **identity, "identity_sha256": hashlib.sha256(json.dumps(
                identity, sort_keys=True, separators=(",", ":"),
            ).encode()).hexdigest(), "legacy_live_baseline_compatible": compatible,
            "note": "Bind this identity to new run artifacts; historical A01 validation is not live acceptance"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = manifest()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print("Stage B identity saved; no scanner/model/target executed")


if __name__ == "__main__":
    main()
