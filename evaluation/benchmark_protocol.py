"""A01 protocol preflight and deterministic split. No producer or scored run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import yaml

from schemas.benchmark import BenchmarkCaseV2, BenchmarkProtocolV2, SplitPolicy

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "benchmarks/juice-shop-v20.2.0-v2/protocol.yaml"


def baseline_digest(relative: str, raw: bytes) -> str:
    """Keep historical corpus raw; normalize checkout EOL for text implementation."""
    if not relative.startswith("benchmarks/juice-shop-v20.2.0/"):
        raw = raw.replace(b"\r\n", b"\n")
    return hashlib.sha256(raw).hexdigest()


def load_protocol(path: Path = PROTOCOL, *, check_baseline: bool = True) -> BenchmarkProtocolV2:
    """Fail closed on malformed protocol, raw-byte lock or frozen input mismatch.

    Future V2 benchmark preflight must call this before infrastructure/model calls,
    and additionally validate the A04 dataset and A06 scanner locks. This command
    validates the A01 artifact only and never substitutes for a dataset preflight.
    """
    raw = path.read_bytes()
    protocol = BenchmarkProtocolV2.model_validate(yaml.safe_load(raw))
    lock = json.loads(path.with_name("protocol.lock.json").read_text(encoding="utf-8"))
    expected = {
        "schema_version": "benchmark.protocol.lock.v2",
        "dataset_id": protocol.dataset_id,
        "dataset_version": protocol.dataset_version,
        "protocol_sha256": hashlib.sha256(raw).hexdigest(),
        "target_commit": protocol.target_commit,
    }
    if lock != expected:
        raise ValueError("Protocol lock mismatch; create a new version, never overwrite the lock")
    if check_baseline:
        for relative, digest in protocol.baseline.input_digests.items():
            source = (ROOT / relative).resolve()
            if not source.is_relative_to(ROOT) or not source.is_file():
                raise ValueError("Frozen baseline input must be inside repository")
            if baseline_digest(relative, source.read_bytes()) != digest:
                raise ValueError("Frozen baseline input mismatch: " + relative)
    return protocol


def split_group(independence_group: str, policy: SplitPolicy) -> str:
    """Use exact UTF-8 and integer arithmetic; no order or Python hash dependence."""
    if not independence_group or "\0" in independence_group or "\0" in policy.seed:
        raise ValueError("Group and seed must be nonempty NUL-free strings")
    raw = (policy.seed + "\0" + independence_group).encode("utf-8")
    value = int.from_bytes(hashlib.sha256(raw).digest(), "big")
    return (
        "development" if value * 100 < policy.development_percent * (1 << 256)
        else "holdout"
    )


def split_cases(cases: list[BenchmarkCaseV2], policy: SplitPolicy) -> dict[str, str]:
    """Twins/anchors stay together. Reject inflated positive counts in a slice."""
    if len({c.id for c in cases}) != len(cases):
        raise ValueError("Duplicate case ID")
    positives = set()
    for case in cases:
        key = (case.independence_group, case.sample_kind)
        if case.expected == "vulnerable":
            if key in positives:
                raise ValueError("Multiple positive cases for one independent cause/slice")
            positives.add(key)
    return {c.id: split_group(c.independence_group, policy) for c in sorted(cases, key=lambda c: c.id)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, default=PROTOCOL)
    protocol = load_protocol(parser.parse_args().protocol)
    print(f"A01 protocol/lock/baseline valid: {protocol.dataset_id}; ground truth pending A04")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
