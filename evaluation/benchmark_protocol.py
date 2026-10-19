"""A01 protocol preflight and deterministic split. No producer or scored run."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Literal

import yaml

from evaluation.historical_baseline import frozen_presentation_input, historical_input
from schemas.benchmark import BenchmarkCaseV2, BenchmarkProtocolV2, SplitPolicy

ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = ROOT / "benchmarks/juice-shop-v20.2.0-v2/protocol.yaml"


def baseline_digest(relative: str, raw: bytes) -> str:
    """Keep historical corpus raw; normalize checkout EOL for text implementation."""
    if not relative.startswith("benchmarks/juice-shop-v20.2.0/"):
        raw = raw.replace(b"\r\n", b"\n")
    return hashlib.sha256(raw).hexdigest()


def load_protocol(
    path: Path = PROTOCOL, *, check_baseline: bool = True,
    baseline_mode: Literal["historical", "live"] = "historical",
) -> BenchmarkProtocolV2:
    """Fail closed on malformed protocol, raw-byte lock or frozen input mismatch.

    Historical mode verifies the recorded implementation in a fixed Git revision,
    plus current benchmark/document inputs. It does NOT attest the running code.
    An exact legacy live replay must explicitly request baseline_mode="live".
    New Stage B measurements require a separate implementation/config manifest.
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
        if baseline_mode not in {"historical", "live"}:
            raise ValueError("Unsupported baseline verification mode")
        for relative, digest in protocol.baseline.input_digests.items():
            source = (ROOT / relative).resolve()
            if not source.is_relative_to(ROOT) or not source.is_file():
                raise ValueError("Frozen baseline input must be inside repository")
            raw_input = source.read_bytes()
            if baseline_mode == "historical":
                historical = historical_input(ROOT, relative)
                if baseline_digest(relative, historical) != digest:
                    raise ValueError("Frozen baseline input historical mismatch: " + relative)
                # Benchmark/data/docs remain local and immutable; only historical
                # Python implementation is allowed to evolve independently.
                if relative.endswith(".py") and not relative.startswith("benchmarks/"):
                    raw_input = historical
                else:
                    raw_input = frozen_presentation_input(ROOT, relative, raw_input)
            if baseline_digest(relative, raw_input) != digest:
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
    parser.add_argument("--baseline-mode", choices=["historical", "live"], default="historical")
    args = parser.parse_args()
    protocol = load_protocol(args.protocol, baseline_mode=args.baseline_mode)
    print(f"A01 protocol/lock/{args.baseline_mode} baseline valid: {protocol.dataset_id}; "
          "not a live measurement or dataset acceptance")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
