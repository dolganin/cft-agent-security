"""Run one or two fixed, offline Juice Shop authorization mini-proof generations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from executor.juice_incremental_fixture import JuiceIncrementalFixture


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--target", type=Path,
        default=Path("artifacts/benchmark-target/juice-shop"),
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--protocol", choices=["role-registration", "anonymous-product-put"], required=True,
    )
    parser.add_argument("--generations", type=int, choices=[1, 2], default=2)
    parser.add_argument("--wall-time-seconds", type=int, choices=range(90, 601), default=240)
    args = parser.parse_args()

    target = args.target.resolve(strict=True)
    output = args.output.resolve()
    if output.exists() or output.is_relative_to(target) or target.is_relative_to(output):
        parser.error("--output must be a new directory outside the target checkout")
    output.mkdir(parents=True)
    generations = []
    for index in range(1, args.generations + 1):
        fixture = JuiceIncrementalFixture(
            repository=target,
            output=output / f"generation-{index:02d}",
            protocol=args.protocol,
            wall_time_seconds=args.wall_time_seconds,
        )
        result = fixture.run()
        generations.append(result)
        if not result["cleanup_complete"]:
            break

    dispositions = [
        item["result"]["disposition"]
        for item in generations if item.get("result") is not None
    ]
    completed = (
        len(generations) == args.generations
        and all(item.get("failure_type") is None
                and item.get("cleanup_complete") is True
                and item.get("target_source_unchanged") is True
                and item.get("result") is not None for item in generations)
    )
    report = {
        "schema_version": "juice.incremental.proof.acceptance.v1",
        "protocol": args.protocol,
        "target_commit": "5658473cf8814459bf89000ce373b20ed0b4eb37",
        "target_image": "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b",
        "requested_generations": args.generations,
        "completed": completed,
        "dispositions": dispositions,
        "same_disposition_across_generations": (
            len(dispositions) == args.generations and len(set(dispositions)) == 1
        ),
        "scope_note": (
            "Operator fixed-protocol acceptance only; not an agent discovery result, "
            "A04 benchmark metric, or full-run reproducibility estimate."
        ),
        "generations": generations,
    }
    (output / "acceptance.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
    )
    print(json.dumps({
        "completed": completed,
        "generations": len(generations),
        "dispositions": dispositions,
        "same_disposition_across_generations": report["same_disposition_across_generations"],
    }, ensure_ascii=False))
    return 0 if completed else 2


if __name__ == "__main__":
    raise SystemExit(main())
