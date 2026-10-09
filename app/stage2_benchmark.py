"""Official Stage 2 entrypoint. External benchmark; unchanged production pipeline."""

import argparse

from evaluation.benchmark_harness import run_benchmark


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", default="juice-shop-v20.2.0-v1")
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--output", default="artifacts/benchmarks/juice-shop-v20.2.0-v1")
    parser.add_argument("--target", help="Clean LF checkout of the pinned target commit")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument(
        "--preflight-only",
        action="store_true",
        help="Check infrastructure; model receives no target source or truth",
    )
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    return run_benchmark(args)


if __name__ == "__main__":
    raise SystemExit(main())
