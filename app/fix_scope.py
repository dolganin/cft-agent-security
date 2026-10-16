"""Replay C01 original evidence and publish explicit eligibility (no model/Docker)."""
import argparse
from pathlib import Path

from fix_verification.scope import assess_scope


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = assess_scope()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8", newline="\n") as handle:
        handle.write(report.model_dump_json(indent=2) + "\n")
    print(f"eligible={report.eligible} failed={report.failed} ineligible={report.ineligible}")
    return 0 if report.eligible >= 2 and report.failed == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
