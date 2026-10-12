"""A06 scanner baseline CLI. Explicit provisioning; no arbitrary target URL."""
import argparse
import json
from pathlib import Path

from evaluation.scanner_baseline import load_profile, preflight, run_baselines, score_exports


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["validate", "preflight", "run", "score"])
    parser.add_argument("--target", type=Path, default=Path("artifacts/benchmark-target/juice-shop"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--artifacts", type=Path)
    parser.add_argument("--retry-of")
    parser.add_argument("--provision-images", action="store_true")
    args = parser.parse_args(argv)
    if args.command in {"run", "score"} and args.output is None:
        parser.error("run/score require --output (a fresh directory)")
    if args.command == "score" and args.artifacts is None:
        parser.error("score requires --artifacts")
    try:
        if args.command == "validate":
            load_profile()
            print("A04 and A06 locks valid; no scanner or target executed")
        elif args.command == "preflight":
            profile, _, files, images = preflight(args.target, provision_images=args.provision_images)
            print(json.dumps({"target_commit": profile.target_commit,
                              "target_files": len(files), "images": images}, indent=2))
        elif args.command == "score":
            print(score_exports(args.artifacts, args.output))
        else:
            result = run_baselines(args.target, args.output, provision_images=args.provision_images,
                                   retry_of=args.retry_of)
            print(json.dumps({k: result[k] for k in ["status", "attempt_id", "observation_counts",
                                                    "technical_errors", "seconds"]}, indent=2))
            return 0 if result["status"] in {"COMPLETED", "COMPLETED_WITH_LIMITATIONS"} else 2
    except ImportError:
        print("A05 evaluator is not installed in this branch; raw exports remain available")
        return 2
    except (ValueError, OSError, RuntimeError) as exc:
        print(f"A06 failed: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
