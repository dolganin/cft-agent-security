"""C04 bounded real-model generation and independent patch verification."""
import argparse
import json
import zipfile
from pathlib import Path

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.config import Settings
from fix_verification.repair_loop import run
from fix_verification.repair_replay import replay
from schemas.repair_loop import RepairLimits


def bundle(directory: Path, destination: Path, protected_target: Path | None = None):
    if destination.resolve().is_relative_to(directory.resolve()):
        raise ValueError("ZIP must be outside the sealed run directory")
    replay(directory)
    config = json.loads((directory / "configuration.json").read_text(encoding="utf-8"))
    original = protected_target or (Path(config["original_path"]) if config.get("original_path") else None)
    if original and destination.resolve().is_relative_to(original.resolve()):
        raise ValueError("ZIP must be outside the original target")
    with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(directory).as_posix())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--replay", type=Path)
    parser.add_argument("--target", type=Path)
    parser.add_argument("--family", choices=("sql-search", "redirect-allowlist"))
    parser.add_argument("--output", type=Path)
    parser.add_argument("--route", default="nsu:qwen3.8-flash-next")
    parser.add_argument("--fix-image", default="cft-fix-juice:stage1")
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--wall-clock-seconds", type=float, default=3600)
    parser.add_argument("--bundle", type=Path, help="Optional new portable ZIP outside the run directory")
    args = parser.parse_args()
    if args.replay:
        print(json.dumps(replay(args.replay)))
        if args.bundle:
            bundle(args.replay, args.bundle)
        return 0
    if not (args.target and args.family and args.output):
        parser.error("--target, --family and --output are required")
    if args.bundle and (args.bundle.exists()
            or args.bundle.resolve().is_relative_to(args.target.resolve())
            or args.bundle.resolve().is_relative_to(args.output.resolve())):
        parser.error("--bundle must be new and outside the target and run directory")
    routes = parse_route_specs(args.route, allow_external_fallbacks=False)
    if len(routes) != 1:
        parser.error("C04 requires one operator-selected provider route")
    limits = RepairLimits(max_attempts=args.max_attempts, wall_clock_seconds=args.wall_clock_seconds)
    client = ProviderFailoverClient(routes=routes, credentials=Settings().llm_provider_credentials(),
        timeout_seconds=45, max_output_tokens=3072, reasoning_effort="low", trace=False)
    result = run(target=args.target, family=args.family, output=args.output, client=client,
                 limits=limits, fix_image=args.fix_image)
    checked = replay(args.output)
    if args.bundle:
        bundle(args.output, args.bundle, protected_target=args.target)
    print(json.dumps({**checked, "duration_ms": result.duration_ms}, ensure_ascii=False))
    return 0 if result.status == "FIXED" else 1 if result.status == "NOT_FIXED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
