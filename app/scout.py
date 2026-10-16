"""Run just source exploration, with the same Scout used by the CI pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from agent.llm_model import FallbackLLMAgentModel
from agent.prompts import SYSTEM_PROMPT
from agent.repository_scout import RepositoryScout
from app.config import settings
from discovery.express_routes import build_express_source_map, link_candidates_to_routes
from discovery.scout import merge_scout_candidates
from discovery.service import ProjectDiscovery
from schemas.finding import Finding
from security.scout_surface import load_surface_profile, scope_discovery
from tools.repository_source import RepositorySource


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--sast-findings", type=Path,
                        help="Saved canonical Finding JSON array; never sent to Scout")
    parser.add_argument("--max-turns", type=int, default=settings.scout_max_turns)
    parser.add_argument("--schedule", choices=["round_robin", "handlers"],
                        default=settings.scout_schedule_mode)
    parser.add_argument("--max-source-chars", type=int, default=settings.scout_max_source_chars)
    parser.add_argument("--wall-clock-seconds", type=float, default=settings.scout_wall_clock_seconds)
    parser.add_argument("--max-candidates", type=int, default=settings.scout_max_candidates)
    parser.add_argument("--max-output-tokens", type=int, default=settings.llm_max_output_tokens)
    parser.add_argument(
        "--blind-discovery", action="store_true",
        help="Run source discovery without SAST seeds and write a provenance manifest",
    )
    parser.add_argument(
        "--surface", help="Operator-registered broad source surface (requires blind mode)",
    )
    parser.add_argument(
        "--surface-registry", type=Path,
        default=Path(__file__).resolve().parents[1] / "targets/juice-scout-surfaces.yaml",
    )
    args = parser.parse_args()
    if args.blind_discovery and args.sast_findings:
        parser.error("--blind-discovery cannot be combined with --sast-findings")
    if args.surface and not args.blind_discovery:
        parser.error("--surface requires --blind-discovery")
    baseline = []
    if args.sast_findings:
        baseline = [Finding.model_validate(item) for item in json.loads(
            args.sast_findings.read_text(encoding="utf-8"),
        )]
    destination = Path(args.output_dir)
    destination.mkdir(parents=True, exist_ok=False)
    config = settings.model_copy(update={
        "executor_audit_log": destination / "audit/executor.jsonl",
        "llm_max_output_tokens": args.max_output_tokens,
    })
    discovery = ProjectDiscovery().discover(args.target)
    profile = None
    profile_bytes = None
    if args.surface:
        try:
            profile, profile_bytes = load_surface_profile(args.surface_registry, args.surface)
            discovery = scope_discovery(discovery, profile)
        except (OSError, ValueError) as exc:
            parser.error(f"Invalid blind-discovery surface: {exc}")
    source_map = build_express_source_map(discovery, include_oracle_controllers=False,
                                          include_vulnerability_regions=False)
    client = FallbackLLMAgentModel.from_settings(config).client
    scout = RepositoryScout(
        client, max_turns=args.max_turns, max_candidates=args.max_candidates,
        max_source_chars=args.max_source_chars,
        wall_clock_seconds=args.wall_clock_seconds,
        schedule_mode=args.schedule,
    )
    batch = scout.scout(
        discovery, source_map=source_map,
        surface_focus=profile.focus if profile is not None else None,
    )
    findings, duplicates = merge_scout_candidates(
        baseline, batch.candidates, service_resolver=discovery.resolve_component,
        repository_root=discovery.repository_root,
    )
    original_ids = {item.id for item in baseline}
    added = sum(not original_ids.intersection(
        {item.id, *(item.provenance.aliases if item.provenance else [])},
    ) for item in findings)
    scout.audit.update(duplicates=duplicates, merged_candidates=added)
    scout.audit["sast_vs_sast_scout"] = {
        "sast_queue": len(baseline), "combined_queue": len(findings),
        "new_scout_candidates": added, "duplicates": duplicates,
        "baseline_supplied": args.sast_findings is not None,
        "scope": "candidate_discovery_only_not_precision_recall_or_confirmed",
    }
    scout.audit["express_source_map"] = {
        "analyzed_files": len(source_map.analyzed_files),
        "routes": len(source_map.routes),
        "middleware_mounts": len(source_map.middleware_mounts),
        "dynamic_routes": source_map.dynamic_routes,
        "omitted_routes": source_map.omitted_routes,
        "omitted_middleware_mounts": source_map.omitted_middleware_mounts,
        "unsupported_files": source_map.unsupported_files,
    }
    route_links = link_candidates_to_routes(batch.candidates, source_map)
    scout.audit["route_candidate_links"] = {
        "candidates": len(route_links),
        "mapped": sum(item["binding_status"] != "unmapped" for item in route_links),
        "ambiguous": sum(item["binding_status"] == "ambiguous" for item in route_links),
        "authorization_assessed": False,
    }
    (destination / "express-source-map.json").write_text(
        source_map.model_dump_json(indent=2), encoding="utf-8",
    )
    (destination / "candidate-route-links.json").write_text(
        json.dumps(route_links, ensure_ascii=False, indent=2), encoding="utf-8",
    )
    for name, value in (
        ("summary", scout.audit),
        ("candidates", batch.model_dump(mode="json")),
        ("findings", [f.model_dump(mode="json") for f in findings]),
    ):
        (destination / f"{name}.json").write_text(
            json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8",
        )
    if args.blind_discovery:
        source = RepositorySource(discovery)
        profile_data = profile.model_dump(mode="json") if profile is not None else None
        manifest = {
            "schema_version": "cft.blind_discovery_manifest.v1",
            "created_at": datetime.now(UTC).isoformat(),
            "mode": "targeted_development_run" if profile is not None else "blind_project_discovery",
            "target": {
                "revision": _git_revision(discovery.repository_root),
                "revision_source": "git rev-parse HEAD; null if target has no Git revision",
            },
            "surface": {
                "id": profile.id if profile is not None else None,
                "focus": profile.focus if profile is not None else None,
                "profile_sha256": _sha256(_canonical_json(profile_data))
                if profile_data is not None else None,
                "registry_file_sha256": _sha256(profile_bytes)
                if profile_bytes is not None else None,
                "source_paths": sorted(source.lines),
                "projected_source_sha256": {
                    path: _sha256("\n".join(source.lines[path]).encode("utf-8"))
                    for path in sorted(source.lines)
                },
            },
            "model_input_boundaries": {
                "sast_findings_supplied": False,
                "finding_seed_supplied": False,
                "benchmark_labels_supplied": False,
                "oracle_controllers_enabled": False,
                "vulnerability_regions_enabled": False,
            },
            "model_configuration": {
                "system_prompt_sha256": _sha256(SYSTEM_PROMPT.encode("utf-8")),
                "max_turns": args.max_turns,
                "max_source_chars": args.max_source_chars,
                "max_candidates": args.max_candidates,
                "wall_clock_seconds": args.wall_clock_seconds,
                "schedule": args.schedule,
                "max_output_tokens": args.max_output_tokens,
            },
            "source_map_sha256": _sha256(_canonical_json(source_map.model_dump(mode="json"))),
            "result": {
                "candidate_count": len(batch.candidates),
                "stop_reason": scout.audit["stop_reason"],
                "model_calls": scout.audit["model_calls"],
            },
        }
        (destination / "blind-manifest.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8",
        )
    print(json.dumps({
        "indexed_files": scout.audit["indexed_files"],
        "reviewed_files": len({r["file"] for r in scout.audit["reviewed_ranges"]}),
        "candidates": len(findings), "stop_reason": scout.audit["stop_reason"],
        "elapsed_seconds": scout.audit.get("elapsed_seconds", 0),
    }, ensure_ascii=False))
    return 2 if scout.audit["stop_reason"] == "model_unavailable" else 0


def _sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def _git_revision(repository_root: Path) -> str | None:
    try:
        root_result = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "--show-toplevel"],
            capture_output=True, text=True, check=False, timeout=5,
        )
        if (root_result.returncode != 0
                or Path(root_result.stdout.strip()).resolve() != repository_root.resolve()):
            return None
        result = subprocess.run(
            ["git", "-C", str(repository_root), "rev-parse", "--verify", "HEAD"],
            capture_output=True, text=True, check=False, timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    revision = result.stdout.strip()
    return revision if (
        result.returncode == 0 and len(revision) == 40
        and all(char in "0123456789abcdefABCDEF" for char in revision)
    ) else None


if __name__ == "__main__":
    raise SystemExit(main())
