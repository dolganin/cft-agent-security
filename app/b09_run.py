"""One operator-pinned B09 run; benchmark labels never enter the producer."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path

from app.ci_pipeline import run_ci_pipeline
from app.config import settings
from app.pipeline_run import run_pipeline
from sast.profiles import validate_target_snapshot
from schemas.target import TargetProfile

COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
PROFILES = ("juice-verification.yaml", "juice-b05-access-fixture.yaml", "juice-b06-verification.yaml")


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False, default=str) + "\n")


def git(*args, cwd=None):
    return subprocess.check_output(["git", *args], cwd=cwd, text=True).strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-target", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = Path(args.output).resolve()
    if output.exists():
        raise ValueError("B09 requires a new output directory, never overwrite a run")
    source = Path(args.source_target).resolve(strict=True)
    validate_target_snapshot(source, COMMIT)
    output.mkdir(parents=True)
    target = output.parent / (output.name + "-target")
    if target.exists():
        raise ValueError("Disposable target path already exists")
    git("clone", "--shared", str(source), str(target))
    git("checkout", "--detach", COMMIT, cwd=target)
    # Operator-only Compose is excluded locally, never change target tracked source.
    with (target / ".git/info/exclude").open("a") as stream:
        stream.write("\n/docker-compose.presentation.yml\n")
    shutil.copyfile(root / "targets/juice-b09.compose.yml", target / "docker-compose.presentation.yml")
    before = validate_target_snapshot(target, COMMIT)
    settings.llm_routes = "nsu:qwen3.8-flash-next"
    settings.llm_timeout_seconds = 55
    settings.llm_max_output_tokens = 8192
    settings.llm_reasoning_effort = "low"
    settings.llm_allow_external_fallbacks = False
    settings.scout_schedule_mode = "handlers"
    settings.scout_max_turns = 8
    settings.scout_wall_clock_seconds = 240
    settings.scout_max_candidates = 32
    settings.scout_max_source_chars = 160000
    settings.agent_wall_clock_seconds = 120
    pinned = {name: getattr(settings, name) for name in (
        "llm_routes", "llm_timeout_seconds", "llm_max_output_tokens", "llm_reasoning_effort",
        "llm_allow_external_fallbacks", "scout_schedule_mode", "scout_max_turns",
        "scout_wall_clock_seconds", "scout_max_candidates", "scout_max_source_chars",
        "agent_wall_clock_seconds")}
    pinned.update(max_iterations=2, repetitions=1, reproducibility="not_measured",
                  mttr="not_measured", implementation_commit=git("rev-parse", "HEAD", cwd=root),
                  started_at=datetime.now(UTC).isoformat(), target_snapshot=before)
    inputs = [root / "targets" / name for name in PROFILES]
    inputs += [root / "targets/juice-b09.compose.yml", root / "sast/rules/juice-shop-v2/profile.yaml"]
    pinned["operator_inputs_sha256"] = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in inputs}
    write_json(output / "run-config.json", pinned)

    def runner(pipeline_args, *, profile_override, runtime_services):
        profiles = tuple(TargetProfile.from_yaml(root / "targets" / name,
                         repository_path_override=target) for name in PROFILES)
        # This union contains only existing operator endpoints. Private checks
        # still require their original exact profile, fixture and approval.
        endpoints = sorted({endpoint for profile in profiles for service in profile.services.values()
                            for endpoint in service.runtime_endpoints})
        services = {name: service.model_copy(update={"allowed_endpoints": endpoints})
                    for name, service in runtime_services.services.items()}
        runtime = runtime_services.model_copy(update={"services": services})
        write_json(output / "pipeline/operator-runtime-service-map.json", runtime.model_dump(mode="json"))
        write_json(output / "pipeline/operator-profiles.json", [p.model_dump(mode="json") for p in profiles])
        return run_pipeline(pipeline_args, profile_override=profile_override,
                            runtime_services=runtime, verification_profiles=profiles)

    ci_args = argparse.Namespace(target=str(target), target_repository=None,
        profile=str(root / "targets/juice-verification.yaml"), architecture=None,
        architecture_overrides=None, sast_config=str(root / "sast/rules/juice-shop-v2/profile.yaml"),
        findings=None, output_dir=str(output / "pipeline"), agent_mode="llm",
        max_iterations=2, full_reports=True, base_ref=None, head_ref="HEAD",
        base_findings=None, base_architecture=None)
    exit_code = run_ci_pipeline(ci_args, pipeline_runner=runner)
    after = validate_target_snapshot(target, COMMIT)
    write_json(output / "run-result.json", {"exit_code": exit_code,
        "finished_at": datetime.now(UTC).isoformat(), "target_snapshot_after": after,
        "source_unchanged": before == after})
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
