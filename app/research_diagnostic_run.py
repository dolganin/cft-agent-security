"""One expanded live R09 DEV campaign; no benchmark answers enter the producer."""
import argparse
import json
import subprocess
import time
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.config import settings
from app.research_acceptance import docker
from app.research_campaign import campaign, write_json
from app.research_juice_smoke import COMMIT, IMAGE
from executor.access_fixture import WORKER_IMAGE
from pipeline.cancellation import RunCancelled
from sast.profiles import load_scan_profile, validate_target_snapshot
from sast.semgrep_runner import run_semgrep_scan
from schemas.llm import LLMProbeResult
from schemas.research_agent import ResearchLimits
from schemas.research_campaign import CampaignLimits
from schemas.research_fixtures import ResearchFixtureGrant
from schemas.target import TargetProfile
from security.error_redaction import redact_observation

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = ["/socket.io", "/rest/challenges", "/api/Challenges", "/score-board", "/scoreboard",
            "/rest/score-board", "/rest/continue-code", "/rest/continue-code-findIt", "/rest/continue-code-fixIt",
            "/snippets", "/codefixes", "/solutions"]
FIXTURE_GRANTS = (
    ResearchFixtureGrant(protocol="b05.own-read.v1", max_http_requests=238),
    ResearchFixtureGrant(protocol="b06.redirect.v1", max_http_requests=38),
    ResearchFixtureGrant(protocol="b06.password-reauth.v1", max_http_requests=194),
)


def limits():
    return CampaignLimits(max_questions=64, max_actions=256, max_model_calls=256,
        wall_seconds=1800, max_model_io_bytes=67108864, max_observation_bytes=16777216,
        max_write_bytes=4194304, max_http_requests=1024, dev_preferred_families=[])


def run(checkout, image, browser_image, output, *, campaign_limits=None, question_limits=None):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("One new R09 output; never overwrite or silently restart")
    started = time.monotonic()
    try:
        return _run(checkout, image, browser_image, output,
                    campaign_limits=campaign_limits, question_limits=question_limits)
    except (KeyboardInterrupt, RunCancelled, Exception) as exc:
        if output.is_dir():
            state = json.loads((output / "run-state.json").read_text()) if (output / "run-state.json").exists() else {}
            source_unchanged = None
            try:
                source_unchanged = state.get("target") == validate_target_snapshot(Path(checkout).resolve(), COMMIT)
            except (OSError, ValueError, RuntimeError):
                source_unchanged = False
            campaign_result = json.loads((output / "campaign/summary.json").read_text()) if (output / "campaign/summary.json").exists() else None
            write_json(output / "run-result.json", {"stage": "R09", "completed": False,
                "stop_reason": "operator_cancelled" if isinstance(exc, (KeyboardInterrupt, RunCancelled)) else "run_failed",
                "failure_type": type(exc).__name__, "campaign": campaign_result,
                "source_unchanged": source_unchanged, "target_cleanup_verified": state.get("cleanup_verified", False),
                "elapsed_seconds": round(time.monotonic() - started, 3), "full_benchmark_measurement": False,
                "repetitions": 1, "phase": state.get("phase")})
            _seal(output)
        raise


def _seal(output):
    write_json(output / "seal.json", {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
        for p in sorted(output.rglob("*")) if p.is_file() and p != output / "seal.json"})


def _run(checkout, image, browser_image, output, *, campaign_limits=None, question_limits=None):
    checkout, output = Path(checkout).resolve(), Path(output).resolve()
    active_limits = campaign_limits or limits()
    if output.exists():
        raise FileExistsError("One new R09 output; never overwrite or silently restart")
    before = validate_target_snapshot(checkout, COMMIT)
    for reference in (image, browser_image, IMAGE, WORKER_IMAGE):
        docker(["image", "inspect", reference])
    output.mkdir(parents=True)
    started = time.monotonic()
    run_state = {"phase": "preflight", "target": before, "cleanup_verified": True}
    write_json(output / "run-state.json", run_state)
    client_args = {"routes":parse_route_specs("nsu:qwen3.8-flash-next", allow_external_fallbacks=False),
        "credentials":settings.llm_provider_credentials(), "timeout_seconds":45,
        "reasoning_effort":"low", "diagnostics_path":output / "llm-attempts.jsonl"}
    probe = ProviderFailoverClient(**client_args, max_output_tokens=256)
    probe.complete_model(output_model=LLMProbeResult, system_prompt="Return status ready and note ok.",
        user_payload={"purpose":"R09 generation/authentication preflight"}, operation="r09_preflight")
    write_json(output / "preflight.json", {"generation_validated":True, "model":"nsu:qwen3.8-flash-next",
        "calls":len(probe.last_attempts), "provider_usage":probe.last_usage})
    run_state["phase"] = "sast"
    write_json(output / "run-state.json", run_state)
    scan_profile = load_scan_profile(ROOT / "sast/rules/juice-shop-v2/profile.yaml")
    scan = run_semgrep_scan(checkout, config=scan_profile["config_files"], timeout_seconds=120)
    write_json(output / "sast/raw-redacted.json", redact_observation(scan.raw))
    write_json(output / "sast/findings.json", [x.model_dump(mode="json") for x in scan.findings])
    prefix = "r09-juice-"+uuid4().hex[:12]
    network, container = prefix+"-net", prefix+"-target"
    result = None
    run_state.update({"phase": "provisioning", "container": container, "network": network, "cleanup_verified": False})
    write_json(output / "run-state.json", run_state)
    try:
        docker(["network", "create", "--internal", network])
        docker(["run", "--detach", "--pull=never", "--name", container,
            "--network", network, "--network-alias", "juice", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--memory=768m", "--cpus=2",
            "--pids-limit=128", "--log-driver=none", IMAGE])
        for _ in range(60):
            ready = subprocess.run(["docker", "exec", container, "/nodejs/bin/node", "-e",
                "require('http').get('http://127.0.0.1:3000/',r=>{r.resume();process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"],
                capture_output=True, timeout=5, check=False)
            if ready.returncode == 0:
                break
            time.sleep(.5)
        else:
            raise RuntimeError("R09 target readiness failed")
        profile = TargetProfile(id="juice-research-r09", name="Pinned R09 diagnostic DEV target",
            environment="sandbox", repository_path=checkout, services={"juice":{"internal_port":3000}})
        config = {"worker_image":image, "browser_image":browser_image, "action_timeout":30,
            "max_http_requests":128, "runtime_service_map":{"session_id":prefix, "network_name":network,
                "services":{"juice":{"name":"juice", "address":"http://juice:3000", "ready":True,
                    "readiness_source":"http_probe"}}},
            "http_grants":{"juice":{"read_prefixes":["/"], "denied_prefixes":EXCLUDED, "write_paths":{}}}}
        research_limits = question_limits or ResearchLimits(max_steps=12, max_model_calls=28, max_schema_corrections=1,
            max_context_bytes=64000, max_model_io_bytes=4194304, wall_seconds=180)
        manifest = {"stage":"R09", "kind":"development_diagnostic", "started_at":datetime.now(UTC).isoformat(),
            "implementation_commit":subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,text=True).strip(),
            "runner_sha256":sha256(Path(__file__).read_bytes()).hexdigest(), "target":before,
            "implementation_dirty":bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT, text=True).strip()),
            "implementation_sha256":{p.relative_to(ROOT).as_posix():sha256(p.read_bytes()).hexdigest()
                for base in ("agent", "app", "schemas", "security", "executor", "pipeline", "tools", "evidence", "validator", "reporting", "sast")
                for p in sorted((ROOT / base).rglob("*.py"))},
            "target_image":IMAGE, "research_image":image, "browser_image":browser_image,
            "model":"nsu:qwen3.8-flash-next", "model_output_tokens":8192, "repetitions":1,
            "campaign_limits":active_limits.model_dump(), "research_limits":research_limits.model_dump(),
            "selection":"All fresh SAST observations; no family representatives or preferred proof families",
            "fresh_sast_observations":len(scan.findings), "fresh_dast":False,
            "runtime_scope":"anonymous read-only research plus exact operator-granted B05 own-read and B06 redirect/re-auth fixtures; no model-selected credentials, writes, or arbitrary fixture actions",
            "operator_grants":config["http_grants"], "evaluator_labels_provided_to_model":False,
            "canonical_verification_profiles":["targets/juice-verification.yaml",
                "targets/juice-b05-access-fixture.yaml", "targets/juice-b06-verification.yaml"],
            "canonical_fixture_grants":[grant.model_dump() for grant in FIXTURE_GRANTS],
            "canonical_verification_worker_image":WORKER_IMAGE,
            "canonical_verification_scope":"B01 SQL/directory plus explicitly granted B05 own-read and B06 redirect/re-auth; each exact protocol remains source-bound and independently validated",
            "full_benchmark_measurement":False, "mttr":"not_measured", "reproducibility":"not_measured"}
        write_json(output / "run-manifest.json", manifest)
        print(json.dumps({"phase":"campaign_started", "sast_observations":len(scan.findings),
                          "max_wall_seconds":active_limits.wall_seconds, "model":manifest["model"]}), flush=True)
        run_state.update({"phase": "campaign", "campaign_started_at": datetime.now(UTC).isoformat(),
                          "preparation_seconds": round(time.monotonic() - started, 3)})
        write_json(output / "run-state.json", run_state)
        verification_profiles = tuple(TargetProfile.from_yaml(ROOT / relative,
            repository_path_override=checkout) for relative in (
                "targets/juice-verification.yaml", "targets/juice-b05-access-fixture.yaml",
                "targets/juice-b06-verification.yaml"))
        result = campaign(profile=profile, configuration=config, client=ProviderFailoverClient(**client_args, max_output_tokens=8192),
            output=output / "campaign", sast=scan.findings, limits=active_limits, research_limits=research_limits,
            verification_profiles=verification_profiles,
            verification_worker_image=WORKER_IMAGE, fixture_grants=FIXTURE_GRANTS)
    finally:
        from pipeline.cancellation import suspend_cancellation

        cleanup = []
        with suspend_cancellation():
            for kind, name, command in (("container", container, ["rm", "--force", container]),
                                         ("network", network, ["network", "rm", network])):
                try:
                    docker(command)
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    pass
                inventory = subprocess.run(["docker", "ps", "-a", "--format", "{{.Names}}"] if kind == "container" else
                    ["docker", "network", "ls", "--format", "{{.Name}}"], capture_output=True, text=True, timeout=15, check=False)
                cleanup.append({"kind": kind, "name": name,
                    "verified_absent": inventory.returncode == 0 and name not in inventory.stdout.splitlines()})
        run_state.update({"cleanup_verified": all(row["verified_absent"] for row in cleanup), "cleanup": cleanup})
        write_json(output / "run-state.json", run_state)
        if not run_state["cleanup_verified"]:
            raise RuntimeError("R09 target cleanup could not be verified")
    after = validate_target_snapshot(checkout, COMMIT)
    write_json(output / "run-result.json", {"stage":"R09", "completed":True, "campaign":result, "source_unchanged":before == after,
        "target_cleanup_verified":True, "elapsed_seconds":round(time.monotonic()-started,3),
        "full_benchmark_measurement":False, "repetitions":1})
    _seal(output)
    return result


if __name__ == "__main__":
    import signal

    def cancelled_signal(_signum, _frame):
        raise RunCancelled("Operator sent termination signal")

    signal.signal(signal.SIGTERM, cancelled_signal)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--browser-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wall-seconds", type=int, default=1800, help="Campaign budget; preparation is reported separately")
    parser.add_argument("--max-questions", type=int, default=64)
    args = parser.parse_args()
    selected_limits = CampaignLimits.model_validate({**limits().model_dump(),
        "wall_seconds": args.wall_seconds, "max_questions": args.max_questions})
    try:
        print(json.dumps(run(args.checkout, args.image, args.browser_image, args.output,
                             campaign_limits=selected_limits), indent=2))
    except (KeyboardInterrupt, RunCancelled):
        print(json.dumps({"completed": False, "stop_reason": "operator_cancelled", "output": str(args.output)}))
        raise SystemExit(130) from None
