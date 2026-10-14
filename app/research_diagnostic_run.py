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
from sast.profiles import load_scan_profile, validate_target_snapshot
from sast.semgrep_runner import run_semgrep_scan
from schemas.llm import LLMProbeResult
from schemas.research_agent import ResearchLimits
from schemas.research_campaign import CampaignLimits
from schemas.target import TargetProfile
from security.error_redaction import redact_observation

ROOT = Path(__file__).resolve().parents[1]
EXCLUDED = ["/socket.io", "/rest/challenges", "/api/Challenges", "/score-board", "/scoreboard",
            "/rest/score-board", "/rest/continue-code", "/rest/continue-code-findIt", "/rest/continue-code-fixIt",
            "/snippets", "/codefixes", "/solutions"]


def limits():
    return CampaignLimits(max_questions=64, max_actions=256, max_model_calls=256,
        wall_seconds=1800, max_model_io_bytes=67108864, max_observation_bytes=16777216,
        max_write_bytes=4194304, max_http_requests=1024, dev_preferred_families=[])


def run(checkout, image, browser_image, output):
    checkout, output = Path(checkout).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError("One new R09 output; never overwrite or silently restart")
    before = validate_target_snapshot(checkout, COMMIT)
    for reference in (image, browser_image, IMAGE):
        docker(["image", "inspect", reference])
    output.mkdir(parents=True)
    started = time.monotonic()
    client_args = {"routes":parse_route_specs("nsu:qwen3.8-flash-next", allow_external_fallbacks=False),
        "credentials":settings.llm_provider_credentials(), "timeout_seconds":45,
        "reasoning_effort":"low", "diagnostics_path":output / "llm-attempts.jsonl"}
    probe = ProviderFailoverClient(**client_args, max_output_tokens=256)
    probe.complete_model(output_model=LLMProbeResult, system_prompt="Return status ready and note ok.",
        user_payload={"purpose":"R09 generation/authentication preflight"}, operation="r09_preflight")
    write_json(output / "preflight.json", {"generation_validated":True, "model":"nsu:qwen3.8-flash-next",
        "calls":len(probe.last_attempts), "provider_usage":probe.last_usage})
    scan_profile = load_scan_profile(ROOT / "sast/rules/juice-shop-v2/profile.yaml")
    scan = run_semgrep_scan(checkout, config=scan_profile["config_files"], timeout_seconds=120)
    write_json(output / "sast/raw-redacted.json", redact_observation(scan.raw))
    write_json(output / "sast/findings.json", [x.model_dump(mode="json") for x in scan.findings])
    prefix = "r09-juice-"+uuid4().hex[:12]
    network, container = prefix+"-net", prefix+"-target"
    cid = None
    result = None
    docker(["network", "create", "--internal", network])
    try:
        cid = docker(["run", "--detach", "--pull=never", "--name", container,
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
        research_limits = ResearchLimits(max_steps=12, max_model_calls=28, max_schema_corrections=1,
            max_context_bytes=64000, max_model_io_bytes=4194304, wall_seconds=180)
        manifest = {"stage":"R09", "kind":"development_diagnostic", "started_at":datetime.now(UTC).isoformat(),
            "implementation_commit":subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT,text=True).strip(),
            "runner_sha256":sha256(Path(__file__).read_bytes()).hexdigest(), "target":before,
            "target_image":IMAGE, "research_image":image, "browser_image":browser_image,
            "model":"nsu:qwen3.8-flash-next", "model_output_tokens":8192, "repetitions":1,
            "campaign_limits":limits().model_dump(), "research_limits":research_limits.model_dump(),
            "selection":"All fresh SAST observations; no family representatives or preferred proof families",
            "fresh_sast_observations":len(scan.findings), "fresh_dast":False,
            "runtime_scope":"anonymous read-only HTTP/browser; no authenticated private fixture or write grant",
            "operator_grants":config["http_grants"], "evaluator_labels_provided_to_model":False,
            "full_benchmark_measurement":False, "mttr":"not_measured", "reproducibility":"not_measured"}
        write_json(output / "run-manifest.json", manifest)
        print(json.dumps({"phase":"campaign_started", "sast_observations":len(scan.findings),
                          "max_wall_seconds":1800, "model":manifest["model"]}), flush=True)
        result = campaign(profile=profile, configuration=config, client=ProviderFailoverClient(**client_args, max_output_tokens=8192),
            output=output / "campaign", sast=scan.findings, limits=limits(), research_limits=research_limits)
    finally:
        if cid:
            docker(["rm", "--force", container])
        docker(["network", "rm", network])
    after = validate_target_snapshot(checkout, COMMIT)
    write_json(output / "run-result.json", {"stage":"R09", "campaign":result, "source_unchanged":before == after,
        "target_cleanup_verified":True, "elapsed_seconds":round(time.monotonic()-started,3),
        "full_benchmark_measurement":False, "repetitions":1})
    seal = {p.relative_to(output).as_posix():sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob("*")) if p.is_file()}
    write_json(output / "seal.json", seal)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--browser-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.checkout, args.image, args.browser_image, args.output), indent=2))
