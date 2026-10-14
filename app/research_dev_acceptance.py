"""One live R07 DEV campaign against pinned Juice Shop. Not the final benchmark."""
import argparse
import json
import subprocess
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.config import settings
from app.research_acceptance import docker
from app.research_campaign import campaign, write_json
from app.research_juice_smoke import COMMIT, IMAGE
from sast.identity import rule_family
from sast.profiles import load_scan_profile, validate_target_snapshot
from sast.semgrep_runner import run_semgrep_scan
from schemas.research_agent import ResearchLimits
from schemas.research_campaign import CampaignLimits
from schemas.target import TargetProfile
from security.error_redaction import redact_observation

ROOT = Path(__file__).resolve().parents[1]


def run(checkout, image, output, *, max_questions=4):
    if not 1 <= max_questions <= 4:
        raise ValueError("DEV acceptance supports one to four explicitly selected questions")
    checkout, output = Path(checkout).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError("R07 is one fresh campaign, never overwrite/retry a saved run")
    snapshot = validate_target_snapshot(checkout, COMMIT)
    output.mkdir(parents=True)
    scan_profile = load_scan_profile(ROOT / "sast/rules/juice-shop-v2/profile.yaml")
    scan = run_semgrep_scan(checkout, config=scan_profile["config_files"], timeout_seconds=120)
    write_json(output / "sast/raw-redacted.json", redact_observation(scan.raw))
    write_json(output / "sast/findings.json", [f.model_dump(mode="json") for f in scan.findings])
    # DEV acceptance deliberately includes one candidate per scanner family,
    # rather than spending the whole functional test on a single repeated family.
    # All raw scanner rows remain saved; this is NOT full-catalog Recall.
    representatives = {}
    for finding in scan.findings:
        family = rule_family(finding.rule_id)
        if finding.file.endswith((".ts", ".js", ".py")):
            representatives.setdefault(family, finding)
    selected = list(representatives.values())
    write_json(output / "dev-selection.json", {"policy": "one source candidate per scanner family for functional DEV acceptance",
        "selected_ids": [f.id for f in selected], "raw_count": len(scan.findings),
        "selected_count": len(selected), "benchmark_measurement": False})
    prefix = "r07-juice-" + uuid4().hex[:12]
    network, container = prefix + "-net", prefix + "-target"
    container_id = None
    docker(["network", "create", "--internal", network])
    try:
        container_id = docker(["run", "--detach", "--pull=never", "--name", container,
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
            raise RuntimeError("Juice Shop readiness failed; campaign not started")
        profile = TargetProfile(id="juice-research-dev", name="R07 pinned Juice Shop DEV acceptance",
            environment="sandbox", repository_path=checkout, services={"juice": {"internal_port": 3000}})
        config = {"worker_image": image,
            "runtime_service_map": {"session_id": prefix, "network_name": network,
                "services": {"juice": {"name": "juice", "address": "http://juice:3000", "ready": True,
                                        "readiness_source": "http_probe"}}},
            "http_grants": {"juice": {"read_prefixes": ["/rest/products/search", "/api/Products", "/ftp/"]}}}
        client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next", allow_external_fallbacks=False),
            credentials=settings.llm_provider_credentials(), timeout_seconds=45, max_output_tokens=8192,
            reasoning_effort="low", diagnostics_path=output / "llm-attempts.jsonl")
        write_json(output / "run-manifest.json", {"target": snapshot, "target_image": IMAGE,
            "implementation_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "model": "nsu:qwen3.8-flash-next", "model_output_tokens": 8192, "repetitions": 1,
            "max_questions": max_questions,
            "http_grants": config["http_grants"], "benchmark_measurement": False,
            "purpose": "Live DEV read/write/run/candidate/independent-source-proof acceptance"})
        summary = campaign(profile=profile, configuration=config, client=client, output=output / "campaign",
            sast=selected, limits=CampaignLimits(max_questions=max_questions, max_actions=32, max_model_calls=36, wall_seconds=480,
                                               dev_preferred_families=["weak-cryptography"]),
            research_limits=ResearchLimits(max_steps=8, max_model_calls=20, max_schema_corrections=1, max_model_io_bytes=2097152,
                                          wall_seconds=180), acceptance_require_script=True)
        write_json(output / "campaign-result.json", summary)
    finally:
        if container_id:
            docker(["rm", "--force", container])
        docker(["network", "rm", network])
    after = validate_target_snapshot(checkout, COMMIT)
    ledgers = [json.loads(p.read_text()) for p in sorted((output / "campaign/questions").glob("*/progress.json"))]
    tools = [x["tool"] for progress in ledgers for x in progress["ledger"]]
    checks = {"live_model": summary["model_calls"] > 0 and summary["stop_reason"] != "model_failure",
        "source_read": "read_source" in tools, "script_written": "write_workspace_file" in tools,
        "script_executed": "sandbox_command" in tools, "source_unchanged": snapshot == after,
        "http_observed": "target_http" in tools,
        "cleanup_verified": summary["cleanup_verified"], "independent_review_attempted": bool(summary["review_counts"]["confirmed"]
            + summary["review_counts"]["rejected"] + summary["review_counts"]["review_pending"])}
    result = {"checks": checks, "passed": all(checks.values()), "repetitions": 1,
        "reproducibility": "not_measured", "benchmark_measurement": False,
        "full_catalog_recall": "not_measured", "harness": "existing LangGraph research adapter",
        "max_questions": max_questions,
        "harness_selection": "functional acceptance, not comparative efficacy ranking"}
    write_json(output / "acceptance.json", result)
    seal = {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest() for p in sorted(output.rglob("*")) if p.is_file()}
    write_json(output / "seal.json", seal)
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-questions", type=int, choices=range(1, 5), default=4,
                        help="Explicit functional DEV scope, not full benchmark coverage")
    args = parser.parse_args()
    print(json.dumps(run(args.checkout, args.image, args.output, max_questions=args.max_questions), indent=2))
