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
from app.juice_run_preflight import (
    check_candidate_catalog_reproducibility,
    require_immutable_image,
    verify_frozen_benchmark,
)
from app.research_acceptance import docker
from app.research_campaign import campaign, write_json
from app.research_juice_smoke import COMMIT, IMAGE
from executor.access_fixture import WORKER_IMAGE
from pipeline.cancellation import RunCancelled
from pipeline.research_verification import verification_handoff
from sast.profiles import load_scan_profile, validate_target_snapshot
from sast.semgrep_runner import run_semgrep_scan
from schemas.llm import LLMProbeResult
from schemas.research_agent import ResearchLimits
from schemas.research_campaign import CampaignLimits
from schemas.research_fixtures import ResearchFixtureGrant, ResearchVerificationGrant
from schemas.target import TargetProfile
from security.error_redaction import redact_error_message, redact_observation

ROOT = Path(__file__).resolve().parents[1]
BENCHMARK = ROOT / "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml"
SCAN_PROFILE = ROOT / "sast/rules/juice-shop-v2/profile.yaml"
VERIFICATION_PROFILE_PATHS = (
    "targets/juice-verification.yaml",
    "targets/juice-b05-access-fixture.yaml",
    "targets/juice-b06-verification.yaml",
    "targets/juice-incremental-proof.yaml",
)
EXCLUDED = ["/socket.io", "/rest/challenges", "/api/Challenges", "/score-board", "/scoreboard",
            "/rest/score-board", "/rest/continue-code", "/rest/continue-code-findIt", "/rest/continue-code-fixIt",
            "/snippets", "/codefixes", "/solutions"]
FIXTURE_GRANTS = (
    ResearchFixtureGrant(protocol="b05.review-owner.v1", max_http_requests=250),
    ResearchFixtureGrant(protocol="b05.review-nosql.v1", max_http_requests=250),
    ResearchFixtureGrant(protocol="b05.user-fields.v1", max_http_requests=244),
    ResearchFixtureGrant(protocol="b05.feedback-owner.v1", max_http_requests=244),
    ResearchFixtureGrant(protocol="b05.own-read.v1", max_http_requests=238),
    ResearchFixtureGrant(protocol="b05.basket-insert.v1", max_http_requests=238),
    ResearchFixtureGrant(protocol="b06.redirect.v1", max_http_requests=38),
    ResearchFixtureGrant(protocol="b06.password-reauth.v1", max_http_requests=194),
)
VERIFICATION_GRANTS = (ResearchVerificationGrant(protocol="b01.login-sql.v1", route_id="juice-login"),)


def limits(*, max_http_requests=1024):
    return CampaignLimits(max_questions=64, max_actions=256, max_model_calls=256,
        wall_seconds=1800, max_model_io_bytes=67108864, max_observation_bytes=16777216,
        max_write_bytes=4194304, max_http_requests=max_http_requests, dev_preferred_families=[])


def preflight(checkout, image, browser_image, *, probe_model=False, diagnostics_path=None):
    """Validate immutable inputs and operator wiring before any measurement work."""
    checkout = Path(checkout).resolve(strict=True)
    target = validate_target_snapshot(checkout, COMMIT)
    benchmark = verify_frozen_benchmark(ROOT, expected_commit=COMMIT)
    catalog_reproducibility = check_candidate_catalog_reproducibility(checkout, root=ROOT)
    scan_profile = load_scan_profile(SCAN_PROFILE)
    if scan_profile["target_commit"] != COMMIT:
        raise ValueError("Semgrep profile target pin differs from Juice Shop")
    try:
        semgrep_version = subprocess.check_output(["semgrep", "--version"], text=True,
            stderr=subprocess.STDOUT, timeout=15).strip().splitlines()[-1]
    except (OSError, subprocess.SubprocessError, IndexError) as exc:
        raise ValueError("Pinned Semgrep executable is unavailable") from exc
    if semgrep_version != scan_profile["semgrep_version"]:
        raise ValueError("Semgrep executable version differs from the locked profile")

    verification_profiles = tuple(TargetProfile.from_yaml(ROOT / relative,
        repository_path_override=checkout) for relative in VERIFICATION_PROFILE_PATHS)
    verification_handoff([], verification_profiles, checkout)
    profile_ids = {profile.id for profile in verification_profiles}
    from pipeline.research_fixture_verification import PROTOCOLS

    if any(PROTOCOLS[grant.protocol][0] not in profile_ids for grant in FIXTURE_GRANTS):
        raise ValueError("A fixed fixture grant has no matching operator profile")
    for grant in VERIFICATION_GRANTS:
        owner = next((item for item in verification_profiles if item.id == "juice-verification"), None)
        if owner is None or not any(route.id == grant.route_id and route.tool == "verify_sql_injection"
                                    and route.endpoint == "/rest/user/login" and route.method == "POST"
                                    for route in owner.verification_routes):
            raise ValueError("A fixed verification grant has no exact operator route")
    for profile in verification_profiles:
        for route in profile.verification_routes:
            for source in route.sources:
                candidate = (checkout / source.file).resolve(strict=True)
                if not candidate.is_relative_to(checkout) or not candidate.is_file():
                    raise ValueError("Operator verification source is missing or outside the pinned target")

    proof_images = tuple(profile.juice_incremental_proofs.worker_image
        for profile in verification_profiles if profile.juice_incremental_proofs is not None)
    image_refs = tuple(dict.fromkeys((image, browser_image, IMAGE, WORKER_IMAGE, *proof_images)))
    images = [require_immutable_image(reference, docker) for reference in image_refs]
    generation = {"status": "not_run", "model": "nsu:qwen3.8-flash-next", "calls": 0}
    if probe_model:
        client = ProviderFailoverClient(
            routes=parse_route_specs("nsu:qwen3.8-flash-next", allow_external_fallbacks=False),
            credentials=settings.llm_provider_credentials(), timeout_seconds=45,
            reasoning_effort="low", diagnostics_path=diagnostics_path, max_output_tokens=256)
        try:
            client.complete_model(output_model=LLMProbeResult,
                system_prompt="Return status ready and note ok.",
                user_payload={"purpose": "Juice Shop generation/authentication preflight"},
                operation="juice_shop_preflight")
            generation = {"status": "validated", "model": "nsu:qwen3.8-flash-next",
                "calls": len(client.last_attempts)}
        except (RuntimeError, ValueError, TypeError) as exc:
            generation = {"status": "failed", "model": "nsu:qwen3.8-flash-next",
                "calls": len(client.last_attempts), "reason": redact_error_message(exc),
                "attempts": [{"route": row.route, "status": row.status,
                    "error": redact_error_message(row.error) if row.error else None}
                    for row in client.last_attempts]}
    warnings = []
    if catalog_reproducibility["status"] != "reproducible":
        warnings.append("Current A02 candidate extractor differs from its frozen output; changed fields are summarized separately, while A04 lock and target snapshot are validated independently.")
    status = "blocked" if generation["status"] == "failed" else "ready_with_warnings" if warnings else "ready"
    return {"status": status, "target": target,
        "benchmark": benchmark, "candidate_catalog_reproducibility": catalog_reproducibility,
        "warnings": warnings,
        "scan_profile": {"id": scan_profile["id"], "version": scan_profile["version"],
            "semgrep_version": semgrep_version, "profile_sha256": scan_profile["profile_sha256"],
            "config_sha256": scan_profile["config_sha256"]},
        "verification_profiles": [{"id": profile.id, "routes": len(profile.verification_routes)}
            for profile in verification_profiles],
        "images": images, "generation": generation,
        "model_labels_received": False, "target_checks_started": False}


def run(checkout, image, browser_image, output, *, campaign_limits=None, question_limits=None,
        verification_only=False):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("One new R09 output; never overwrite or silently restart")
    started = time.monotonic()
    try:
        return _run(checkout, image, browser_image, output,
                    campaign_limits=campaign_limits, question_limits=question_limits,
                    verification_only=verification_only)
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


def _run(checkout, image, browser_image, output, *, campaign_limits=None, question_limits=None,
         verification_only=False):
    checkout, output = Path(checkout).resolve(), Path(output).resolve()
    active_limits = campaign_limits or limits()
    if output.exists():
        raise FileExistsError("One new R09 output; never overwrite or silently restart")
    output.mkdir(parents=True)
    started = time.monotonic()
    run_state = {"phase": "preflight", "cleanup_verified": True}
    write_json(output / "run-state.json", run_state)
    checked = preflight(checkout, image, browser_image, probe_model=not verification_only,
                        diagnostics_path=output / "llm-attempts.jsonl")
    before = checked["target"]
    write_json(output / "preflight.json", checked)
    run_state.update({"target": before, "preflight": checked["status"]})
    write_json(output / "run-state.json", run_state)
    if not verification_only and checked["generation"]["status"] != "validated":
        raise RuntimeError("Juice Shop run stopped: configured Qwen generation preflight failed")
    run_state.update({"target": before, "preflight": "passed",
                      "engine": "fixed_verification_only" if verification_only else "research_and_fixed_verification"})
    write_json(output / "run-state.json", run_state)
    run_state["phase"] = "sast"
    write_json(output / "run-state.json", run_state)
    scan_profile = load_scan_profile(SCAN_PROFILE)
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
        from discovery.service import ProjectDiscovery
        from pipeline.juice_source_detectors import detect_juice_source_candidates
        from tools.repository_source import RepositorySource

        source_detector_findings = detect_juice_source_candidates(profile,
            RepositorySource(ProjectDiscovery().discover(checkout), research_mode=True))
        write_json(output / "source-detectors/findings.json",
                   [f.model_dump(mode="json") for f in source_detector_findings])
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
                for base in ("agent", "app", "schemas", "security", "executor", "pipeline", "tools", "evidence", "validator", "reporting", "sast", "discovery")
                for p in sorted((ROOT / base).rglob("*.py"))},
            "preflight": checked, "target_image":IMAGE, "research_image":image, "browser_image":browser_image,
            "engine": "fixed_verification_only" if verification_only else "research_and_fixed_verification",
            "model": None if verification_only else "nsu:qwen3.8-flash-next",
            "model_output_tokens": 0 if verification_only else 8192, "repetitions":1,
            "campaign_limits":active_limits.model_dump(), "research_limits":research_limits.model_dump(),
            "selection":"All fresh SAST observations; no family representatives or preferred proof families",
            "fresh_sast_observations":len(scan.findings), "fresh_dast":False,
            "source_detector_enabled": True, "source_detector_findings": len(source_detector_findings),
            "runtime_scope":"anonymous read-only model research plus fixed B01 SQL/login, B05 own-read, basket insert, review-owner, NoSQL review-selector, whoami private-field and feedback-attribution, B06 redirect/re-auth, and registered Juice role-registration/anonymous-product-put protocols; model has no fixture credentials or arbitrary fixture actions",
            "operator_grants":config["http_grants"], "evaluator_labels_provided_to_model":False,
            "canonical_verification_profiles":list(VERIFICATION_PROFILE_PATHS),
            "canonical_fixture_grants":[grant.model_dump() for grant in FIXTURE_GRANTS],
            "canonical_verification_grants":[grant.model_dump() for grant in VERIFICATION_GRANTS],
            "canonical_verification_worker_image":WORKER_IMAGE,
            "incremental_proof_http_reservation_per_check":114,
            "canonical_verification_scope":"B01 SQL/directory/login, explicitly granted B05 own-read/basket-insert/review-owner/NoSQL-selector/whoami-private-fields/feedback-attribution, B06 redirect/re-auth, and registered Juice role-registration/anonymous-product-put; each protocol remains source-bound and independently validated",
            "full_benchmark_measurement":False, "mttr":"not_measured", "reproducibility":"not_measured"}
        write_json(output / "run-manifest.json", manifest)
        print(json.dumps({"phase":"campaign_started", "sast_observations":len(scan.findings),
                          "max_wall_seconds":active_limits.wall_seconds, "model":manifest["model"]}), flush=True)
        run_state.update({"phase": "campaign", "campaign_started_at": datetime.now(UTC).isoformat(),
                          "preparation_seconds": round(time.monotonic() - started, 3)})
        write_json(output / "run-state.json", run_state)
        verification_profiles = tuple(TargetProfile.from_yaml(ROOT / relative,
            repository_path_override=checkout) for relative in VERIFICATION_PROFILE_PATHS)
        client = None
        if not verification_only:
            client = ProviderFailoverClient(
                routes=parse_route_specs("nsu:qwen3.8-flash-next", allow_external_fallbacks=False),
                credentials=settings.llm_provider_credentials(), timeout_seconds=45,
                reasoning_effort="low", diagnostics_path=output / "llm-attempts.jsonl", max_output_tokens=8192)
        result = campaign(profile=profile, configuration=config, client=client,
            output=output / "campaign", sast=scan.findings, limits=active_limits, research_limits=research_limits,
            verification_profiles=verification_profiles,
            verification_worker_image=WORKER_IMAGE, fixture_grants=FIXTURE_GRANTS,
            verification_grants=VERIFICATION_GRANTS, source_detector_findings=source_detector_findings,
            verification_only=verification_only)
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
    parser.add_argument("--output", type=Path)
    parser.add_argument("--preflight-only", action="store_true",
                        help="Check pinned inputs/images and operator profiles without running SAST or research")
    parser.add_argument("--probe-model", action="store_true",
                        help="Make one small generation/authentication request to the configured Qwen route")
    parser.add_argument("--wall-seconds", type=int, default=1800, help="Campaign budget; preparation is reported separately")
    parser.add_argument("--max-questions", type=int, default=64)
    parser.add_argument("--max-http-requests", type=int, default=1024,
                        help="Explicit total campaign HTTP budget (0..2048); per-runtime limit stays 256")
    parser.add_argument("--verification-only", action="store_true",
                        help="Explicit fixed-protocol acceptance with fresh source detection; no model calls")
    args = parser.parse_args()
    if args.preflight_only:
        try:
            report = preflight(args.checkout, args.image, args.browser_image, probe_model=args.probe_model)
            print(json.dumps(report, indent=2))
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            parser.exit(1, "Juice Shop preflight failed: " + redact_observation(str(exc)) + "\n")
        if report["status"] == "blocked":
            raise SystemExit(2)
        raise SystemExit(0)
    if args.output is None:
        parser.error("--output is required unless --preflight-only is selected")
    selected_limits = CampaignLimits.model_validate({**limits(max_http_requests=args.max_http_requests).model_dump(),
        "wall_seconds": args.wall_seconds, "max_questions": args.max_questions})
    try:
        print(json.dumps(run(args.checkout, args.image, args.browser_image, args.output,
                             campaign_limits=selected_limits, verification_only=args.verification_only), indent=2))
    except (KeyboardInterrupt, RunCancelled):
        print(json.dumps({"completed": False, "stop_reason": "operator_cancelled", "output": str(args.output)}))
        raise SystemExit(130) from None
