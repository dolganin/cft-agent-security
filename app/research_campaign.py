"""R05/R06 integrated bounded campaign. No evaluator answers enter the producer."""
import json
import subprocess
import time
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from agent.budget import provider_deadline
from app.research_run import run_research
from discovery.express_routes import build_express_source_map
from discovery.service import ProjectDiscovery
from evidence.research_http_replay import replay_marker
from evidence.research_review import attach_source_review, review_source_claims
from evidence.research_scan_review import review_scanner_source_conditions
from executor.research_runtime import ResearchRuntime
from pipeline.cancellation import RunCancelled, check_cancelled
from pipeline.research_queue import ResearchQueue
from pipeline.research_verification import (
    REQUEST_RESERVATIONS,
    verification_handoff,
    verify_bound_candidate,
)
from reporting.builder import build_final_report
from reporting.checkpoints import write_json
from reporting.research_diagnostics import saved_campaign_diagnostics
from schemas.research import HttpServiceScope
from schemas.research_agent import ResearchLimits
from schemas.research_campaign import CampaignLimits
from schemas.research_fixtures import ResearchVerificationGrant
from schemas.runtime import RuntimeServiceMap
from security.error_redaction import redact_error_message
from tools.repository_source import RepositorySource


def campaign(*, profile, configuration, client, output, sast=(), dast=(), limits=None, research_limits=None,
             http_review_registry=None, acceptance_require_script=False, verification_profiles=(),
             verification_worker_image=None, fixture_grants=(), verification_grants=(),
             source_detector_findings=(), verification_only=False):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("A campaign never overwrites a saved run")
    started = time.monotonic()
    try:
        with provider_deadline(started + (limits or CampaignLimits()).wall_seconds):
            result = _campaign(profile=profile, configuration=configuration, client=client, output=output,
                sast=sast, dast=dast, limits=limits, research_limits=research_limits,
                http_review_registry=http_review_registry, acceptance_require_script=acceptance_require_script,
                verification_profiles=verification_profiles, verification_worker_image=verification_worker_image,
                fixture_grants=fixture_grants, verification_grants=verification_grants,
                source_detector_findings=source_detector_findings, verification_only=verification_only)
        write_json(output / "operational-diagnostics.json", saved_campaign_diagnostics(output))
        return result
    except (KeyboardInterrupt, RunCancelled, Exception) as exc:
        if output.is_dir():
            diagnostic = saved_campaign_diagnostics(output)
            active = json.loads((output / "active-phase.json").read_text()) if (output / "active-phase.json").exists() else {}
            write_json(output / "summary.json", {"schema": "cft.research.campaign.result.v1",
                "completed": False, "benchmark_measurement": False, "degraded": True,
                "stop_reason": "operator_cancelled" if isinstance(exc, (KeyboardInterrupt, RunCancelled)) else "campaign_failed",
                "failure_type": type(exc).__name__, "elapsed_seconds": round(time.monotonic() - started, 3),
                "questions_researched": diagnostic["questions_completed"],
                "incomplete_questions": diagnostic["incomplete_questions"],
                "model_calls": diagnostic["model_calls_completed_questions"] +
                    sum(row["model_calls"] for row in diagnostic["incomplete_questions"]),
                "canonical_runtime_review_counts": diagnostic["persisted_runtime_status_counts"],
                "cleanup_verified": active.get("phase") == "research" and bool(diagnostic["incomplete_questions"]) and
                    all(row.get("summary") and row["summary"].get("cleanup_verified")
                    for row in diagnostic["incomplete_questions"]) and all(
                        json.loads(p.read_text()).get("cleanup_verified") for p in (output / "questions").glob("*/summary.json"))})
            write_json(output / "operational-diagnostics.json", diagnostic)
        raise


def _preverify_bound_findings(*, queue, profile, configuration, output, limits,
                             verification_profiles, verification_worker_image,
                             fixture_grants, verification_grants, started):
    """Run already-supported fixed checks before spending LLM research budget."""
    if not verification_profiles or not (verification_worker_image or fixture_grants or verification_grants):
        return {}, [], 0, 0, 0, 0, False

    selected = {}
    for question in sorted((q for q in queue.questions if q.is_candidate), key=queue.priority):
        handoff = verification_handoff([question.finding], verification_profiles, profile.repository_path)
        row = handoff["checks"][0]
        if row["status"] != "ready_for_canonical_verification":
            continue
        selected.setdefault(queue.work_key(question.finding), question)
    if not selected:
        return {}, [], 0, 0, 0, 0, False

    preverification = Path(output) / "preverification"
    preverification.mkdir(parents=True, exist_ok=False)
    runtime_services = None
    if configuration.get("runtime_service_map") is not None:
        runtime_services = RuntimeServiceMap.model_validate(configuration["runtime_service_map"])
        grants = configuration.get("http_grants", configuration.get("services", {}))
        services = ResearchRuntime.services_from_runtime_map(profile, runtime_services, grants)
        network_name = runtime_services.network_name
    else:
        services = {name: HttpServiceScope.model_validate(value)
                    for name, value in configuration.get("services", {}).items()}
        network_name = configuration.get("network_name")

    runtime = ResearchRuntime(target=profile, source_files=configuration.get("source_files", sorted(queue.source_files)),
        worker_image=configuration["worker_image"], output=preverification / "scope",
        services=services, network_name=network_name, runtime_services=runtime_services,
        browser_image=configuration.get("browser_image"), timeout=configuration.get("action_timeout", 10),
        wall_seconds=limits.wall_seconds, max_actions=1,
        max_http_requests=min(256, limits.max_http_requests))
    reviews, by_key = [], {}
    actions = unknown_actions = reserved = observed = 0
    checks_directory = preverification / "checks"
    checks_directory.mkdir()
    with runtime:
        for ordinal, (key, question) in enumerate(selected.items()):
            remaining_wall = limits.wall_seconds - int(time.monotonic() - started)
            remaining_http = max(0, limits.max_http_requests - reserved)
            if remaining_wall <= 0 or actions + unknown_actions >= limits.max_actions:
                break
            try:
                review = verify_bound_candidate(finding=question.finding, profiles=verification_profiles,
                    scope=runtime.scope, repository=profile.repository_path,
                    output=checks_directory / str(ordinal), max_http_requests=remaining_http,
                    worker_image=verification_worker_image or "python@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7",
                    fixture_grants=fixture_grants, verification_grants=verification_grants,
                    remaining_wall_seconds=remaining_wall)
            except (OSError, ValueError, RuntimeError, TypeError, KeyError, IndexError,
                    AssertionError, subprocess.SubprocessError) as exc:
                review = {"finding_id": question.finding.id, "status": "inconclusive",
                    "executed": None, "actions": 1, "requests_reserved": min(4, remaining_http),
                    "worker_cleanup_verified": False, "reason": redact_error_message(exc)}
            review["job_finding_ids"] = _job_finding_ids(queue, key)
            review.setdefault("finding_id", question.finding.id)
            review.setdefault("executed", False)
            review.setdefault("actions", 0)
            review.setdefault("requests_reserved", 0)
            reserved += int(review["requests_reserved"])
            observed += int(review.get("requests_observed", 0))
            if review["executed"] is True:
                actions += int(review.get("actions", 0))
            elif review["executed"] is None:
                unknown_actions += int(review.get("actions", 0))
            by_key[key] = review
            reviews.append(review)
            write_json(checks_directory / f"{ordinal}-result.json", review)
            write_json(preverification / "canonical-runtime-reviews.json", reviews)
            if review["status"] in {"confirmed", "rejected"}:
                queue.complete(question)
            if review.get("worker_cleanup_verified") is False:
                break
    fatal = any(review.get("worker_cleanup_verified") is False for review in reviews)
    return by_key, reviews, actions, unknown_actions, reserved, observed, fatal


def _preverified_terminal_reports(queue, preverified):
    """Emit one report for the exact representative; grouped observations inherit none."""
    reports = []
    for question in queue.questions:
        if not question.is_candidate or question.status == "grouped":
            continue
        key = queue.work_key(question.finding)
        review = preverified.get(key)
        if not review or review.get("status") not in {"confirmed", "rejected"}:
            continue
        report = review.get("report")
        if not isinstance(report, dict) or report.get("finding_id") != question.id:
            raise ValueError("Pre-verification report does not bind the exact finding")
        reports.append({"question_id": question.id, "is_candidate": True,
                        "report": report, "canonical_runtime_review": review})
    return reports


def _job_finding_ids(queue, key):
    """Keep all exact-sink scanner observations attached to one proof job."""
    return sorted(question.id for question in queue.questions
                  if question.is_candidate and queue.work_key(question.finding) == key)


def _campaign(*, profile, configuration, client, output, sast=(), dast=(), limits=None, research_limits=None,
              http_review_registry=None, acceptance_require_script=False, verification_profiles=(),
              verification_worker_image=None, fixture_grants=(), verification_grants=(),
              source_detector_findings=(), verification_only=False):
    from schemas.research_fixtures import ResearchFixtureGrant, ResearchVerificationGrant

    limits, research_limits = limits or CampaignLimits(), research_limits or ResearchLimits(max_steps=8)
    fixture_grants = tuple(ResearchFixtureGrant.model_validate(grant) for grant in fixture_grants)
    if len({grant.protocol for grant in fixture_grants}) != len(fixture_grants):
        raise ValueError("Duplicate private fixture protocol grant")
    verification_grants = tuple(ResearchVerificationGrant.model_validate(grant) for grant in verification_grants)
    if len({grant.protocol for grant in verification_grants}) != len(verification_grants):
        raise ValueError("Duplicate fixed verification grant")
    output = Path(output).resolve()
    verification_handoff([], verification_profiles, profile.repository_path)
    if output.exists():
        raise FileExistsError("A campaign never overwrites a saved run")
    started = time.monotonic()
    output.mkdir(parents=True)
    inventory = ProjectDiscovery().discover(profile.repository_path)
    source = RepositorySource(inventory, research_mode=True)
    source_map = build_express_source_map(inventory, include_oracle_controllers=False,
                                          include_vulnerability_regions=False)
    files = configuration.get("source_files", list(source.files))
    files = [p for p in files if p in source.files]
    if not files:
        raise ValueError("No approved application source")
    configuration = {**configuration, "source_files": files}
    verification_paths = set()
    fixture_routes = []
    if verification_worker_image or fixture_grants or verification_grants:
        grants = configuration.get("http_grants", configuration.get("services", {}))
        for operator_profile in verification_profiles:
            for route in operator_profile.verification_routes:
                grant = grants.get(route.service, {})
                if (route.tool in REQUEST_RESERVATIONS and route.method == "GET" and
                        any(route.endpoint == prefix.rstrip("/") or route.endpoint.startswith(prefix.rstrip("/") + "/")
                            for prefix in grant.get("read_prefixes", []))):
                    verification_paths.update(source.file for source in route.sources)
                from pipeline.research_fixture_verification import PROTOCOLS

                for fixture_grant in fixture_grants:
                    target, selection, _, family = PROTOCOLS[fixture_grant.protocol]
                    if target == operator_profile.id and ((family == "b05" and route.tool == "verify_access_control" and route.id == selection) or
                            (family == "b06" and route.tool == selection)):
                        verification_paths.update(source.file for source in route.sources)
                        fixture_routes.append({"protocol": fixture_grant.protocol, "profile_id": target,
                            "route_id": route.id, "family": route.family, "endpoint": route.endpoint,
                            "source_files": [source.file for source in route.sources],
                            "operator_bound_protocol": True, "is_evidence": False})
        for verification_grant in verification_grants:
            for operator_profile in verification_profiles:
                if (verification_grant.protocol != "b01.login-sql.v1"
                        or operator_profile.id != "juice-verification"):
                    continue
                route = next((item for item in operator_profile.verification_routes
                              if item.id == verification_grant.route_id
                              and item.tool == "verify_sql_injection"
                              and item.method == "POST"
                              and item.endpoint == "/rest/user/login"
                              and item.mode == "authentication"), None)
                if route is not None:
                    verification_paths.update(source.file for source in route.sources)
    queue = ResearchQueue(profile=profile, source_map=source_map, source_files=files,
                          preferred_families=limits.dev_preferred_families, verification_paths=verification_paths,
                          verification_profiles=verification_profiles)
    http_review_registry = http_review_registry or {}
    queue.import_findings(sast, "sast")
    queue.import_findings(dast, "dast")
    queue.import_findings(source_detector_findings, "source_detector")
    fixed_source_review = review_scanner_source_conditions(root=profile.repository_path,
        findings=queue.findings, output=output / "source-condition-reviews")
    write_json(output / "questions.json", [q.model_dump(mode="json") for q in queue.questions])
    write_json(output / "findings.json", [f.model_dump(mode="json") for f in queue.findings])
    write_json(output / "raw-observations.json", queue.raw)
    write_json(output / "surface-map.json", source_map.model_dump(mode="json"))
    write_json(output / "manifest.json", {"schema": "cft.research.campaign.v1",
        "started_at": datetime.now(UTC).isoformat(), "limits": limits.model_dump(),
        "research_limits": research_limits.model_dump(), "source_files": files,
        "engine": "fixed_verification_only" if verification_only else "research_and_fixed_verification",
        "source_inventory_exclusions": source.skipped,
        "source_sha256": {p: sha256((profile.repository_path / p).read_bytes()).hexdigest() for p in files},
        "source_review_protocols": ["weak_digest_call.v1"],
        "source_review_scope": "source condition only; not runtime exploitability",
        "fixed_source_condition_reviews": {"artifact": "source-condition-reviews/reviews.json",
            "scope": "source_condition_only", "changes_runtime_verdicts": False},
        "canonical_verification_profiles": [p.model_dump(mode="json") for p in verification_profiles],
        "canonical_verification_worker_image": verification_worker_image,
        "canonical_fixture_grants": [grant.model_dump(mode="json") for grant in fixture_grants],
        "canonical_verification_grants": [grant.model_dump(mode="json") for grant in verification_grants],
        "http_review_protocols": [spec.public() for spec, _ in http_review_registry.values()],
        "http_review_status": "enabled" if http_review_registry else "requires private operator-owned marker registry/factory",
        "benchmark_measurement": False, "repetitions": 1, "reproducibility": "not_measured"})
    calls = actions = http_requests = 0
    unknown_action_reservations = 0
    verification_http_reserved = 0
    verification_http_observed = 0
    runtime_reviews = []
    model_io = observation_bytes = write_bytes = 0
    ledgers, reports, reviews, runs = [], [], [], []
    stop = "queue_exhausted"
    failures = []
    question_failures = []
    consecutive_failures = 0
    stage_seconds = {"research": 0.0, "source_review": 0.0, "canonical_verification": 0.0}
    preverification_started = time.monotonic()
    preverified, pre_reviews, pre_actions, pre_unknown_actions, pre_reserved, pre_observed, pre_fatal = (
        _preverify_bound_findings(queue=queue, profile=profile, configuration=configuration, output=output,
            limits=limits, verification_profiles=verification_profiles,
            verification_worker_image=verification_worker_image, fixture_grants=fixture_grants,
            verification_grants=verification_grants, started=started))
    runtime_reviews.extend(pre_reviews)
    stage_seconds["canonical_verification"] += time.monotonic() - preverification_started
    actions += pre_actions
    unknown_action_reservations += pre_unknown_actions
    verification_http_reserved += pre_reserved
    verification_http_observed += pre_observed
    write_json(output / "questions.json", [q.model_dump(mode="json") for q in queue.questions])
    write_json(output / "findings.json", [f.model_dump(mode="json") for f in queue.findings])
    write_json(output / "canonical-runtime-reviews.json", runtime_reviews)
    reports.extend(_preverified_terminal_reports(queue, preverified))
    if pre_fatal:
        stop = "cleanup_unverified"
    for ordinal in range(limits.max_questions):
        if stop == "cleanup_unverified":
            break
        if verification_only:
            stop = "fixed_verification_only"
            break
        check_cancelled()
        remaining_wall = int(limits.wall_seconds - (time.monotonic() - started))
        remaining_calls = limits.max_model_calls - calls
        remaining_actions = limits.max_actions - actions - unknown_action_reservations
        remaining_io = limits.max_model_io_bytes - model_io
        remaining_observation = limits.max_observation_bytes - observation_bytes
        if min(remaining_wall, remaining_calls, remaining_actions) < 1 or remaining_io < 4096 or remaining_observation < 65536:
            stop = "campaign_budget_exhausted"
            break
        question = queue.next_question()
        if question is None:
            break
        related = source_map.for_context({question.finding.file}, limit=12)
        related["related_observations"] = queue.related_observations(question)
        related["source_priority_index"] = [p for p in files if p.startswith(("routes/", "lib/", "models/"))][:48]
        related["http_proof_specs"] = [spec.public() for spec, _ in http_review_registry.values()]
        # Only bounded navigation metadata crosses question sessions; old observations
        # cannot be cited as current-session Evidence or approval provenance.
        related["campaign_memory"] = {
            "previous_questions": [{"id": r["question_id"], "stop_reason": r["summary"].get("stop_reason"),
                                    "interpretation": r.get("interpretation"), "uncertainties": r.get("uncertainties", [])}
                                   for r in runs[-4:]],
            "previous_reads": [{"path": item.observation.get("path"),
                                "line_start": item.observation.get("line_start"),
                                "line_end": item.observation.get("line_end")}
                               for ledger in ledgers for item in ledger
                               if item.tool == "read_source" and item.category == "observation"][-64:],
            "known_candidates": [{"file": f.file, "line_start": f.line_start, "rule_id": f.rule_id}
                                 for f in queue.findings[:64]],
            "provenance": "navigation_only; re-read before new claims"}
        related["verification_availability"] = {
            "source_protocols": ["weak_digest_call.v1"],
            "http_protocols": [spec.public() for spec, _ in http_review_registry.values()],
            "legacy_b_verifiers_connected": bool(verification_profiles and verification_worker_image),
            "private_fixture_protocols_connected": [grant.protocol for grant in fixture_grants],
            "private_fixture_routes": fixture_routes,
            "unsupported_claims": "retain as pending; never infer rejected from missing verification"}
        if acceptance_require_script:
            related["dev_acceptance_objective"] = "Demonstrate a self-authored Python/Node source-inspection script and an ordinary non-mutating allowed target_http observation before finishing. Script stdout and a successful HTTP response are NOT security verdicts. Use read/write/run tools, not host execution."
        scoped_limits = research_limits.model_copy(update={
            "max_steps": min(research_limits.max_steps, remaining_actions),
            "max_model_calls": min(research_limits.max_model_calls, remaining_calls),
            "max_model_io_bytes": min(research_limits.max_model_io_bytes, remaining_io),
            "max_observation_bytes": min(research_limits.max_observation_bytes, remaining_observation),
            "max_write_bytes": max(0, min(research_limits.max_write_bytes, limits.max_write_bytes - write_bytes)),
            "wall_seconds": min(research_limits.wall_seconds, remaining_wall)})
        directory = output / "questions" / str(ordinal)
        write_json(output / "active-phase.json", {"phase": "research", "question": str(ordinal), "finding_id": question.id})
        question_config = {**configuration, "max_http_requests": min(
            256,
            configuration.get("max_http_requests", 128 if configuration.get("browser_image") else 32),
            max(0, limits.max_http_requests - http_requests - verification_http_reserved))}
        stage_started = time.monotonic()
        state, summary = run_research(profile=profile, configuration=question_config, finding=question.finding,
            client=client, output=directory, limits=scoped_limits, surface_context=related)
        stage_seconds["research"] += time.monotonic() - stage_started
        write_json(output / "timings.json", stage_seconds)
        write_json(output / "active-phase.json", {"phase": "source_review", "question": str(ordinal)})
        stage_started = time.monotonic()
        progress, scope = state["research_progress"], state["research_scope"]
        calls += summary["model_calls"]
        actions += summary["actions"]
        http_requests += summary.get("http_requests", 0)
        model_io += progress.model_io_bytes
        observation_bytes += progress.observation_bytes
        write_bytes += progress.write_bytes
        ledgers.append(progress.ledger)
        queue.complete(question, failed=bool(state.get("workflow_errors")) or
                       state.get("stop_reason") in {"proposal_corrections_exhausted", "repeated_action"})
        queue.import_candidates(progress.candidates)
        independent = review_source_claims(root=profile.repository_path, scope=scope,
            progress=progress, output=output / "reviews" / str(ordinal))
        reviews.extend(independent)
        for claim in progress.http_claims:
            spec, factory = http_review_registry[claim.spec_id]
            original_reads = {item.action_id: item for item in progress.ledger}
            if any(original_reads[ref].observation.get("path") != spec.probe_path for ref in claim.observation_refs):
                reviews.append({"status": "review_pending", "reason": "Claim references a different HTTP observation"})
                continue
            reviews.append(replay_marker(claim=claim, spec=spec, generation_factory=factory,
                output=output / "http-reviews" / f"{ordinal}-{len(reviews)}",
                original_container_ids=[service.container_id for service in scope.services.values()],
                source_snapshot=scope.source_snapshot, image_ids={spec.service: scope.services[spec.service].image_id}))
        state = attach_source_review(state, independent, output / "reviews" / str(ordinal))
        report = build_final_report(state)
        reports.append({"question_id": question.id, "is_candidate": question.is_candidate,
                        "report": report.model_dump(mode="json")})
        stage_seconds["source_review"] += time.monotonic() - stage_started
        stage_started = time.monotonic()
        write_json(output / "active-phase.json", {"phase": "canonical_verification", "question": str(ordinal)})
        verification_key = queue.work_key(question.finding)
        runtime_review = preverified.get(verification_key)
        if (runtime_review is None and verification_profiles and
                (verification_worker_image or fixture_grants or verification_grants)
                and summary["cleanup_verified"]
                and actions + unknown_action_reservations < limits.max_actions
                and time.monotonic() - started + 30 < limits.wall_seconds):
            try:
                runtime_review = verify_bound_candidate(finding=question.finding,
                    profiles=verification_profiles, scope=scope, repository=profile.repository_path,
                    output=output / "canonical-verification" / str(ordinal),
                    max_http_requests=max(0, limits.max_http_requests - http_requests - verification_http_reserved),
                    worker_image=verification_worker_image or "python@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7",
                    fixture_grants=fixture_grants,
                    verification_grants=verification_grants,
                    remaining_wall_seconds=max(0, limits.wall_seconds - int(time.monotonic() - started)))
            except RunCancelled:
                raise
            except (OSError, ValueError, RuntimeError, TypeError, KeyError, IndexError,
                    AssertionError, subprocess.SubprocessError) as exc:
                # Unknown transport/cleanup must never leave a terminal security
                # verdict. Conservatively reserve the maximal fixed protocol cost.
                max_reserved = max([4, *(int(g.max_http_requests) for g in fixture_grants)], default=4)
                runtime_review = {"finding_id": question.finding.id, "status": "inconclusive",
                    "executed": None, "actions": 1, "requests_reserved": min(max_reserved,
                        max(0, limits.max_http_requests - http_requests - verification_http_reserved)),
                    "worker_cleanup_verified": False, "reason": redact_error_message(exc)}
            runtime_review["job_finding_ids"] = _job_finding_ids(queue, verification_key)
            runtime_reviews.append(runtime_review)
            preverified[verification_key] = runtime_review
            if runtime_review.get("executed") is None:
                unknown_action_reservations += runtime_review.get("actions", 0)
            else:
                actions += runtime_review.get("actions", 0)
            verification_http_reserved += runtime_review.get("requests_reserved", 0)
            verification_http_observed += runtime_review.get("requests_observed", 0)
            # Preserve research history while publishing the independently guarded
            # terminal report for this exact finding, never an unrelated candidate.
            reports[-1]["canonical_runtime_review"] = runtime_review
            if runtime_review["status"] in {"confirmed", "rejected"}:
                reports[-1]["research_report"] = reports[-1]["report"]
                reports[-1]["report"] = {**runtime_review["report"],
                    "workflow_errors": reports[-1]["research_report"].get("workflow_errors", []) +
                                       runtime_review["report"].get("workflow_errors", [])}
            write_json(output / "canonical-runtime-reviews.json", runtime_reviews)
        elif runtime_review is not None:
            reports[-1]["canonical_runtime_review"] = runtime_review
            if runtime_review.get("status") in {"confirmed", "rejected"}:
                reports[-1]["research_report"] = reports[-1]["report"]
                reports[-1]["report"] = runtime_review["report"]
        stage_seconds["canonical_verification"] += time.monotonic() - stage_started
        write_json(output / "timings.json", stage_seconds)
        write_json(output / "active-phase.json", {"phase": "checkpoint", "question": str(ordinal)})
        # A new cause discovered during another question owns its own report;
        # don't attribute a crypto proof to the original unrelated SAST finding.
        already_reported = {r["report"]["finding_id"] for r in reports}
        for finding in queue.findings:
            if finding.id in already_reported:
                continue
            derived = attach_source_review({**state, "finding": finding, "status": "inconclusive",
                "cvss": None, "context_priority": None, "technical_severity": None,
                "scoring_review": None, "scoring_review_resolution": None}, independent, output / "reviews" / str(ordinal))
            if derived["status"] not in {"confirmed", "rejected"}:
                continue
            derived_report = build_final_report(derived)
            reports.append({"question_id": finding.id, "is_candidate": True,
                "discovered_during": question.id, "report": derived_report.model_dump(mode="json")})
            related_question = next((q for q in queue.questions if q.id == finding.id), None)
            if related_question is not None:
                queue.complete(related_question)
        last_turn = progress.turns[-1] if progress.turns else None
        runs.append({"question_id": question.id, "summary": summary,
                     "interpretation": last_turn.summary[:800] if last_turn else None,
                     "uncertainties": [s[:200] for s in last_turn.uncertainties[:3]] if last_turn else []})
        write_json(output / "checkpoint.json", {"completed": False, "runs": runs,
            "elapsed_seconds": round(time.monotonic() - started, 3)})
        write_json(output / "verification-backlog.json", [{
            "finding_id": row["report"]["finding_id"], "status": row["report"]["status"],
            "reason": "No sufficient independent protocol Evidence; not a safe verdict"}
            for row in reports if row["report"]["status"] in {"inconclusive", "policy_blocked"}])
        write_json(output / "canonical-verification-handoff.json",
                   verification_handoff(queue.findings, verification_profiles, profile.repository_path))
        write_json(output / "questions.json", [q.model_dump(mode="json") for q in queue.questions])
        write_json(output / "raw-observations.json", queue.raw)
        write_json(output / "findings.json", [f.model_dump(mode="json") for f in queue.findings])
        write_json(output / "reports.json", reports)
        write_json(output / "reviews.json", reviews)
        write_json(output / "coverage.json", queue.coverage(ledgers))
        if state.get("stop_reason") in {"proposal_corrections_exhausted", "repeated_action"}:
            question_failures.append({"question_id": question.id, "reason": state["stop_reason"],
                                      "proposal_feedback": progress.proposal_feedback})
            write_json(output / "question-failures.json", question_failures)
        # Lost cleanup is fatal regardless of which node/result stopped the question.
        if (not summary["cleanup_verified"] or any(
                r.get("worker_cleanup_verified") is False for r in runtime_reviews)):
            stop = "cleanup_unverified"
            break
        if state.get("stop_reason") == "model_failure":
            consecutive_failures += 1
            failure = {"question_id": question.id, "category": progress.provider_failure_status or "local_model_contract",
                       "diagnostic": progress.model_diagnostic,
                       "validation_errors": progress.model_validation_errors}
            failures.append(failure)
            write_json(output / "model-failures.json", failures)
            if failure["category"] in {"auth_or_access", "payment_required", "rate_limited", "model_or_endpoint_unavailable"}:
                stop = "provider_unavailable"
                break
            if consecutive_failures >= limits.max_consecutive_model_failures:
                stop = "consecutive_model_failures"
                break
        else:
            consecutive_failures = 0
    else:
        stop = "question_budget_exhausted"
    manifest = json.loads((output / "manifest.json").read_text())
    integrity = all(sha256((profile.repository_path / p).read_bytes()).hexdigest() == digest
                    for p, digest in manifest["source_sha256"].items())
    summary = {"schema": "cft.research.campaign.result.v1", "completed": True, "runs": runs,
        "timing_seconds": stage_seconds,
        "model_calls": calls, "actions": actions, "questions_researched": len(runs),
        "actions_execution_unknown": unknown_action_reservations,
        "action_budget_used": actions + unknown_action_reservations,
        "http_requests": http_requests,
        "canonical_verification_http_requests_reserved": verification_http_reserved,
        "canonical_verification_http_requests_observed": verification_http_observed,
        "http_request_budget_used": http_requests + verification_http_reserved,
        "canonical_runtime_reviews": [{"finding_id": r["finding_id"], "status": r["status"],
                                       "executed": r["executed"]} for r in runtime_reviews],
        "canonical_runtime_review_counts": {status: sum(r["status"] == status for r in runtime_reviews)
                                            for status in ("confirmed", "rejected", "inconclusive", "review_pending")},
        "model_io_reserved_bytes": model_io, "observation_bytes": observation_bytes, "write_bytes": write_bytes,
        "candidate_count": len(queue.findings), "review_counts": {status: sum(r["status"] == status for r in reviews)
            for status in ("confirmed", "rejected", "review_pending")},
        "fixed_source_condition_review_counts": {status: sum(
            row["review"].get("status") == status for row in fixed_source_review["reviews"])
            for status in ("confirmed", "rejected", "review_pending")},
        "stop_reason": stop, "source_unchanged": integrity,
        "model_failures": failures, "question_failures": question_failures,
        "degraded": bool(failures or question_failures or stop == "cleanup_unverified"),
        "cleanup_verified": all(r["summary"]["cleanup_verified"] for r in runs) and
                            not any(r.get("worker_cleanup_verified") is False for r in runtime_reviews),
        "elapsed_seconds": round(time.monotonic() - started, 3), "benchmark_measurement": False,
        "source_confirmations_are_not_runtime_exploits": True}
    write_json(output / "summary.json", summary)
    # Early fixed verification can finish before any research question executes.
    # Its reports and the empty research-review stream must still be portable.
    write_json(output / "reports.json", reports)
    write_json(output / "reviews.json", reviews)
    write_json(output / "canonical-verification-handoff.json",
               verification_handoff(queue.findings, verification_profiles, profile.repository_path))
    write_json(output / "active-phase.json", {"phase": "finished"})
    write_json(output / "rejected-inputs.json", queue.rejections)
    write_json(output / "coverage.json", queue.coverage(ledgers))
    if not integrity:
        raise RuntimeError("Campaign source integrity changed; result invalid")
    return summary


def main():
    import argparse

    from agent.llm_model import FallbackLLMAgentModel
    from app.config import settings
    from schemas.finding import Finding
    from schemas.research_campaign import RuntimeScannerObservation
    from schemas.target import TargetProfile

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--operator-config", type=Path, required=True)
    parser.add_argument("--sast", type=Path)
    parser.add_argument("--dast", type=Path)
    parser.add_argument("--limits", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--verification-profile", type=Path, action="append", default=[],
                        help="Operator profile for a source-bound handoff; does not execute new checks")
    parser.add_argument("--verification-worker-image", help="Enable fixed SQL/directory review using this immutable Docker image")
    parser.add_argument("--fixture-grant", choices=("b05.own-read.v1", "b05.basket-insert.v1",
                        "b06.redirect.v1", "b06.password-reauth.v1"),
                        action="append", default=[], help="Explicit operator permission for one closed private fixture protocol")
    parser.add_argument("--verification-grant", choices=("b01.login-sql.v1",), action="append", default=[],
                        help="Explicit grant for a fixed canonical verification protocol; does not enable model HTTP")
    args = parser.parse_args()
    client = FallbackLLMAgentModel.from_settings(settings).client
    if len(client.routes) != 1:
        raise ValueError("Select one explicit model route for a bounded campaign")
    profile = TargetProfile.from_yaml(args.profile, repository_path_override=args.checkout)
    sast = [Finding.model_validate(x) for x in json.loads(args.sast.read_text())] if args.sast else []
    dast = [(RuntimeScannerObservation if "endpoint" in x else Finding).model_validate(x)
            for x in json.loads(args.dast.read_text())] if args.dast else []
    limits = CampaignLimits.model_validate(json.loads(args.limits.read_text())) if args.limits else CampaignLimits()
    from schemas.research_fixtures import ResearchFixtureGrant
    print(json.dumps(campaign(profile=profile, configuration=json.loads(args.operator_config.read_text()),
        client=client, output=args.output, sast=sast, dast=dast, limits=limits,
        verification_profiles=tuple(TargetProfile.from_yaml(p, repository_path_override=args.checkout)
                                    for p in args.verification_profile),
        verification_worker_image=args.verification_worker_image,
        fixture_grants=tuple(ResearchFixtureGrant(protocol=item, max_http_requests={
            "b05.own-read.v1": 238, "b05.basket-insert.v1": 238,
            "b06.redirect.v1": 38, "b06.password-reauth.v1": 194}[item])
            for item in args.fixture_grant),
        verification_grants=tuple(ResearchVerificationGrant(protocol=item, route_id="juice-login")
                                  for item in args.verification_grant)), indent=2))


if __name__ == "__main__":
    main()
