"""Closed operator-only B05/B06 fixture bridge for bounded research campaigns."""
from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from agent.verification import register_source_artifacts, verification_candidates
from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.access_control import AccessVerificationRuntime
from executor.access_fixture import WORKER_IMAGE
from executor.approvals import InMemoryApprovalStore
from executor.b06_runtime import B06Runtime
from executor.executor import SafeExecutor
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_policy import SandboxLimits, SandboxPolicy
from executor.targets import TargetRegistry
from pipeline.research_verification import read_protocol_execution
from reporting.builder import build_final_report
from schemas.action import ActionProposal
from schemas.agent_loop import AgentActionRecord
from security.access_verification import ACCESS_CHECKS
from security.verification_binding import resolve_binding
from validator.validator import PolicyValidator

ROOT = Path(__file__).resolve().parents[1]
PROTOCOLS = {
    "b05.own-read.v1": ("juice-access-fixture", "juice-basket-own-read", 238, "b05"),
    "b05.basket-insert.v1": ("juice-access-fixture", "juice-basket-insert-owner-check", 238, "b05"),
    "b06.redirect.v1": ("juice-b06-verification", "verify_redirect_destination", 38, "b06"),
    "b06.password-reauth.v1": ("juice-b06-verification", "verify_auth_reauthentication", 194, "b06"),
}


def _source_matches(binding, scope):
    return bool(binding and binding.source_files and all(
        path in scope.source_files and scope.source_files[path].original_sha256 == digest
        for path, digest in binding.source_files.items()))


def _grant_for(profile, finding, grants):
    for grant in grants:
        target, selection, _, family = PROTOCOLS[grant.protocol]
        if profile.id != target:
            continue
        resolution = resolve_binding(profile, finding)
        route = next((item for item in profile.verification_routes
                      if resolution.binding and item.id == resolution.binding.route_id), None)
        if route is None:
            continue
        if family == "b05" and (route.tool != "verify_access_control" or route.id != selection):
            continue
        if family == "b06" and route.tool != selection:
            continue
        return grant, route
    return None, None


def _b05(*, finding, profile, route, scope, output, worker_image, wall_seconds,
         request_reservation):
    from security.verification_binding import resolve_binding

    resolution = resolve_binding(profile, finding)
    binding = resolution.binding
    if binding is None or binding.route_id != route.id or not _source_matches(binding, scope):
        return None
    registration = next((item for item in ACCESS_CHECKS.values() if item.route_id == route.id), None)
    if registration is None:
        return None
    action = ActionProposal(id="research-b05-" + uuid4().hex, tool="verify_access_control",
        target=profile.id, environment="sandbox", parameters={"check_id": registration.check_id},
        purpose="Operator-authorized fixed own-read verification", expected_evidence="Two-generation identity-bound B05 trace",
        service=binding.service, endpoint=registration.endpoint,
        verification_binding=binding)
    validator = PolicyValidator.from_yaml(ROOT / "policies/default.yaml", target_profile=profile,
        capability_policy_file=ROOT / "policies/b05-access.yaml")
    validation = validator.validate(action)
    if not validation.approved:
        return {"status": "review_pending", "reason": "Canonical Validator denied B05 protocol",
                "executed": False, "actions": 0, "requests_reserved": 0}
    output.mkdir(parents=True, exist_ok=False)
    runtime = AccessVerificationRuntime(profile=profile, target_repository=profile.repository_path,
        output_directory=output, active_check_id=registration.check_id, max_readiness_attempts=16,
        wall_time_budget_seconds=wall_seconds)
    try:
        runtime.prepare()
        services = runtime.runtime_services()
    except Exception:
        if not runtime.lab.close():
            raise RuntimeError("B05 fixture cleanup could not be verified after preparation")
        raise
    approvals = InMemoryApprovalStore()
    approvals.record(action, validation)
    store = JsonExecutionEvidenceStore(output / "execution")
    audit = JsonlAuditLog(output / "audit.jsonl")
    policy = SandboxPolicy(backend="docker", sandbox_image=worker_image, network_mode="none",
        limits=SandboxLimits(wall_time_seconds=20, cpu_time_seconds=5, max_output_bytes=65536))
    executor = SafeExecutor(approvals=approvals, targets=TargetRegistry([profile]), evidence_store=store,
        audit_log=audit, sandbox=DockerSandbox(policy), run_limiter=RunLimiter(1, 1), policy=policy)
    executor.bind_access_verifier(runtime)
    cleanup = False
    try:
        execution = executor.execute_sequence([action], runtime_services=services).results[0].execution
        record = read_protocol_execution(store, audit, action, execution, runtime.run_session_id)
        evidence = build_evidence(action=action, execution=execution, record=record, evidence_loaded=True,
            artifact_refs=execution.artifacts, hypothesis_id=finding.id,
            sandbox_session_id=runtime.run_session_id)
        trace = evidence.observation.facts.get("b05_trace", {})
        requests = 0
        last_control_by_generation = {}
        for item in runtime.lab.records:
            phase, generation = item.get("phase"), item.get("generation")
            context = item.get("context", {})
            exchanges = int(context.get("http_exchanges", 0))
            if phase in {"prepare", "control"}:
                requests += exchanges
                if phase == "control":
                    last_control_by_generation[generation] = exchanges
            elif phase == "b05-provision":
                requests += max(0, exchanges - last_control_by_generation.get(generation, 0))
        requests += int(trace.get("exchange_count", 0))
        if requests > request_reservation:
            raise ValueError("B05 actual HTTP exchange ledger exceeded its fixed reservation")
        result = {"status": evidence.verdict, "security_verdict": evidence.verdict,
            "executed": True, "runtime_provisioned": True, "actions": 1,
            "requests_reserved": request_reservation, "requests_observed": requests,
            "worker_cleanup_verified": True,
            "origin": "canonical_fixed_B05_verifier", "action": action.model_dump(mode="json"),
            "validation": validation.model_dump(mode="json"), "execution": execution.model_dump(mode="json"),
            "evidence": evidence.model_dump(mode="json"), "finding_id": finding.id}
        result["report"] = build_final_report({"finding": finding, "target_profile": profile,
            "proposed_action": action, "validation": validation, "execution": execution,
            "evidence": [evidence], "status": evidence.verdict, "iteration_count": 1,
            "stop_reason": "terminal_evidence" if evidence.verdict in {"confirmed", "rejected"} else "insufficient_evidence",
            "binding_resolution": resolution,
            "action_history": [AgentActionRecord(step=1, action=action, validation=validation,
                execution=execution, evidence_ids=[evidence.id], sandbox_session_id=runtime.run_session_id)]
        }).model_dump(mode="json")
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        cleanup = runtime.lab.close()
        executor.close_managed_lab()
        if not cleanup:
            raise RuntimeError("B05 fixture cleanup could not be verified")


def _b06(*, finding, profile, route, scope, output, worker_image, wall_seconds):
    resolution = resolve_binding(profile, finding)
    if resolution.binding is None or resolution.binding.route_id != route.id or not _source_matches(resolution.binding, scope):
        return None
    tool = route.tool
    profile = register_source_artifacts(profile, [finding], profile.repository_path)
    runtime = B06Runtime(profile, tool, output, max_readiness_attempts=16,
                         wall_time_budget_seconds=wall_seconds)
    try:
        runtime.open()
        candidate, = verification_candidates({"target_profile": runtime.profile,
            "finding": finding.model_copy(update={"provenance": None}),
            "runtime_services": runtime.runtime_map()})
        action = ActionProposal(id="research-b06-" + uuid4().hex, tool=tool,
            target=runtime.profile.id, environment="sandbox", parameters=candidate["parameters"],
            purpose="Operator-authorized fixed B06 runtime verification",
            expected_evidence="Two independent trials, controls and cleanup", service=candidate["service"],
            endpoint=candidate["endpoint"], verification_binding=candidate["verification_binding"],
            fixture_binding=candidate["fixture_binding"])
        validator = PolicyValidator.from_yaml(ROOT / "policies/b06.yaml", target_profile=runtime.profile)
        validator.fixture_bindings[runtime.profile.id] = runtime.binding
        validation = validator.validate(action)
        if not validation.approved:
            return {"status": "review_pending", "reason": "Canonical Validator denied B06 protocol: " + validation.reason,
                    "executed": False, "actions": 0, "requests_reserved": 0}
        approvals = InMemoryApprovalStore()
        approvals.record(action, validation)
        store = JsonExecutionEvidenceStore(output / "execution")
        audit = JsonlAuditLog(output / "audit.jsonl")
        policy = SandboxPolicy(backend="docker", sandbox_image=worker_image,
            limits=SandboxLimits(wall_time_seconds=60, cpu_time_seconds=3, max_output_bytes=65536))
        executor = SafeExecutor(approvals=approvals, targets=TargetRegistry([runtime.profile]),
            evidence_store=store, audit_log=audit, sandbox=DockerSandbox(policy),
            run_limiter=RunLimiter(1, 1), policy=policy)
        executor.bind_verification_runtime(runtime)
        execution = executor.execute_sequence([action], runtime_services=runtime.runtime_map()).results[0].execution
        record = read_protocol_execution(store, audit, action, execution, runtime.id)
        evidence = build_evidence(action=action, execution=execution, record=record, evidence_loaded=True,
            artifact_refs=execution.artifacts, hypothesis_id=finding.id, sandbox_session_id=runtime.id)
        payload = json.loads(execution.stdout)
        # Executor stdout is the canonical typed B06 result; account every setup and probe exchange.
        requests = sum(int(t.get("http_exchanges", 0)) + int(t.get("setup_http_exchanges", 0))
                       for t in payload.get("trials", []))
        requests += sum(int(item.get("readiness_http_exchanges", 0))
                        for item in runtime.records if item.get("phase") == "ready")
        reservation = PROTOCOLS["b06.redirect.v1" if tool == "verify_redirect_destination"
                                else "b06.password-reauth.v1"][2]
        if requests > reservation:
            raise ValueError("B06 actual HTTP exchange ledger exceeded its fixed reservation")
        result = {"status": evidence.verdict, "security_verdict": evidence.verdict,
            "executed": True, "runtime_provisioned": True, "actions": 1,
            "requests_reserved": reservation, "requests_observed": requests,
            "worker_cleanup_verified": True,
            "origin": "canonical_fixed_B06_verifier", "action": action.model_dump(mode="json"),
            "validation": validation.model_dump(mode="json"), "execution": execution.model_dump(mode="json"),
            "evidence": evidence.model_dump(mode="json"), "finding_id": finding.id}
        result["report"] = build_final_report({"finding": finding, "target_profile": runtime.profile,
            "proposed_action": action, "validation": validation, "execution": execution,
            "evidence": [evidence], "status": evidence.verdict, "iteration_count": 1,
            "stop_reason": "terminal_evidence" if evidence.verdict in {"confirmed", "rejected"} else "insufficient_evidence",
            "binding_resolution": resolve_binding(runtime.profile, finding),
            "action_history": [AgentActionRecord(step=1, action=action, validation=validation,
                execution=execution, evidence_ids=[evidence.id], sandbox_session_id=runtime.id)]
        }).model_dump(mode="json")
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        if not runtime.close():
            raise RuntimeError("B06 fixture cleanup could not be verified")


def verify_fixture_candidate(*, finding, routed, profile, binding, scope, repository, output, pending,
                             grants, max_http_requests, remaining_wall_seconds):
    grant, route = _grant_for(profile, routed, grants)
    if grant is None or route is None:
        return {**pending, "reason": "No matching explicit operator fixture grant"}
    target, _selection, reservation, kind = PROTOCOLS[grant.protocol]
    if profile.id != target or binding.route_id != route.id or not _source_matches(binding, scope):
        return {**pending, "reason": "Fixture route or source snapshot is not bound to campaign inventory"}
    if reservation > min(max_http_requests, grant.max_http_requests):
        return {**pending, "reason": "Insufficient reserved HTTP budget for complete fixture lifecycle"}
    if grant.wall_seconds > remaining_wall_seconds:
        return {**pending, "reason": "Insufficient campaign wall-clock grant for complete fixture lifecycle"}
    root = Path(repository).resolve()
    if profile.repository_path.resolve() != root:
        return {**pending, "reason": "Fixture checkout differs from campaign target"}
    if kind == "b05":
        result = _b05(finding=routed, profile=profile, route=route, scope=scope, output=Path(output),
                      worker_image=profile.access_fixture.worker_image, wall_seconds=grant.wall_seconds,
                      request_reservation=reservation)
    else:
        result = _b06(finding=routed, profile=profile, route=route, scope=scope, output=Path(output),
                      worker_image=WORKER_IMAGE, wall_seconds=grant.wall_seconds)
    if result is None:
        return {**pending, "reason": "No unique source-bound fixture binding"}
    return {**pending, **result}
