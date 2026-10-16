"""Operator-owned handoff to canonical verifiers, not an execution permission."""
import json
import subprocess
from pathlib import Path
from uuid import uuid4

from agent.verification import register_source_artifacts, verification_candidates
from agent.verification_routing import select_profile
from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore
from executor.executor import SafeExecutor
from executor.research_runtime import resolve_research_endpoint
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_audit import calculate_sha256_digest
from executor.sandbox_policy import SandboxLimits, SandboxPolicy
from executor.targets import TargetRegistry
from pipeline.cancellation import check_cancelled
from reporting.builder import build_final_report
from schemas.action import ActionProposal
from schemas.agent_loop import AgentActionRecord
from schemas.research_fixtures import ResearchVerificationGrant
from schemas.runtime import RuntimeService, RuntimeServiceMap
from security.verification_binding import resolve_binding
from tools.research import research_proposal
from validator.validator import PolicyValidator

ROOT = Path(__file__).resolve().parents[1]
REQUEST_RESERVATIONS = {"verify_sql_injection": 4, "verify_sensitive_directory": 1}
RULE_ALIASES = {
    "javascript.express.security.injection.tainted-sql-string.tainted-sql-string": "sql-injection",
    "javascript.sequelize.security.audit.sequelize-raw-query.sequelize-raw-query": "sql-injection",
    "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection": "sql-injection",
}


def verification_finding(finding):
    """Exact operator adapter aliases select a verifier, never a verdict/identity."""
    alias = RULE_ALIASES.get(finding.rule_id)
    return finding.model_copy(update={"rule_id": alias}) if alias else finding


def inspect_docker(args):
    check_cancelled()
    return subprocess.run(["docker", *args], check=True, capture_output=True, text=True, timeout=15)


def read_protocol_execution(store, audit, action, execution, session_id):
    """Readback requires an independent matching audit, not live worker stdout."""
    record = store.get_execution(execution.evidence_ref)
    matching = [a for a in audit.records() if a.get("run_id") == execution.run_id and a.get("action_id") == action.id]
    payload = {k: v for k, v in record.items() if k not in {"id", "type", "created_at"}}
    if (len(matching) != 1 or matching[0]["proposal_digest"] != calculate_sha256_digest(action.model_dump())
            or matching[0]["evidence_digest"] != calculate_sha256_digest(payload)
            or matching[0]["runtime_backend"] != "docker"
            or matching[0].get("session_id") != session_id
            or matching[0].get("evidence_ref") != execution.evidence_ref
            or record.get("action_id") != action.id or record.get("run_id") != execution.run_id
            or (action.verification_binding is not None and
                record.get("verification_binding") != action.verification_binding.model_dump(mode="json"))
            or (action.fixture_binding is not None and
                record.get("fixture_binding") != action.fixture_binding.model_dump(mode="json"))
            or (action.juice_proof_binding is not None and (
                record.get("juice_proof_binding") != action.juice_proof_binding.model_dump(mode="json")
                or matching[0].get("network_mode") != "internal"
                or record.get("session_id") != session_id
                or record.get("status") != execution.status
                or record.get("exit_code") != execution.exit_code))):
        raise ValueError("Canonical protocol audit does not match persisted execution")
    return record


def verification_handoff(findings, profiles, repository):
    """Keep candidate identity/source binding; do not substitute benchmark cases.

    A plan is deliberately not Evidence. Actual execution needs the canonical
    pipeline's matching runtime, policy, approvals and (where required) fixtures.
    """
    if len({p.id for p in profiles}) != len(profiles):
        raise ValueError("Duplicate operator verification profile")
    if any(p.environment != "sandbox" or p.repository_path != repository for p in profiles):
        raise ValueError("Verification handoff requires the same sandbox repository")
    rows = []
    for finding in findings:
        routed = verification_finding(finding)
        profile, reason = select_profile(routed, profiles)
        bound = resolve_binding(profile, routed) if profile else None
        binding = bound.binding if bound else None
        if profile and profile.juice_incremental_proofs is not None:
            from security.juice_incremental_binding import bind_finding

            binding = bind_finding(profile, routed)
            reason = "Fixed Juice proof bound to the operator rule and source snapshot"
        rows.append({"finding_id": finding.id, "status": "ready_for_canonical_verification"
                     if binding else "missing_binding_or_capability",
                     "profile_id": profile.id if profile else None,
                     "reason": bound.reason if bound and bound.binding else reason,
                     "binding": binding.model_dump(mode="json") if binding else None,
                     "rule_alias": {"original": finding.rule_id, "verification_family": routed.rule_id,
                                    "registry": "research-verification-aliases.v1"},
                     "runtime_provisioned": False, "executed": False, "security_verdict": None})
    return {"schema": "cft.research.verification-handoff.v1", "checks": rows,
            "findings": [f.model_dump(mode="json") for f in findings],
            "execution_path": "canonical ActionProposal -> Validator -> Executor -> persisted Evidence",
            "is_evidence": False}


def verify_bound_candidate(*, finding, profiles, scope, repository, output, max_http_requests, worker_image,
                           fixture_grants=(), verification_grants=(), remaining_wall_seconds=3600):
    """Optional fixed canonical verification bridge for B01, B05 and B06.

    Operator profiles select a protocol but cannot enlarge model research scope.
    Fixed B01 POST checks need their separate route-exact grant. This function
    never uses model argv, HTTP bodies, credentials or target URLs.
    """
    plan = verification_handoff([finding], profiles, repository)["checks"][0]
    pending = {**plan, "status": "review_pending", "requests_reserved": 0, "actions": 0}
    if not plan["binding"]:
        return pending
    profile = next(p for p in profiles if p.id == plan["profile_id"])
    routed = verification_finding(finding)
    if profile.juice_incremental_proofs is not None:
        from pipeline.juice_proof_verification import verify_incremental_candidate

        return verify_incremental_candidate(finding=routed, profile=profile, scope=scope,
            output=output, pending=pending, max_http_requests=max_http_requests,
            remaining_wall_seconds=remaining_wall_seconds)
    binding = resolve_binding(profile, routed).binding
    cost = REQUEST_RESERVATIONS.get(binding.tool)
    if cost is None:
        from pipeline.research_fixture_verification import verify_fixture_candidate
        return verify_fixture_candidate(finding=finding, routed=routed, profile=profile, binding=binding,
            scope=scope, repository=repository, output=output, pending=pending,
            grants=fixture_grants, max_http_requests=max_http_requests, remaining_wall_seconds=remaining_wall_seconds)
    if cost > max_http_requests:
        return {**pending, "reason": "Insufficient remaining network reservation"}
    # Reuse the model's read-only grant when it covers this exact protocol. The
    # login verifier has a separate, fixed operator grant: it never adds POST to
    # ResearchScope, and the model cannot choose its body or credentials.
    try:
        research_proposal(scope=scope, action_id="bridge-preflight", tool="target_http",
            parameters={"method": binding.method, "path": binding.endpoint},
            service=binding.service, endpoint=binding.endpoint,
            purpose="Check existing operator grant", expected_evidence="No execution")
    except ValueError:
        if not _fixed_verification_granted(binding, profile, verification_grants):
            return {**pending, "reason": "Protocol method/path is not granted by the research operator"}
    if any(p not in scope.source_files or scope.source_files[p].original_sha256 != h
           for p, h in binding.source_files.items()):
        return {**pending, "reason": "Protocol source snapshot is outside or differs from research inventory"}
    # Same registered target container/image/internal network before and after.
    service = scope.services[binding.service]
    resolve_research_endpoint(scope, service, inspect_docker)
    profile = register_source_artifacts(profile, [finding], repository)
    runtime = RuntimeServiceMap(session_id="research-bridge-" + uuid4().hex,
        network_name=scope.network_name, source_files_sha256=binding.source_files,
        services={binding.service: RuntimeService(name=binding.service, address=service.address,
            ready=True, readiness_source="http_probe", allowed_endpoints=[binding.endpoint])})
    candidates = verification_candidates({"finding": routed, "target_profile": profile, "runtime_services": runtime})
    if len(candidates) != 1:
        return {**pending, "reason": "No unique canonical verification candidate"}
    candidate = candidates[0]
    action = ActionProposal(id="research-bridge-" + uuid4().hex, target=profile.id, environment="sandbox",
        tool=candidate["tool"], parameters=candidate["parameters"], purpose=candidate["purpose"],
        expected_evidence="Fixed runtime protocol with independently persisted audit",
        service=candidate["service"], endpoint=candidate["endpoint"], verification_binding=candidate["verification_binding"])
    validation = PolicyValidator.from_yaml(ROOT / "policies/default.yaml", target_profile=profile).validate(action)
    if not validation.approved:
        return {**pending, "reason": "Canonical Validator denied the protocol"}
    output = Path(output).resolve()
    if output.exists() or output.is_relative_to(repository) or repository.is_relative_to(output):
        raise ValueError("Verification requires fresh output outside the target")
    output.mkdir(parents=True)
    store, audit = JsonExecutionEvidenceStore(output / "execution"), JsonlAuditLog(output / "audit.jsonl")
    approvals = InMemoryApprovalStore()
    approvals.record(action, validation)
    policy = SandboxPolicy(backend="docker", sandbox_image=worker_image,
        limits=SandboxLimits(wall_time_seconds=10, cpu_time_seconds=3, max_output_bytes=65536))
    executor = SafeExecutor(approvals=approvals, targets=TargetRegistry([profile]), evidence_store=store,
        audit_log=audit, sandbox=DockerSandbox(policy), run_limiter=RunLimiter(1, 1), policy=policy)
    try:
        sequence = executor.execute_sequence([action], runtime_services=runtime)
        execution = sequence.results[0].execution
        record = read_protocol_execution(store, audit, action, execution, runtime.session_id)
        resolve_research_endpoint(scope, service, inspect_docker)
        current = resolve_binding(profile, routed)
        if current.binding != binding:
            raise ValueError("Canonical source binding changed during verification")
        evidence = build_evidence(action=action, execution=execution, record=record, evidence_loaded=True,
            artifact_refs=execution.artifacts, hypothesis_id=finding.id, sandbox_session_id=runtime.session_id)
        observation = evidence.observation.facts
        observed_facts = observation.get("facts", {}) if isinstance(observation, dict) else {}
        observed_requests = observed_facts.get("requests") if isinstance(observed_facts, dict) else None
        if (isinstance(observed_requests, bool) or not isinstance(observed_requests, int)
                or observed_requests < 0 or observed_requests > cost):
            raise ValueError("Canonical verifier did not report a valid bounded HTTP exchange count")
        result = {**plan, "status": evidence.verdict, "security_verdict": evidence.verdict,
            "executed": True, "runtime_provisioned": True, "actions": 1, "requests_reserved": cost,
            "requests_observed": observed_requests,
            "origin": "canonical_fixed_verifier; not a model-generated proof",
            "action": action.model_dump(mode="json"), "validation": validation.model_dump(mode="json"),
            "execution": execution.model_dump(mode="json"), "evidence": evidence.model_dump(mode="json")}
    finally:
        executor.close_managed_lab()
    result["worker_cleanup_verified"] = True
    result["report"] = build_final_report({"finding": finding, "target_profile": profile,
        "proposed_action": action, "validation": validation, "execution": execution,
        "evidence": [evidence], "status": evidence.verdict, "iteration_count": 1,
        "stop_reason": "terminal_evidence" if evidence.verdict in {"confirmed", "rejected"} else "insufficient_evidence",
        "binding_resolution": resolve_binding(profile, routed),
        "action_history": [AgentActionRecord(step=1, action=action, validation=validation,
            execution=execution, evidence_ids=[evidence.id], sandbox_session_id=runtime.session_id)]
    }).model_dump(mode="json")
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def _fixed_verification_granted(binding, profile, grants):
    """Match the complete reviewed B01 login route; never widen generic HTTP scope."""
    grants = tuple(ResearchVerificationGrant.model_validate(grant) for grant in grants)
    return any(
        grant.protocol == "b01.login-sql.v1"
        and grant.route_id == "juice-login"
        and profile.id == "juice-verification"
        and binding.route_id == grant.route_id
        and binding.tool == "verify_sql_injection"
        and binding.check == "sql_interpolation"
        and binding.mode == "authentication"
        and binding.method == "POST"
        and binding.endpoint == "/rest/user/login"
        and grant.max_http_requests == REQUEST_RESERVATIONS["verify_sql_injection"]
        for grant in grants
    )
