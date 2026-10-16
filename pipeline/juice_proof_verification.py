"""Campaign bridge to the two registered, source-bound Juice proof capabilities."""
from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore
from executor.executor import SafeExecutor
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_policy import SandboxLimits, SandboxPolicy
from executor.targets import TargetRegistry
from reporting.builder import build_final_report
from schemas.action import ActionProposal
from schemas.agent_loop import AgentActionRecord
from security.juice_incremental_binding import _protocol_files, bind_finding
from validator.validator import PolicyValidator

ROOT = Path(__file__).resolve().parents[1]
# Ninety readiness attempts and at most twenty-four fixed protocol exchanges.
HTTP_RESERVATION = 114
# Includes bounded readiness attempts, worker timeout and mandatory cleanup.
WALL_RESERVATION = 900


def verify_incremental_candidate(*, finding, profile, scope, output, pending,
                                 max_http_requests, remaining_wall_seconds):
    binding = bind_finding(profile, finding)
    if binding is None:
        return {**pending, "reason": "No fixed Juice proof source binding"}
    for relative in _protocol_files(binding.check_id):
        scoped = scope.source_files.get(relative)
        if scoped is None or scoped.original_sha256 != sha256(
                (profile.repository_path / relative).read_bytes()).hexdigest():
            return {**pending, "reason": "Fixed Juice proof source differs from campaign inventory"}
    if max_http_requests < HTTP_RESERVATION:
        return {**pending, "reason": "Insufficient complete fixed Juice proof HTTP reservation"}
    if remaining_wall_seconds < WALL_RESERVATION:
        return {**pending, "reason": "Insufficient complete fixed Juice proof wall reservation"}
    action = ActionProposal(
        id="research-juice-proof-" + uuid4().hex, tool="verify_juice_proof", target=profile.id,
        environment="sandbox", parameters={"check_id": binding.check_id},
        purpose="Run the registered source-bound Juice Shop protocol",
        expected_evidence="Typed independent controls and readback in a disposable Docker generation",
        juice_proof_binding=binding,
    )
    validation = PolicyValidator.from_yaml(ROOT / "policies/default.yaml", target_profile=profile,
        capability_policy_file=ROOT / "policies/juice-incremental-proof.yaml").validate(action)
    if not validation.approved:
        return {**pending, "reason": "Canonical Validator denied the fixed Juice proof"}
    output = Path(output).resolve()
    repository = profile.repository_path.resolve()
    if output.exists() or output.is_relative_to(repository) or repository.is_relative_to(output):
        raise ValueError("Fixed Juice proof requires fresh output outside the target")
    output.mkdir(parents=True)
    store, audit = JsonExecutionEvidenceStore(output / "execution"), JsonlAuditLog(output / "audit.jsonl")
    approvals = InMemoryApprovalStore()
    approvals.record(action, validation)
    policy = SandboxPolicy(backend="docker", sandbox_image=profile.juice_incremental_proofs.worker_image,
        limits=SandboxLimits(wall_time_seconds=240, cpu_time_seconds=5, max_output_bytes=65536))
    executor = SafeExecutor(approvals=approvals, targets=TargetRegistry([profile]), evidence_store=store,
        audit_log=audit, sandbox=DockerSandbox(policy), run_limiter=RunLimiter(1, 1), policy=policy)
    try:
        execution = executor.execute_sequence([action]).results[0].execution
        if execution.status == "completed":
            record = executor.read_juice_proof_execution(action, execution)
        else:
            from pipeline.research_verification import read_protocol_execution

            persisted = store.get_execution(execution.evidence_ref)
            record = read_protocol_execution(store, audit, action, execution, persisted.get("session_id"))
        evidence = build_evidence(action=action, execution=execution, record=record, evidence_loaded=True,
            artifact_refs=execution.artifacts, hypothesis_id=finding.id,
            sandbox_session_id=record.get("session_id"))
        payload = json.loads(record.get("stdout") or "{}")
        cleanup = payload.get("cleanup_complete") is True
        requests = 0
        for path in (output / "juice-incremental").glob("*/lifecycle.jsonl"):
            for line in path.read_text().splitlines():
                row = json.loads(line)
                value = row.get("attempts", 0) if row.get("phase") == "readiness" else (
                    row.get("http_exchanges", 0) if row.get("phase") == "proof" else 0)
                if type(value) is not int or value < 0:
                    raise ValueError("Invalid fixed Juice proof request ledger")
                requests += value
        if requests > HTTP_RESERVATION:
            raise ValueError("Fixed Juice proof exceeded its HTTP reservation")
        result = {**pending, "finding_id": finding.id, "status": evidence.verdict,
            "security_verdict": evidence.verdict, "executed": True, "runtime_provisioned": True,
            "actions": 1, "requests_reserved": HTTP_RESERVATION, "requests_observed": requests,
            # Keep the full reservation; a failed worker may have unreported exchanges.
            "request_accounting_complete": False, "worker_cleanup_verified": cleanup,
            "origin": "canonical_fixed_juice_proof", "action": action.model_dump(mode="json"),
            "validation": validation.model_dump(mode="json"), "execution": execution.model_dump(mode="json"),
            "evidence": evidence.model_dump(mode="json")}
        result["report"] = build_final_report({"finding": finding, "target_profile": profile,
            "proposed_action": action, "validation": validation, "execution": execution,
            "evidence": [evidence], "status": evidence.verdict, "iteration_count": 1,
            "stop_reason": "terminal_evidence" if evidence.verdict in {"confirmed", "rejected"} else "insufficient_evidence",
            "action_history": [AgentActionRecord(step=1, action=action, validation=validation,
                execution=execution, evidence_ids=[evidence.id], sandbox_session_id=record.get("session_id"))]
        }).model_dump(mode="json")
        (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
        return result
    finally:
        executor.close_managed_lab()
