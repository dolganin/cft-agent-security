import json
from uuid import uuid4

from pydantic import BaseModel, ValidationError

from schemas.access_verification import AccessCheckTrace
from schemas.action import ActionProposal
from schemas.evidence import (
    Evidence,
    EvidenceAction,
    EvidenceArtifact,
    EvidenceObservation,
    EvidenceScope,
)
from schemas.execution import ExecutionResult
from schemas.security_tools import (
    BoundedVerificationResult,
    DockerfileUserCheckResult,
    PythonPasswordAssignmentCheckResult,
    ReactDangerousHtmlFlowCheckResult,
)
from security.error_redaction import redact_error_message

DOCKERFILE_USER_TOOL = "inspect_dockerfile_user"
PYTHON_PASSWORD_TOOL = "inspect_python_password_assignment"
REACT_HTML_FLOW_TOOL = "inspect_react_dangerous_html_flow"
SANDBOX_COMMAND_TOOL = "sandbox_command"


_SPECIALIZED_RESULTS: dict[str, tuple[type[BaseModel], str]] = {
    "verify_access_control": (AccessCheckTrace, "access_control_verification"),
    "inspect_javascript_security": (BoundedVerificationResult, "javascript_source_metadata"),
    "verify_sql_injection": (BoundedVerificationResult, "sql_differential_check"),
    "verify_sensitive_directory": (BoundedVerificationResult, "sensitive_directory_check"),
    DOCKERFILE_USER_TOOL: (DockerfileUserCheckResult, "dockerfile_user_check"),
    PYTHON_PASSWORD_TOOL: (
        PythonPasswordAssignmentCheckResult,
        "python_password_assignment_check",
    ),
    REACT_HTML_FLOW_TOOL: (
        ReactDangerousHtmlFlowCheckResult,
        "react_dangerous_html_flow_check",
    ),
}


def build_evidence(
    *,
    action: ActionProposal,
    execution: ExecutionResult,
    record: dict,
    evidence_loaded: bool,
    artifact_refs: list[str],
    hypothesis_id: str,
    sandbox_session_id: str | None = None,
) -> Evidence:
    """Преобразует сохраненный результат Executor в Evidence"""
    if action.tool == SANDBOX_COMMAND_TOOL:
        return _sandbox_command_evidence(
            action=action,
            execution=execution,
            record=record,
            evidence_loaded=evidence_loaded,
            artifact_refs=artifact_refs,
            hypothesis_id=hypothesis_id,
            sandbox_session_id=sandbox_session_id,
        )

    specialized = _SPECIALIZED_RESULTS.get(action.tool)
    if specialized is not None:
        evidence = _structured_capability_evidence(
            action=action,
            execution=execution,
            record=record,
            evidence_loaded=evidence_loaded,
            artifact_refs=artifact_refs,
            hypothesis_id=hypothesis_id,
            sandbox_session_id=sandbox_session_id,
            result_model=specialized[0],
            evidence_type=specialized[1],
        )
        if evidence is not None:
            return evidence

    record_status = str(record["status"]) if evidence_loaded else execution.status
    record_exit_code = int(record["exit_code"]) if evidence_loaded else execution.exit_code
    read_status = "read from persistent storage" if evidence_loaded else "unavailable"

    return _evidence(
        action=action,
        execution=execution,
        evidence_type="test_result",
        summary=(
            f"Executor evidence {execution.evidence_ref} {read_status}: "
            f"executor_status={record_status}, exit_code={record_exit_code}, "
            f"timed_out={execution.timed_out}."
        ),
        facts={
            "executor_status": record_status,
            "exit_code": record_exit_code,
            "timed_out": execution.timed_out,
            "record_loaded": evidence_loaded,
        },
        scope_description="bounded executor result; not a vulnerability verdict",
        artifact_refs=artifact_refs,
        reliability="high" if evidence_loaded and record_status == "completed" else "low",
        hypothesis_id=hypothesis_id,
        sandbox_session_id=sandbox_session_id,
    )



def _sandbox_command_evidence(
    *,
    action: ActionProposal,
    execution: ExecutionResult,
    record: dict,
    evidence_loaded: bool,
    artifact_refs: list[str],
    hypothesis_id: str,
    sandbox_session_id: str | None,
) -> Evidence:
    status = str(record.get("status", execution.status)) if evidence_loaded else execution.status
    exit_code = int(record.get("exit_code", execution.exit_code)) if evidence_loaded else execution.exit_code
    stdout = str(record.get("stdout", execution.stdout)) if evidence_loaded else execution.stdout
    stderr = str(record.get("stderr", execution.stderr)) if evidence_loaded else execution.stderr
    stdout = stdout[:8_192]
    stderr = stderr[:4_096]
    return _evidence(
        action=action,
        execution=execution,
        evidence_type="sandbox_command_observation",
        summary=(
            "Bounded command observation from the disposable security lab: "
            f"status={status}, exit_code={exit_code}."
        ),
        facts={
            "executor_status": status,
            "exit_code": exit_code,
            "timed_out": execution.timed_out,
            "stdout": stdout,
            "stderr": stderr,
            "cwd": action.parameters.get("cwd"),
            "argv": [
                redact_error_message(str(item), max_length=1024)
                for item in action.parameters.get("argv", [])
            ],
            "record_loaded": evidence_loaded,
        },
        scope_description=(
            "disposable sandbox command output; target repository is read-only and "
            "the command has no arbitrary network access"
        ),
        artifact_refs=artifact_refs,
        reliability="high" if evidence_loaded else "low",
        hypothesis_id=hypothesis_id,
        sandbox_session_id=sandbox_session_id,
    )

def _structured_capability_evidence(
    *,
    action: ActionProposal,
    execution: ExecutionResult,
    record: dict,
    evidence_loaded: bool,
    artifact_refs: list[str],
    hypothesis_id: str,
    sandbox_session_id: str | None,
    result_model: type[BaseModel],
    evidence_type: str,
) -> Evidence | None:
    if not evidence_loaded:
        return None
    if (str(record.get("status")) != "completed" or int(record.get("exit_code", 1)) != 0) \
            and action.tool != "verify_access_control":
        return None

    if action.verification_binding is not None:
        from executor.approvals import proposal_digest
        if (record.get("verification_binding") != action.verification_binding.model_dump(mode="json")
                or record.get("action_digest") != proposal_digest(action)
                or record.get("endpoint") != action.endpoint
                or record.get("session_id") != sandbox_session_id):
            return _evidence(
                action=action, execution=execution, evidence_type=evidence_type,
                summary="Persisted snapshot/endpoint/approval binding did not match the action.",
                facts={"verification_binding_valid": False},
                scope_description="source snapshot binding mismatch", artifact_refs=artifact_refs,
                reliability="low", verdict="inconclusive", hypothesis_id=hypothesis_id,
                sandbox_session_id=sandbox_session_id,
            )

    try:
        payload = result_model.model_validate_json(str(record.get("stdout", "")))
    except (ValidationError, json.JSONDecodeError, TypeError, ValueError):
        return _evidence(
            action=action,
            execution=execution,
            evidence_type=evidence_type,
            summary="Executor completed, but capability-specific evidence was malformed.",
            facts={"schema_valid": False},
            scope_description="bounded capability result could not be parsed",
            artifact_refs=artifact_refs,
            reliability="low",
            verdict="inconclusive",
            hypothesis_id=hypothesis_id,
            sandbox_session_id=sandbox_session_id,
        )

    if isinstance(payload, BoundedVerificationResult) and not _bounded_result_matches_action(payload, action):
        return _evidence(
            action=action, execution=execution, evidence_type=evidence_type,
            summary="Executor output did not match the approved verification action.",
            facts={"schema_valid": True, "action_binding_valid": False},
            scope_description="bounded capability result failed action binding",
            artifact_refs=artifact_refs, reliability="low", verdict="inconclusive",
            hypothesis_id=hypothesis_id, sandbox_session_id=sandbox_session_id,
        )

    data = payload.model_dump(by_alias=True)
    if isinstance(payload, AccessCheckTrace):
        from evidence.access_control import evaluate_access_check
        from security.access_verification import binding_id
        decision = evaluate_access_check(payload, action)
        return _evidence(
            action=action,
            execution=execution,
            evidence_type=evidence_type,
            summary=decision.reason,
            facts={"b05_evidence": decision.model_dump(mode="json"),
                   "b05_trace": data, "record_loaded": evidence_loaded,
                   "persisted_action_digest": record.get("action_digest")},
            scope_description="registered B05 check on a disposable B04 fixture",
            artifact_refs=artifact_refs,
            reliability="high" if evidence_loaded and decision.binding_id == binding_id(action) else "low",
            verdict=decision.verdict,
            hypothesis_id=hypothesis_id,
            sandbox_session_id=sandbox_session_id,
        )
    verdict = data.get("verdict")
    explanation = str(data.get("explanation", "Capability verification completed."))
    scope_description = str(data.get("scope", "bounded capability result"))
    facts = {
        key: value
        for key, value in data.items()
        if key not in {"verdict", "explanation", "scope"}
    }
    if action.verification_binding is not None:
        facts["verification_binding"] = record["verification_binding"]
        facts["approved_action_digest"] = record["action_digest"]
    return _evidence(
        action=action,
        execution=execution,
        evidence_type=evidence_type,
        summary=explanation,
        facts=facts,
        scope_description=scope_description,
        artifact_refs=artifact_refs,
        reliability="high",
        verdict=verdict,
        hypothesis_id=hypothesis_id,
        sandbox_session_id=sandbox_session_id,
    )


def _bounded_result_matches_action(payload: BoundedVerificationResult, action: ActionProposal) -> bool:
    facts = payload.facts
    if facts.get("artifact_id") != action.parameters.get("artifact_id") or facts.get("line") != action.parameters.get("line"):
        return False
    if action.tool == "inspect_javascript_security":
        if facts.get("check") != action.parameters.get("check"):
            return False
        if payload.scope == "source_metadata":
            return payload.verdict == "inconclusive"
        return (
            payload.scope == "source_sql_interpolation"
            and action.parameters.get("check") == "sql_interpolation"
            and payload.verdict == "confirmed"
            and facts.get("raw_sql_call") is True
            and facts.get("request_derived_interpolations", 0) > 0
            and facts.get("query_binding_present") is False
            and facts.get("recognized_sanitizer_present") is False
            and facts.get("runtime_exploitability_verified") is False
        )
    if action.tool == "verify_sql_injection":
        if (payload.scope != "runtime_sql_differential"
                or facts.get("mode") != action.parameters.get("mode")
                or facts.get("check") != action.parameters.get("check")
                or facts.get("endpoint") != action.endpoint
                or len(facts.get("observations", [])) != 4):
            return False
        observations = facts["observations"]
        if action.parameters.get("mode") == "search":
            controls = all(observations[i].get("valid_json") and observations[i].get("status") == 200
                           and observations[i].get("result_count") == 0 for i in (0, 2))
            probes = all(observations[i].get("valid_json") and observations[i].get("status") == 200
                         and isinstance(observations[i].get("result_count"), int)
                         and observations[i]["result_count"] > 0 for i in (1, 3))
        else:
            controls = all(observations[i].get("status") in {400, 401, 403}
                           and not observations[i].get("authenticated") for i in (0, 2))
            probes = all(observations[i].get("status") == 200 and observations[i].get("valid_json")
                         and observations[i].get("authenticated") for i in (1, 3))
        blocked = controls and all(
            observations[i].get("valid_json") and (
                observations[i].get("status") == 200 and observations[i].get("result_count") == 0
                if action.parameters.get("mode") == "search" else
                observations[i].get("status") in {400, 401, 403}
                and not observations[i].get("authenticated")
            ) for i in (1, 3)
        )
        expected = "confirmed" if controls and probes else "rejected" if blocked else "inconclusive"
        return payload.verdict == expected
    if action.tool == "verify_sensitive_directory":
        if (payload.scope != "runtime_directory_metadata"
                or facts.get("check") != action.parameters.get("check")
                or facts.get("endpoint") != action.endpoint):
            return False
        names = facts.get("sensitive_file_names")
        evidence = (facts.get("status") == 200 and facts.get("directory_listing") is True
                    and facts.get("file_contents_read") is False
                    and isinstance(names, list) and bool(names))
        return payload.verdict == ("confirmed" if evidence else "inconclusive")
    return False


def _evidence(
    *,
    action: ActionProposal,
    execution: ExecutionResult,
    evidence_type: str,
    summary: str,
    facts: dict[str, object],
    scope_description: str,
    artifact_refs: list[str],
    reliability: str,
    hypothesis_id: str,
    sandbox_session_id: str | None,
    verdict: str | None = None,
) -> Evidence:
    artifacts = [_artifact(ref) for ref in artifact_refs]
    return Evidence(
        id=f"evidence-{uuid4().hex[:10]}",
        action_id=action.id,
        type=evidence_type,
        summary=summary,
        artifact_refs=artifact_refs,
        reliability=reliability,
        verdict=verdict,
        source="runtime" if sandbox_session_id is not None else "static",
        sandbox_session_id=sandbox_session_id,
        hypothesis_id=hypothesis_id,
        action=EvidenceAction(id=action.id, tool=action.tool, run_id=execution.run_id),
        observation=EvidenceObservation(kind=evidence_type, facts=facts),
        scope=EvidenceScope(
            target=action.target,
            environment=action.environment,
            service=action.service,
            description=scope_description,
        ),
        artifacts=artifacts,
    )


def _artifact(reference: str) -> EvidenceArtifact:
    if reference.startswith("execution-"):
        role = "execution"
    elif reference.startswith("audit:"):
        role = "audit"
    else:
        role = "other"
    return EvidenceArtifact(ref=reference, role=role)
