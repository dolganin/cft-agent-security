import shutil
from pathlib import Path

import pytest

import executor.executor as executor_module
from app.config import settings as app_settings
from evidence.audit import JsonlAuditLog
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore
from executor.executor import SafeExecutor
from executor.sandbox import (
    RunLimiter,
    SandboxRequest,
    SandboxResult,
)
from executor.sandbox_manager import SandboxConfigurationError
from executor.sandbox_policy import SandboxLimits, SandboxPolicy
from executor.sandbox_session import SessionCleanupError
from executor.targets import TargetArtifactDefinition, TargetDefinition, TargetRegistry
from schemas.action import ActionProposal
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.target import TargetArtifact, TargetProfile, TargetService
from schemas.validation import ValidationResult
from validator.validator import PolicyValidator


class FakeSandbox:
    def __init__(
        self,
        *,
        exit_code: int = 0,
        stdout: str = "ok",
        stderr: str = "",
        timed_out: bool = False,
        raises: bool = False,
        exception_message: str = "synthetic sandbox failure",
        runtime_backend: str = "process",
    ) -> None:
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.timed_out = timed_out
        self.raises = raises
        self.exception_message = exception_message
        self.runtime_backend = runtime_backend
        self.requests: list[SandboxRequest] = []

    def run(self, request: SandboxRequest) -> SandboxResult:
        self.requests.append(request)
        if self.raises:
            raise RuntimeError(self.exception_message)
        return SandboxResult(
            run_id=request.run_id,
            exit_code=self.exit_code,
            stdout=self.stdout,
            stderr=self.stderr,
            duration_ms=1,
            timed_out=self.timed_out,
            workspace_id=f"run-{request.run_id}",
            runtime_backend=self.runtime_backend,
        )


class FailingEvidenceStore:
    def put_execution(self, _record: dict) -> tuple[str, str]:
        raise OSError("synthetic evidence persistence failure")


class FailingAuditLog:
    def append(self, _event: dict) -> str:
        raise OSError("synthetic audit persistence failure")


def _proposal(
    *,
    action_id: str = "executor-test-1",
    tool: str = "safe_noop",
    target: str = "sberlab-local",
    parameters: dict | None = None,
    service: str | None = None,
    endpoint: str | None = None,
) -> ActionProposal:
    return ActionProposal(
        id=action_id,
        tool=tool,
        target=target,
        parameters=parameters or {},
        purpose="executor unit test",
        expected_evidence="structured execution evidence",
        service=service,
        endpoint=endpoint,
    )


def _approve(action: ActionProposal) -> tuple[InMemoryApprovalStore, ValidationResult]:
    validation = PolicyValidator.from_yaml(
        "policies/default.yaml",
        target_file="targets/sberlab.yaml",
    ).validate(action)
    assert validation.approved is True
    approvals = InMemoryApprovalStore()
    approvals.record(action, validation)
    return approvals, validation


def _executor(
    tmp_path,
    approvals: InMemoryApprovalStore,
    *,
    sandbox: FakeSandbox | None = None,
    environment: str = "local",
    max_runs_per_action: int = 1,
    evidence_store=None,
    audit_log=None,
) -> tuple[SafeExecutor, FakeSandbox, object]:
    fake_sandbox = sandbox or FakeSandbox()
    policy = SandboxPolicy(
        backend="process",
        network_mode="none",
        allowed_environments={"local", "sandbox", "staging"},
        limits=SandboxLimits(
            wall_time_seconds=2,
            cpu_time_seconds=1,
            memory_bytes=128 * 1024 * 1024,
            max_file_bytes=1024 * 1024,
            max_processes=4,
            max_output_bytes=1024,
        ),
    )
    configured_audit_log = audit_log or JsonlAuditLog(
        tmp_path / "audit" / "executor.jsonl"
    )
    executor = SafeExecutor(
        approvals=approvals,
        targets=TargetRegistry(
            [
                TargetDefinition(
                    id="sberlab-local",
                    environment=environment,
                    base_url="http://127.0.0.1:8000",
                    repository_path=tmp_path / "target",
                    artifacts={
                        "backend_dockerfile": TargetArtifactDefinition(
                            id="backend_dockerfile",
                            kind="dockerfile",
                            relative_path="backend/Dockerfile",
                        ),
                        "demo_seed": TargetArtifactDefinition(
                            id="demo_seed",
                            kind="python",
                            relative_path="backend/core/management/commands/seed_demo.py",
                        ),
                    },
                )
            ]
        ),
        evidence_store=evidence_store
        or JsonExecutionEvidenceStore(tmp_path / "evidence"),
        audit_log=configured_audit_log,
        sandbox=fake_sandbox,
        run_limiter=RunLimiter(
            max_runs_per_action=max_runs_per_action,
            max_concurrent_runs=1,
        ),
        policy=policy,
    )
    return executor, fake_sandbox, configured_audit_log


def test_executor_denies_action_without_approval_and_records_evidence(tmp_path) -> None:
    action = _proposal()
    executor, sandbox, audit_log = _executor(tmp_path, InMemoryApprovalStore())

    result = executor.execute(action)

    assert result.status == "denied"
    assert result.error is None
    assert result.exit_code == 126
    assert "No trusted approval" in result.stderr
    assert sandbox.requests == []
    record = JsonExecutionEvidenceStore(tmp_path / "evidence").get_execution(
        result.evidence_ref
    )
    assert record["action_id"] == action.id
    assert record["status"] == "denied"
    assert audit_log.records()[0]["evidence_ref"] == result.evidence_ref


def test_executor_denies_proposal_changed_after_approval(tmp_path) -> None:
    approved_action = _proposal(parameters={"message": "original"})
    approvals, _ = _approve(approved_action)
    changed_action = approved_action.model_copy(
        update={"parameters": {"message": "changed"}}
    )

    executor, _, _ = _executor(tmp_path, approvals)
    result = executor.execute(changed_action)

    assert result.status == "denied"
    assert "changed after approval" in result.stderr


def test_approval_rejects_mismatched_action_id() -> None:
    action = _proposal(action_id="expected")
    validation = ValidationResult(
        approved=True,
        action_id="different",
        reason="test",
    )

    with pytest.raises(ValueError, match="does not match"):
        InMemoryApprovalStore().record(action, validation)


def test_denied_validation_cannot_create_approval() -> None:
    action = _proposal()
    validation = ValidationResult(
        approved=False,
        action_id=action.id,
        reason="blocked by policy",
    )

    with pytest.raises(ValueError, match="Denied ValidationResult"):
        InMemoryApprovalStore().record(action, validation)


def test_executor_denies_unknown_registered_capability(tmp_path) -> None:
    action = _proposal(tool="not_registered")
    approvals = InMemoryApprovalStore()
    approvals.record(
        action,
        ValidationResult(
            approved=True,
            action_id=action.id,
            reason="synthetic defense-in-depth test",
        ),
    )

    executor, sandbox, _ = _executor(tmp_path, approvals)
    result = executor.execute(action)

    assert result.status == "denied"
    assert result.exit_code == 126
    assert "Unknown executor tool" in result.stderr
    assert sandbox.requests == []


def test_executor_denies_production_environment(tmp_path) -> None:
    action = _proposal()
    approvals, _ = _approve(action)

    executor, _, _ = _executor(tmp_path, approvals, environment="production")
    result = executor.execute(action)

    assert result.status == "denied"
    assert "production" in result.stderr


def test_http_observation_refuses_process_sandbox_without_starting_target(tmp_path) -> None:
    action = _proposal(
        tool="observe_http_surface",
        service="backend",
        endpoint="/health/",
    )
    approvals, _ = _approve(action)
    executor, sandbox, _ = _executor(tmp_path, approvals)

    result = executor.execute(action)

    assert result.status == "denied"
    assert "Docker sandbox backend" in result.stderr
    assert result.error is not None
    assert result.error.code == "ISOLATION_BLOCKED"
    assert sandbox.requests == []


def test_target_network_capability_uses_managed_address_without_target_base_url(
    tmp_path, monkeypatch,
) -> None:
    action = _proposal(
        action_id="juice-directory-check",
        target="juice-test",
        tool="verify_sensitive_directory",
        parameters={
            "artifact_id": "source-server",
            "line": 288,
            "check": "source_metadata",
        },
        service="juice",
        endpoint="/ftp",
    ).model_copy(update={"environment": "sandbox"})
    approvals = InMemoryApprovalStore()
    approvals.record(
        action,
        ValidationResult(
            approved=True,
            action_id=action.id,
            reason="Synthetic test approval",
        ),
    )
    sandbox = FakeSandbox(runtime_backend="docker")
    executor, sandbox, audit_log = _executor(
        tmp_path, approvals, environment="sandbox", sandbox=sandbox
    )
    target = TargetProfile(
        id="juice-test",
        environment="sandbox",
        services={
            "juice": TargetService(
                id="juice",
                type="node",
                internal_port=3000,
                runtime_endpoints=["/ftp"],
            )
        },
        artifacts={
            "source-server": TargetArtifact(
                id="source-server",
                kind="javascript",
                path="server.ts",
            )
        },
    )
    executor._targets = TargetRegistry([target])
    executor._policy = SandboxPolicy(
        backend="process",
        network_mode="none",
        allowed_environments={"local", "sandbox", "staging"},
        limits=executor._policy.limits,
        sandbox_image="python@sha256:" + "a" * 64,
    )
    opened: list[tuple[str, str]] = []

    class FakeSequenceRuntime:
        runtime_instance_id = "runtime-target-sequence"

        def __enter__(self):
            return self

        def run(self, request):
            return sandbox.run(request)

        def __exit__(self, *_: object) -> bool:
            return False

    class FakeDockerSandbox:
        def __init__(self, policy) -> None:
            assert policy.backend == "docker"
            assert "@sha256:" in policy.sandbox_image

        def open_sequence(self, *, network_name: str, repository_path: str = ""):
            opened.append((network_name, repository_path))
            return FakeSequenceRuntime()

    monkeypatch.setattr(executor_module, "DockerSandbox", FakeDockerSandbox)
    runtime_services = RuntimeServiceMap(
        session_id="juice-session",
        network_name="cft-sandbox-juice_default",
        services={
            "juice": RuntimeService(
                name="juice",
                type="node",
                address="http://juice:3000",
                ready=True,
                readiness_source="compose_health",
                allowed_endpoints=["/ftp"],
            )
        },
    )

    result = executor.execute_sequence([action], runtime_services=runtime_services)

    assert result.results[0].execution.status == "completed"
    assert sandbox.requests[0].base_url == "http://juice:3000"
    assert sandbox.requests[0].endpoint == "/ftp"
    assert opened == [("cft-sandbox-juice_default", "")]
    assert result.runtime_instance_id == "runtime-target-sequence"
    assert audit_log.records()[0]["runtime_backend"] == "docker"
    assert audit_log.records()[0]["network_mode"] == "target"


def test_target_network_capability_without_runtime_map_never_uses_process_sandbox(
    tmp_path,
) -> None:
    action = _proposal(
        action_id="juice-directory-check-without-map",
        target="juice-test",
        tool="verify_sensitive_directory",
        parameters={"artifact_id": "source-server", "line": 288, "check": "source_metadata"},
        service="juice",
        endpoint="/ftp",
    ).model_copy(update={"environment": "sandbox"})
    approvals = InMemoryApprovalStore()
    approvals.record(
        action,
        ValidationResult(approved=True, action_id=action.id, reason="Synthetic approval"),
    )
    executor, sandbox, _ = _executor(tmp_path, approvals, environment="sandbox")
    executor._targets = TargetRegistry([
        TargetProfile(
            id="juice-test",
            environment="sandbox",
            services={"juice": TargetService(id="juice", type="node", internal_port=3000, runtime_endpoints=["/ftp"])},
            artifacts={"source-server": TargetArtifact(id="source-server", kind="javascript", path="server.ts")},
        )
    ])

    result = executor.execute_sequence([action])

    assert result.status == "denied"
    assert "trusted ready RuntimeServiceMap" in result.results[0].stderr
    assert sandbox.requests == []


@pytest.mark.parametrize(
    ("failure", "expected_code"),
    [
        (SandboxConfigurationError("dockerfile build failed (1)"), "BUILD_FAILED"),
        (SandboxConfigurationError("Unsupported target runtime: vm"), "UNSUPPORTED_RUNTIME"),
        (SandboxConfigurationError("Target path must stay inside the repository"), "ISOLATION_BLOCKED"),
        (SessionCleanupError("target cleanup could not be confirmed"), "ISOLATION_BLOCKED"),
    ],
)
def test_runtime_setup_failures_use_guard_error_codes(
    tmp_path,
    monkeypatch,
    failure: Exception,
    expected_code: str,
) -> None:
    action = _proposal(
        tool="observe_http_surface",
        service="backend",
        endpoint="/health/",
    )
    approvals, _ = _approve(action)

    class DockerBoundarySandbox:
        pass

    class FailingSession:
        def __enter__(self):
            raise failure

        def __exit__(self, *_: object) -> bool:
            return False

    class FailingManager:
        def __init__(self, **_: object) -> None:
            pass

        def open(self, _target):
            return FailingSession()

    monkeypatch.setattr(executor_module, "DockerSandbox", DockerBoundarySandbox)
    monkeypatch.setattr(executor_module, "SandboxManager", FailingManager)
    executor, _, _ = _executor(
        tmp_path,
        approvals,
        sandbox=DockerBoundarySandbox(),
    )

    result = executor.execute(action)

    assert result.status == "failed"
    assert result.error is not None
    assert result.error.code == expected_code


def test_executor_limits_replay_of_same_action(tmp_path) -> None:
    action = _proposal()
    approvals, _ = _approve(action)
    executor, sandbox, audit_log = _executor(tmp_path, approvals)

    first = executor.execute(action)
    second = executor.execute(action)

    assert first.status == "completed"
    assert second.status == "denied"
    assert second.exit_code == 75
    assert "run limit reached" in second.stderr
    assert len(sandbox.requests) == 1
    assert len(audit_log.records()) == 2


def test_unexpected_sandbox_error_becomes_structured_result(tmp_path) -> None:
    action = _proposal()
    approvals, _ = _approve(action)
    executor, _, audit_log = _executor(
        tmp_path,
        approvals,
        sandbox=FakeSandbox(raises=True),
    )

    result = executor.execute(action)

    assert result.status == "failed"
    assert result.exit_code == 127
    assert "Sandbox failed" in result.stderr
    assert result.error is not None
    assert result.error.code == "EXECUTION_FAILED"
    assert result.error.layer == "executor"
    assert audit_log.records()[0]["status"] == "failed"


def test_unexpected_sandbox_error_does_not_expose_raw_secret(tmp_path) -> None:
    action = _proposal()
    approvals, _ = _approve(action)
    secret = "sandbox-secret-value"
    executor, _, _ = _executor(
        tmp_path,
        approvals,
        sandbox=FakeSandbox(
            raises=True,
            exception_message=f"password={secret}",
        ),
    )

    result = executor.execute(action)

    assert secret not in result.stderr
    assert result.error is not None
    assert secret not in result.error.message


def test_executor_timeout_has_retryable_structured_error(tmp_path) -> None:
    action = _proposal()
    approvals, _ = _approve(action)
    executor, _, _ = _executor(
        tmp_path,
        approvals,
        sandbox=FakeSandbox(
            exit_code=124,
            stderr="Process timed out",
            timed_out=True,
        ),
    )

    result = executor.execute(action)

    assert result.status == "failed"
    assert result.timed_out is True
    assert result.error is not None
    assert result.error.code == "TIMEOUT"
    assert result.error.layer == "executor"
    assert result.error.retryable is True


def test_evidence_persistence_failure_is_structured_and_fail_closed(tmp_path) -> None:
    action = _proposal()
    approvals, _ = _approve(action)
    executor, _, audit_log = _executor(
        tmp_path,
        approvals,
        evidence_store=FailingEvidenceStore(),
    )

    result = executor.execute(action)

    assert result.status == "failed"
    assert result.exit_code == 1
    assert result.error is not None
    assert result.error.code == "PERSISTENCE_ERROR"
    assert result.error.layer == "storage"
    assert result.artifacts == []
    assert audit_log.records()[0]["status"] == "failed"


def test_audit_persistence_failure_is_structured_and_fail_closed(tmp_path) -> None:
    action = _proposal()
    approvals, _ = _approve(action)
    executor, _, _ = _executor(
        tmp_path,
        approvals,
        audit_log=FailingAuditLog(),
    )

    result = executor.execute(action)

    assert result.status == "failed"
    assert result.exit_code == 1
    assert result.error is not None
    assert result.error.code == "PERSISTENCE_ERROR"
    assert result.error.layer == "storage"
    record = JsonExecutionEvidenceStore(tmp_path / "evidence").get_execution(
        result.evidence_ref
    )
    assert record["status"] == "failed"
    assert record["error"]["code"] == "PERSISTENCE_ERROR"


def test_executor_exposes_only_predefined_tools(tmp_path) -> None:
    executor, _, _ = _executor(tmp_path, InMemoryApprovalStore())

    assert executor.registered_tools() == (
        "fix_target_stage",
        "inspect_dockerfile_user",
        "inspect_javascript_security",
        "inspect_python_password_assignment",
        "inspect_react_dangerous_html_flow",
        "observe_http_surface",
        "safe_noop",
        "sandbox_command",
        "verify_access_control",
        "verify_auth_reauthentication",
        "verify_demo_idor",
        "verify_juice_proof",
        "verify_redirect_destination",
        "verify_sensitive_directory",
        "verify_sql_injection",
    )


def test_dockerfile_user_capability_passes_only_trusted_artifact_registry(tmp_path) -> None:
    action = _proposal(
        tool="inspect_dockerfile_user",
        parameters={"artifact_id": "backend_dockerfile"},
    )
    approvals, _ = _approve(action)
    sandbox = FakeSandbox(
        stdout=(
            '{"schema":"cft.dockerfile_user_check.v2",'
            '"artifact_id":"backend_dockerfile",'
            '"dockerfile":"backend/Dockerfile","final_stage":1,'
            '"user_directive_present":false,"user":null,"user_line":null,'
            '"user_classification":"missing","verdict":"confirmed",'
            '"scope":"source","runtime_user_verified":false,'
            '"explanation":"source condition present"}'
        )
    )

    executor, sandbox, _ = _executor(tmp_path, approvals, sandbox=sandbox)
    result = executor.execute(action)

    assert result.status == "completed"
    assert len(sandbox.requests) == 1
    request = sandbox.requests[0]
    assert request.tool == "inspect_dockerfile_user"
    assert request.parameters == {"artifact_id": "backend_dockerfile"}
    assert request.repository_path == str((tmp_path / "target").resolve())
    assert request.artifacts["backend_dockerfile"] == {
        "kind": "dockerfile",
        "path": "backend/Dockerfile",
    }


def test_source_capability_rejects_extra_agent_parameters_before_sandbox(tmp_path) -> None:
    action = _proposal(
        tool="inspect_dockerfile_user",
        parameters={
            "artifact_id": "backend_dockerfile",
            "path": "../../not-allowed",
        },
    )
    approvals = InMemoryApprovalStore()
    approvals.record(
        action,
        ValidationResult(
            approved=True,
            action_id=action.id,
            reason="synthetic executor defense-in-depth test",
        ),
    )

    executor, sandbox, _ = _executor(tmp_path, approvals)
    result = executor.execute(action)

    assert result.status == "failed"
    assert result.exit_code == 2
    assert "exactly one artifact_id" in result.stderr
    assert sandbox.requests == []

def test_docker_backend_fails_closed_when_docker_is_unavailable(monkeypatch, tmp_path: Path,) -> None:
    monkeypatch.setattr(shutil, "which", lambda _: None)

    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
runtime:
  backend: docker
  network_mode: none

environments:
  allowed:
    - local
    - sandbox
    - staging

limits:
  executor:
    wall_time_seconds: 5
    cpu_time_seconds: 2
    memory_mb: 256
    max_file_bytes: 1048576
    max_processes: 8
    max_output_bytes: 16384
""",
        encoding="utf-8",
    )

    with pytest.raises(
        RuntimeError,
        match="Refusing to fall back to ProcessSandbox",
    ):
        SafeExecutor.from_config(
            approvals=InMemoryApprovalStore(),
            policy_file=policy_file,
            target_file=tmp_path / "targets.yaml",
            evidence_directory=tmp_path / "evidence",
            audit_log_path=tmp_path / "audit.jsonl",
            workspace_directory=tmp_path / "workspace",
        )


def test_executor_uses_dotenv_sandbox_image_when_process_environment_is_unset(
    monkeypatch, tmp_path: Path,
) -> None:
    pinned_image = "registry.example/sandbox@sha256:" + "b" * 64
    monkeypatch.delenv("CFT_SANDBOX_IMAGE", raising=False)
    monkeypatch.setattr(app_settings, "sandbox_image", pinned_image)
    policy_file = tmp_path / "policy.yaml"
    policy_file.write_text(
        """
runtime:
  backend: process
  network_mode: none
  sandbox_image: example.invalid/sandbox@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
environments:
  allowed: [local, sandbox, staging]
""",
        encoding="utf-8",
    )
    configured = SafeExecutor.from_config(
        approvals=InMemoryApprovalStore(),
        policy_file=policy_file,
        target_profile=TargetProfile(id="dotenv-image-test"),
        evidence_directory=tmp_path / "configured-evidence",
        audit_log_path=tmp_path / "configured-audit.jsonl",
        workspace_directory=tmp_path / "configured-workspaces",
    )

    assert configured._policy.sandbox_image == pinned_image


def test_sandbox_command_never_falls_back_to_process_sandbox(tmp_path) -> None:
    action = _proposal(
        tool="sandbox_command",
        parameters={"argv": ["python", "-V"], "cwd": "/target"},
    )
    approvals, _ = _approve(action)
    executor, sandbox, _ = _executor(tmp_path, approvals)

    result = executor.execute(action)

    assert result.status == "denied"
    assert "Docker security boundary" in result.stderr
    assert sandbox.requests == []


def test_sandbox_command_does_not_use_networked_managed_lab(tmp_path) -> None:
    action = _proposal(
        tool="sandbox_command",
        parameters={"argv": ["python", "-V"], "cwd": "/target"},
    )
    approvals, _ = _approve(action)
    executor, sandbox, _ = _executor(tmp_path, approvals)
    lab = FakeSandbox()
    executor._managed_lab = lab

    result = executor.execute(action)

    assert result.status == "denied"
    assert sandbox.requests == []
    assert lab.requests == []


def test_sandbox_command_cannot_mix_with_target_network_capability(tmp_path) -> None:
    action = _proposal(
        tool="sandbox_command",
        parameters={"argv": ["python", "-V"], "cwd": "/target"},
    )
    executor, _, _ = _executor(tmp_path, InMemoryApprovalStore())
    observation = _proposal(action_id="observation", tool="observe_http_surface")
    with pytest.raises(ValueError, match="cannot share"):
        executor.execute_sequence([action, observation])
