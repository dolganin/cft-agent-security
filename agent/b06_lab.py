"""Bind B06 provisioning to the existing graph's Validator and Executor."""
from agent.lab import ManagedAgentLab
from evidence.audit import JsonlAuditLog
from evidence.store import JsonExecutionEvidenceStore
from executor.access_fixture import WORKER_IMAGE
from executor.approvals import InMemoryApprovalStore
from executor.b06_runtime import B06Runtime
from executor.executor import SafeExecutor
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_policy import SandboxLimits, SandboxPolicy
from executor.targets import TargetRegistry
from security.verification_binding import resolve_binding


class B06GraphLab(ManagedAgentLab):
    def __init__(self, profile, finding, output, *, safe_control=False):
        resolution = resolve_binding(profile, finding)
        if resolution.binding is None:
            raise ValueError("B06 needs a unique source/route binding: " + resolution.reason)
        self.runtime = B06Runtime(profile, resolution.binding.tool, output, safe_control=safe_control)
        self.runtime.open()
        try:
            self.executor_target = self.runtime.profile
            self.runtime_services = self.runtime.runtime_map()
            policy = SandboxPolicy(backend="docker", sandbox_image=WORKER_IMAGE,
                limits=SandboxLimits(wall_time_seconds=60, max_output_bytes=65536))
            self.executor = SafeExecutor(approvals=InMemoryApprovalStore(),
                targets=TargetRegistry([self.runtime.profile]),
                evidence_store=JsonExecutionEvidenceStore(self.runtime.output / "execution"),
                audit_log=JsonlAuditLog(self.runtime.output / "audit.jsonl"),
                sandbox=DockerSandbox(policy), run_limiter=RunLimiter(1, 1), policy=policy)
            self._token = None
            self.executor.bind_verification_runtime(self.runtime)
        except Exception:
            self.runtime.close()
            raise

    def __exit__(self, exc_type, exc, traceback):
        try:
            return super().__exit__(exc_type, exc, traceback)
        finally:
            self.runtime.close()
