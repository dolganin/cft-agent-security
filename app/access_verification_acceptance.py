"""Run the registered B05 checks against a fresh local B04 Docker fixture."""
import argparse
import json
import subprocess
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.access_control import AccessVerificationRuntime
from executor.access_fixture import COMMIT
from executor.approvals import InMemoryApprovalStore, proposal_digest
from executor.executor import SafeExecutor
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_policy import SandboxLimits, SandboxPolicy
from executor.targets import TargetRegistry
from schemas.action import ActionProposal
from schemas.finding import Finding
from schemas.target import TargetProfile
from schemas.verification_binding import BindingResolution
from security.access_verification import ACCESS_CHECKS, binding_id
from security.verification_binding import resolve_binding
from validator.validator import PolicyValidator

ROOT = Path(__file__).resolve().parents[1]
PROFILE_FILE = ROOT / "targets/juice-b05-access-fixture.yaml"
POLICY_FILE = ROOT / "policies/default.yaml"
B05_POLICY_FILE = ROOT / "policies/b05-access.yaml"


def _write(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def _action(profile, check_id: str) -> tuple[ActionProposal, BindingResolution]:
    registration = ACCESS_CHECKS[check_id]
    route = next(item for item in profile.verification_routes if item.id == registration.route_id)
    # Prefer an operator-mapped source span unique to this route. Registration
    # lines may be shared by multiple versioned candidates for one endpoint.
    source_selector = next(
        (item for item in route.sources if item.file != route.registration.file),
        route.registration,
    )
    source = profile.repository_path / source_selector.file
    anchor = source_selector.anchor
    lines = source.read_text(encoding="utf-8").splitlines()
    matches = [index for index, line in enumerate(lines, 1) if anchor in line]
    if len(matches) != 1:
        raise ValueError("Registered B05 source anchor is missing or ambiguous")
    finding = Finding(
        id="operator-" + registration.route_id,
        source="b05-operator-acceptance",
        rule_id="idor",
        title="Operator-mapped access-control check",
        description="B05 acceptance binds a fixed check to one registered source route.",
        file=source_selector.file,
        line_start=matches[0],
        line_end=matches[0],
    )
    resolution = resolve_binding(profile, finding)
    if resolution.status != "bound" or resolution.binding is None:
        raise ValueError("B01 could not bind the B05 operator route")
    binding = resolution.binding
    if binding.route_id != registration.route_id:
        raise ValueError("B01 resolved a different or ambiguous B05 route")
    action = ActionProposal(
        id="b05-" + uuid4().hex,
        tool="verify_access_control",
        target=profile.id,
        environment=profile.environment,
        parameters={"check_id": registration.check_id},
        purpose="Execute one closed operator-registered access-control verification.",
        expected_evidence="Identity-bound controls, repeated access result, reset and cleanup evidence.",
        service="juice",
        endpoint=registration.endpoint,
        verification_binding=binding,
    )
    return action, resolution


def _run_check(repository: Path, output: Path, profile, check_id: str) -> dict:
    directory = output / check_id
    directory.mkdir(parents=True, exist_ok=False)
    result = {"check_id": check_id, "status": "failed", "cleanup_complete": False}
    action, binding_resolution = _action(profile, check_id)
    validator = PolicyValidator.from_yaml(
        POLICY_FILE, target_profile=profile, capability_policy_file=B05_POLICY_FILE,
    )
    validation = validator.validate(action)
    _write(directory / "action.json", action.model_dump(mode="json"))
    _write(directory / "binding-resolution.json", binding_resolution.model_dump(mode="json"))
    _write(directory / "validator.json", validation.model_dump(mode="json"))
    if not validation.approved:
        result.update(status="unsupported", cleanup_complete=True, deny_reason=validation.reason)
        _write(directory / "check-summary.json", result)
        return result

    runtime = AccessVerificationRuntime(profile=profile, target_repository=repository,
                                        output_directory=directory, active_check_id=check_id)
    try:
        runtime.prepare()
        approvals = InMemoryApprovalStore()
        approvals.record(action, validation)
        store = JsonExecutionEvidenceStore(directory / "executor-evidence")
        policy = SandboxPolicy(
            backend="docker", sandbox_image=profile.access_fixture.worker_image,
            network_mode="none", limits=SandboxLimits(wall_time_seconds=20, cpu_time_seconds=5),
        )
        executor = SafeExecutor(
            approvals=approvals,
            targets=TargetRegistry([profile]),
            evidence_store=store,
            audit_log=JsonlAuditLog(directory / "audit.jsonl"),
            sandbox=DockerSandbox(policy),
            run_limiter=RunLimiter(1, 1),
            policy=policy,
        )
        executor.bind_access_verifier(runtime)
        sequence = executor.execute_sequence([action], runtime_services=runtime.runtime_services())
        execution = sequence.results[0].execution
        record = store.get_execution(execution.evidence_ref)
        evidence = build_evidence(
            action=action,
            execution=execution,
            record=record,
            evidence_loaded=record is not None,
            artifact_refs=execution.artifacts,
            hypothesis_id="b05-" + check_id,
            sandbox_session_id=runtime.run_session_id,
        )
        _write(directory / "execution.json", execution.model_dump(mode="json"))
        _write(directory / "evidence.json", evidence.model_dump(mode="json"))
        trace = evidence.observation.facts.get("b05_trace")
        if isinstance(trace, dict):
            _write(directory / "trace.json", trace)
        result.update(
            status="passed" if execution.status == "completed" and evidence.verdict in {"confirmed", "rejected", "inconclusive"}
            else "technical_failure",
            verdict=evidence.verdict,
            execution_status=execution.status,
            action_digest=proposal_digest(action),
            binding_id=binding_id(action),
            source_snapshot_digest=action.verification_binding.source_snapshot,
            evidence_ref=execution.evidence_ref,
            audit_ref=execution.audit_ref,
            executor_artifacts=execution.artifacts,
            request_count=(trace.get("exchange_count") if isinstance(trace, dict) else None),
            reset_complete=(trace.get("reset_complete") if isinstance(trace, dict) else False),
            integrity_verified=(trace.get("integrity_verified") if isinstance(trace, dict) else False),
        )
        return result
    finally:
        if runtime.lab.resources is not None:
            result["cleanup_complete"] = runtime.lab.close()
        else:
            result["cleanup_complete"] = any(
                item.get("phase") == "destroy" and item.get("cleanup_complete") is True
                for item in runtime.lab.records
            )
        _write(directory / "check-summary.json", result)


def run(repository: Path, output: Path, check_ids: list[str] | None = None) -> dict:
    repository = repository.resolve(strict=True)
    output = output.resolve()
    if output.exists() or repository in output.parents or output in repository.parents:
        raise ValueError("B05 output must be a fresh directory outside the target checkout")
    profile = TargetProfile.from_yaml(PROFILE_FILE, repository_path_override=repository)
    if profile.access_fixture is None or not profile.access_fixture.b05_write_candidate:
        raise ValueError("The fixed B05 operator fixture profile is required")
    default_checks = ["juice-basket-own-read-v1", "juice-address-own-write-v1"]
    selected_checks = list(check_ids) if check_ids is not None else default_checks
    if (not selected_checks or len(set(selected_checks)) != len(selected_checks)
            or any(check_id not in ACCESS_CHECKS for check_id in selected_checks)):
        raise ValueError("B05 check selection must contain unique registered check IDs")
    output.mkdir(parents=True)
    source_commit = subprocess.check_output(
        ["git", "-C", str(repository), "rev-parse", "HEAD"], text=True
    ).strip()
    if source_commit != COMMIT:
        raise ValueError("B05 accepts only the pinned Juice Shop development checkout")
    summary = {
        "schema_version": ("b05.acceptance.v1" if selected_checks == default_checks
                            else "b05.acceptance.v2"),
        "base_commit": "7b4f8572af99f0432c8afd1454232378e9a21d28",
        "target_commit": source_commit,
        "status": "failed",
        "checks": [],
        "llm_requests": 0,
        "external_targets": 0,
        "ground_truth_read": False,
        "limitations": [
            "Synthetic B04 operator fixtures are used; no benchmark labels or holdout inputs are loaded.",
            "The R01 OWN-READ schedule has 7 HTTP exchanges; OWN-WRITE has an explicit 12-exchange maximum.",
        ],
    }
    try:
        for check_id in selected_checks:
            summary["checks"].append(_run_check(repository, output, profile, check_id))
        if all(check["status"] == "passed" and check.get("verdict") in {"confirmed", "rejected"}
               and check["cleanup_complete"] for check in summary["checks"]):
            summary["status"] = "passed"
        elif all(check["status"] in {"passed", "unsupported"}
                 for check in summary["checks"]):
            summary["status"] = "incomplete"
    finally:
        _write(output / "manifest.json", summary)
        seal = {
            path.relative_to(output).as_posix(): sha256(path.read_bytes()).hexdigest()
            for path in sorted(output.rglob("*")) if path.is_file() and path.name != "seal.json"
        }
        _write(output / "seal.json", seal)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, required=True,
                        help="Existing pinned local Juice Shop checkout; it is read-only")
    parser.add_argument("--output", type=Path, required=True,
                        help="Fresh artifact directory outside the target checkout")
    parser.add_argument("--check-id", action="append", choices=sorted(ACCESS_CHECKS),
                        help="Run only the explicitly selected registered check (repeat for a fixed set)")
    args = parser.parse_args()
    result = run(args.repository, args.output, args.check_id)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "passed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
