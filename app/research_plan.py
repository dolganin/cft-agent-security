"""Operator CLI: run a typed research action plan through the canonical boundaries."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path
from uuid import uuid4

from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore
from executor.executor import SafeExecutor
from executor.research_runtime import ResearchRuntime
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_policy import SandboxPolicy
from executor.targets import TargetRegistry
from schemas.research import HttpServiceScope
from schemas.runtime import RuntimeServiceMap
from schemas.target import TargetProfile
from tools.research import research_proposal
from validator.validator import PolicyValidator

ROOT = Path(__file__).resolve().parents[1]
POLICY_IMAGE = "python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"


def execute_plan(*, profile: TargetProfile, configuration: dict, actions: list[dict], output: Path, role_headers=None):
    if (set(configuration) - {"worker_image", "network_name", "services", "source_files", "runtime_service_map", "http_grants"}
            or not 1 <= len(actions) <= 64):
        raise ValueError("Invalid operator configuration or action plan")
    if "source_files" in configuration:
        files = configuration["source_files"]
    else:
        files = subprocess.check_output(["git", "ls-files"], cwd=profile.repository_path,
                                        text=True).splitlines()
    services = {name: HttpServiceScope.model_validate(value)
                for name, value in configuration.get("services", {}).items()}
    runtime_services = None
    network_name = configuration.get("network_name")
    if "runtime_service_map" in configuration:
        if services or network_name:
            raise ValueError("Use one operator runtime registry")
        runtime_services = RuntimeServiceMap.model_validate(configuration["runtime_service_map"])
        services = ResearchRuntime.services_from_runtime_map(profile, runtime_services,
                                                             configuration.get("http_grants", {}))
        network_name = runtime_services.network_name
    with ResearchRuntime(target=profile, source_files=files,
                         worker_image=configuration["worker_image"], output=output / "runtime",
                         services=services, network_name=network_name,
                         role_headers=role_headers,
                         runtime_services=runtime_services) as runtime:
        validator = PolicyValidator.from_yaml(ROOT / "policies/research.yaml", target_profile=profile)
        validator.bind_research_scope(runtime.scope)
        store = JsonExecutionEvidenceStore(output / "evidence")
        policy = SandboxPolicy(sandbox_image=POLICY_IMAGE)
        executor = SafeExecutor(approvals=InMemoryApprovalStore(), targets=TargetRegistry([profile]),
                                evidence_store=store, audit_log=JsonlAuditLog(output / "audit.jsonl"),
                                sandbox=DockerSandbox(policy), run_limiter=RunLimiter(), policy=policy)
        executor.bind_research_runtime(runtime)
        result = []
        for iteration, item in enumerate(actions, 1):
            if set(item) - {"tool", "parameters", "purpose", "expected_evidence", "service", "endpoint"}:
                raise ValueError("Action plan cannot set permissions or provenance")
            action = research_proposal(scope=runtime.scope, action_id="research-" + uuid4().hex,
                                       iteration=iteration, **item)
            validation = validator.validate(action)
            execution = None
            evidence = None
            if validation.approved:
                executor.record_approval(action, validation)
                execution = executor.execute(action)
                record = store.get_execution(execution.evidence_ref)
                evidence = build_evidence(action=action, execution=execution, record=record,
                                          evidence_loaded=True, artifact_refs=execution.artifacts,
                                          hypothesis_id="operator-research")
            entry = {"action": action.model_dump(mode="json"), "validation": validation.model_dump(mode="json"),
                     "execution": execution.model_dump(mode="json") if execution else None,
                     "evidence": evidence.model_dump(mode="json") if evidence else None}
            result.append(entry)
            (output / "actions.json").write_text(json.dumps(result, indent=2) + "\n")
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--operator-config", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError("Choose a fresh output directory")
    profile = TargetProfile.from_yaml(args.profile.resolve(), repository_path_override=args.checkout.resolve())
    result = execute_plan(profile=profile, configuration=json.loads(args.operator_config.read_text()),
                          actions=json.loads(args.plan.read_text()), output=output)
    print(json.dumps({"actions": len(result), "output": str(output), "benchmark_measurement": False}))


if __name__ == "__main__":
    main()
