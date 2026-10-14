"""R04 opt-in canonical graph, one selected model route, sealed observations."""
from __future__ import annotations

import argparse
import json
import subprocess
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path

from agent.graph import build_graph
from agent.lab import executor_context
from agent.llm_model import FallbackLLMAgentModel
from agent.research import ResearchAgentModel, research_context
from app.config import settings
from app.research_plan import POLICY_IMAGE, ROOT
from evidence.audit import JsonlAuditLog
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore
from executor.executor import SafeExecutor
from executor.research_runtime import ResearchRuntime
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_policy import SandboxPolicy
from executor.targets import TargetRegistry
from schemas.finding import Finding
from schemas.research import HttpServiceScope
from schemas.research_agent import ResearchLimits
from schemas.runtime import RuntimeServiceMap
from schemas.target import TargetProfile
from validator.validator import PolicyValidator


def run_research(*, profile, configuration, finding, output, client, limits=None):
    limits = limits or ResearchLimits()
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("Choose a fresh output directory")
    if set(configuration) - {"worker_image", "source_files", "runtime_service_map", "http_grants", "services", "network_name"}:
        raise ValueError("Unknown operator configuration fields")
    files = configuration.get("source_files")
    if files is None:
        files = subprocess.check_output(["git", "ls-files"], cwd=profile.repository_path,
                                        text=True).splitlines()
    services = {name: HttpServiceScope.model_validate(value)
                for name, value in configuration.get("services", {}).items()}
    runtime_services = None
    network_name = configuration.get("network_name")
    if "runtime_service_map" in configuration:
        if services or network_name:
            raise ValueError("Use exactly one operator runtime registry")
        runtime_services = RuntimeServiceMap.model_validate(configuration["runtime_service_map"])
        services = ResearchRuntime.services_from_runtime_map(profile, runtime_services,
                                                             configuration.get("http_grants", {}))
        network_name = runtime_services.network_name
    output.mkdir(parents=True)
    state = {"finding": finding, "target_profile": profile,
             "started_at": datetime.now(UTC)}
    with ExitStack() as stack:
        runtime = stack.enter_context(ResearchRuntime(target=profile, source_files=files,
            worker_image=configuration["worker_image"], output=output / "runtime", services=services,
            network_name=network_name, runtime_services=runtime_services,
            max_actions=limits.max_steps, wall_seconds=limits.wall_seconds))
        validator = PolicyValidator.from_yaml(ROOT / "policies/research.yaml", target_profile=profile)
        validator.bind_research_scope(runtime.scope)
        policy = SandboxPolicy(sandbox_image=POLICY_IMAGE)
        executor = SafeExecutor(approvals=InMemoryApprovalStore(), targets=TargetRegistry([profile]),
            evidence_store=JsonExecutionEvidenceStore(output / "evidence"),
            audit_log=JsonlAuditLog(output / "audit.jsonl"), sandbox=DockerSandbox(policy),
            run_limiter=RunLimiter(), policy=policy)
        executor.bind_research_runtime(runtime)
        model = ResearchAgentModel(client=client, scope=runtime.scope, validator=validator, limits=limits)
        stack.enter_context(research_context(model))
        stack.enter_context(executor_context(executor))
        state["research_scope"] = runtime.scope
        if runtime_services is not None:
            state["runtime_services"] = runtime_services
        # Checkpoints are inspectable diagnostics, NOT resumable live approvals.
        with (output / "events.jsonl").open("x") as events:
            for update in build_graph().stream(state, config={"recursion_limit": 1024}, stream_mode="updates"):
                for node, values in update.items():
                    state.update(values)
                    checkpoint = {"node": node, "status": state.get("status"),
                                  "step": state.get("iteration_count", 0),
                                  "stop_reason": state.get("stop_reason"),
                                  "progress": model.progress.model_dump(mode="json")}
                    events.write(json.dumps(checkpoint, ensure_ascii=False) + "\n")
                    events.flush()
                    (output / "progress.json").write_text(model.progress.model_dump_json(indent=2))
        report = state["final_report"]
        (output / "report.json").write_text(report.model_dump_json(indent=2))
    summary = {"schema_version": "cft.research.r04.v1", "benchmark_measurement": False,
               "status": report.status, "stop_reason": state.get("stop_reason"),
               "actions": runtime.actions, "http_requests": runtime.requests,
               "model_calls": model.progress.model_calls,
               "cleanup_verified": runtime.closed,
               "independent_verification": "pending R06"}
    (output / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    return state, summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--operator-config", type=Path, required=True)
    parser.add_argument("--finding", type=Path, required=True)
    parser.add_argument("--limits", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    client = FallbackLLMAgentModel.from_settings(settings).client
    if len(client.routes) != 1:
        raise ValueError("Select exactly one route in CFT_LLM_ROUTES for R04")
    profile = TargetProfile.from_yaml(args.profile.resolve(), repository_path_override=args.checkout.resolve())
    limits = ResearchLimits.model_validate(json.loads(args.limits.read_text())) if args.limits else ResearchLimits()
    _, summary = run_research(profile=profile, configuration=json.loads(args.operator_config.read_text()),
        finding=Finding.model_validate(json.loads(args.finding.read_text())), output=args.output,
        client=client, limits=limits)
    print(json.dumps(summary))


if __name__ == "__main__":
    main()
