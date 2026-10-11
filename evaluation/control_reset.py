"""A03 operator-only reset experiment. Fixed Stage 1 stages, no new Agent tool."""
from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from uuid import uuid4

from app.stage1_e2e import pinned_image
from evaluation.benchmark_protocol import ROOT, load_protocol
from evaluation.control_catalog import TARGET, pinned_files, sha
from evaluation.control_patch import redirect_patch
from evaluation.control_workspace import patched_snapshot
from evidence.audit import JsonlAuditLog
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore
from executor.executor import SafeExecutor
from executor.fix_runtime import DockerFixRuntime
from fix_verification.service import FixVerificationService
from fix_verification.workspace import snapshot, tree_digest
from schemas.action import ActionProposal
from schemas.target import TargetFixConfig, TargetProfile
from validator.validator import PolicyValidator


def absent(kind: str, name: str) -> bool:
    result = subprocess.run(["docker", kind, "ls", "--format", "{{.Name}}" if kind == "network" else "{{.Names}}", "--filter", "name=" + name],
                            capture_output=True, text=True, timeout=15, check=False)
    return result.returncode == 0 and name not in result.stdout.splitlines()


def experiment(target: Path, output: Path, *, cycles: int = 2, patch_redirect: bool = False) -> dict:
    if cycles < 2:
        raise ValueError("Two independent reset cycles required")
    pinned_files(target)
    before = snapshot(target)
    profile = TargetProfile.from_yaml(ROOT / "targets/juice-presentation.yaml", repository_path_override=target)
    profile = profile.model_copy(update={"fix_verification": TargetFixConfig(
        image=pinned_image("cft-fix-juice:stage1"), service="juice", source_commit=load_protocol().target_commit)})
    output.mkdir(parents=True, exist_ok=True)
    report = {"schema_version": "a03.reset_evidence.v1", "target_commit": load_protocol().target_commit,
        "image": profile.fix_verification.image, "original_tree_sha256": tree_digest(before), "cycles": []}
    report["bootstrap_sha256"] = sha((ROOT / "evaluation/control_bootstrap.cjs").read_bytes())
    patch = redirect_patch(target) if patch_redirect else None
    if patch:
        report["patch"] = {k:v for k,v in patch.items() if k != "diff"}
        (output / "redirect.patch").write_text(patch["diff"], encoding="utf-8", newline="\n")
    for number in range(cycles):
        cycle = {"properties": {}, "stages": {}, "cleanup": False, "original_unchanged": False}
        runtime = None
        with tempfile.TemporaryDirectory(prefix="cft-a03-reset-") as directory:
            source = Path(directory) / "source"
            source.mkdir()
            if patch:
                with patched_snapshot(target, patch["file"], patch["diff"], patch["source_sha256"], patch["patch_sha256"]) as patched:
                    snapshot(patched, source)
            else:
                snapshot(target, source)
            isolated = profile.model_copy(update={"repository_path": source})
            runtime = DockerFixRuntime(isolated)
            cycle.update(container=runtime.id, network=runtime.network)
            approvals = InMemoryApprovalStore()
            stage_dir = output / f"cycle-{number+1}"
            store = JsonExecutionEvidenceStore(stage_dir / "evidence")
            audit = JsonlAuditLog(stage_dir / "audit.jsonl")
            policy = ROOT / "policies/default.yaml"
            executor = SafeExecutor.from_config(approvals=approvals, policy_file=policy, target_profile=isolated,
                evidence_directory=store.directory, audit_log_path=audit.path,
                workspace_directory=stage_dir / "workspaces", backend_override="docker")
            validator = PolicyValidator.from_yaml(policy, target_profile=isolated)
            try:
                runtime.open()
                executor.bind_fix_runtime(runtime)
                for stage in ("prepare", "build", "tests", "start", "smoke"):
                    action = ActionProposal(id=f"a03-{uuid4().hex}-{stage}", tool="fix_target_stage",
                        target=isolated.id, environment=isolated.environment,
                        parameters={"adapter":"juice_node_v1", "stage":stage},
                        purpose="Operator-owned A03 fresh fixture stage", expected_evidence="Persisted stage result")
                    execution, evidence = FixVerificationService._execute(action, executor, approvals, validator, store, audit)
                    passed = execution.status == "completed" and execution.exit_code == 0 and evidence.reliability == "high"
                    cycle["stages"][stage] = {"passed": passed, "execution_ref": execution.evidence_ref, "audit_ref": execution.audit_ref}
                    if not passed:
                        raise RuntimeError("Required stage failed: " + stage)
                # Fixed evaluator fixture preparation/assertions; not a model-selected capability.
                script = (ROOT / "evaluation/control_bootstrap.cjs").read_text(encoding="utf-8")
                if patch:
                    script = "process.env.CFT_A03_REDIRECT='1';\n" + script
                result = runtime._control(["docker", "exec", "--workdir", "/workspace/target", runtime.id,
                                           "node", "-e", script], timeout=60)
                if result.exit_code != 0 or result.timed_out:
                    cycle["fixture_failure_stage"] = result.stderr.strip() if result.stderr.startswith("A03 fixture assertion failed at ") else "unavailable"
                    raise RuntimeError("Identity/object/availability/property precondition failed")
                body = json.loads(result.stdout)
                cycle["baseline"] = body["baseline"]
                cycle["properties"] = body["properties"]
            except (OSError, ValueError, RuntimeError, TimeoutError):
                cycle["failure"] = "Runtime preparation/assertion failed; no safe verdict"
            finally:
                closed = runtime.close()
                cycle["cleanup"] = closed and absent("container", runtime.id) and absent("network", runtime.network)
                cycle["original_unchanged"] = snapshot(target) == before
                for prop in cycle["properties"].values():
                    prop.update({key: cycle["stages"].get(key, {}).get("passed", False) for key in ("build","tests","start","smoke")})
                    prop.update(cleanup=cycle["cleanup"], original_unchanged=cycle["original_unchanged"])
        cycle["snapshot_removed"] = not Path(directory).exists()
        for prop in cycle["properties"].values():
            prop["snapshot_removed"] = cycle["snapshot_removed"]
        report["cycles"].append(cycle)
        (output / "reset-evidence.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")
        print(f"A03 reset cycle {number+1}: stages={len(cycle['stages'])}, properties={len(cycle['properties'])}, cleanup={cycle['cleanup']}", flush=True)
    if len({x.get("baseline") for x in report["cycles"]}) != 1 or any(not x.get("baseline") for x in report["cycles"]):
        raise RuntimeError("Fresh logical state not reproducible")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=TARGET)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts/a03-checks/reset")
    parser.add_argument("--patch-redirect", action="store_true")
    args = parser.parse_args()
    experiment(args.target, args.output, patch_redirect=args.patch_redirect)


if __name__ == "__main__":
    main()
