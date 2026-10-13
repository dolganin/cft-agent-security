"""B01 real Docker acceptance on pinned Juice Shop, without model calls.

Only operator-selected local source and fixed registered checks are used. Target
code never executes on the host. Original checkout and A01-A08 data stay unchanged.
"""
import argparse
import json
import shutil
import subprocess
import tempfile
import time
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from agent.verification import register_source_artifacts, verification_candidates
from evaluation.scanner_baseline import validate_target
from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore
from executor.executor import SafeExecutor
from executor.sandbox import DockerSandbox, RunLimiter
from executor.sandbox_policy import SandboxLimits, SandboxPolicy
from executor.targets import TargetRegistry
from sast.identity import normalize_finding
from schemas.action import ActionProposal
from schemas.finding import Finding
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.target import TargetProfile
from security.verification_binding import source_snapshot
from validator.validator import PolicyValidator

COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
TARGET_IMAGE = "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
WORKER_IMAGE = "python@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7"


def command(argv, check=True):
    result = subprocess.run(argv, capture_output=True, text=True, timeout=45, check=False)
    if check and result.returncode:
        raise RuntimeError(result.stderr[-1500:])
    return result.stdout.strip()


def write(path, data):
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def run(repository, output):
    repository, output = Path(repository).resolve(), Path(output).resolve()
    if output.exists() or output.is_relative_to(repository) or repository.is_relative_to(output):
        raise ValueError("Use a fresh output directory outside the target")
    output.mkdir(parents=True)
    run_id = "b01-" + uuid4().hex[:12]
    network, container = run_id + "-net", run_id + "-juice"
    manifest = {"id": run_id, "target_commit": COMMIT, "checks": [],
                "status": "failed", "errors": [], "cleanup_complete": False}
    root = Path(__file__).resolve().parents[1]
    inputs = ["app/binding_acceptance.py", "agent/verification.py", "agent/model.py", "agent/nodes.py",
              "security/verification_binding.py", "schemas/verification_binding.py", "schemas/action.py",
              "schemas/target.py", "schemas/runtime.py", "executor/executor.py", "executor/worker.py",
              "executor/runtime_service_map.py", "evidence/interpreter.py", "validator/validator.py",
              "targets/juice-verification.yaml", "policies/default.yaml", "pyproject.toml"]
    manifest["implementation_sha256_lf"] = {
        name: sha256((root / name).read_bytes().replace(b"\r\n", b"\n")).hexdigest() for name in inputs}
    manifest["images"] = {"target": TARGET_IMAGE, "worker": WORKER_IMAGE}
    try:
        original = validate_target(repository, SimpleNamespace(target_commit=COMMIT))
        for image in [TARGET_IMAGE, WORKER_IMAGE]:
            command(["docker", "image", "inspect", image])
        command(["docker", "network", "create", "--internal", network])
        command(["docker", "run", "-d", "--pull=never", "--name", container,
                 "--network", network, "--network-alias", "juice", "--cap-drop=ALL",
                 "--security-opt=no-new-privileges:true", "--memory=768m", "--cpus=2",
                 "--pids-limit=128", TARGET_IMAGE])
        deadline = time.monotonic() + 90
        while True:
            # Inspect an explicit marker, not merely an empty successful stdout.
            ready = command(["docker", "exec", container, "/nodejs/bin/node", "-e",
                             "require('http').get('http://127.0.0.1:3000/',r=>{r.resume();if(r.statusCode===200)console.log('ready')}).on('error',()=>process.exit(1))"], check=False)
            if ready == "ready":
                break
            if time.monotonic() > deadline:
                raise RuntimeError("Target readiness timed out")
            time.sleep(1)
        policy = SandboxPolicy(backend="docker", sandbox_image=WORKER_IMAGE,
                               limits=SandboxLimits(wall_time_seconds=10, cpu_time_seconds=3))
        with tempfile.TemporaryDirectory(prefix="cft-b01-") as directory:
            snapshot = Path(directory)
            template = TargetProfile.from_yaml("targets/juice-verification.yaml",
                                                repository_path_override=repository)
            _, initial_hashes = source_snapshot(template)
            for name in initial_hashes:
                dest = snapshot / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(repository / name, dest)
            profile = template.model_copy(update={"repository_path": snapshot})
            findings = []
            for name, file, marker, family in [
                ("search", "routes/search.ts", "models.sequelize.query(", "sql-injection"),
                ("login", "routes/login.ts", "models.sequelize.query(", "sql-injection"),
                ("ftp", "server.ts", "app.use('/ftp', serveIndexMiddleware", "file-exposure"),
            ]:
                lines = (snapshot / file).read_text(encoding="utf-8").splitlines()
                line = next(i for i, text in enumerate(lines, 1) if marker in text)
                findings.append(normalize_finding(Finding(
                    id=name, source="operator_acceptance", rule_id=family, title=name,
                    description="B01 binding acceptance, not a discovery benchmark",
                    file=file, line_start=line, line_end=line,
                ), repository_root=snapshot))
            profile = register_source_artifacts(profile, findings, snapshot)
            store = JsonExecutionEvidenceStore(output / "execution")
            approvals = InMemoryApprovalStore()
            executor = SafeExecutor(approvals=approvals, targets=TargetRegistry([profile]),
                                    evidence_store=store, audit_log=JsonlAuditLog(output / "audit.jsonl"),
                                    sandbox=DockerSandbox(policy), run_limiter=RunLimiter(1, 1), policy=policy)
            for stage in ["original", "shifted"]:
                if stage == "shifted":
                    for name in initial_hashes:
                        path = snapshot / name
                        path.write_bytes(b"// B01 inserted header\n\n\n" + path.read_bytes())
                _, hashes = source_snapshot(profile)
                for name in hashes:
                    destination = output / "sources" / stage / name
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(snapshot / name, destination)
                runtime = RuntimeServiceMap(session_id=run_id + "-" + stage, network_name=network,
                                            source_files_sha256=hashes, services={
                    "juice": RuntimeService(name="juice", address="http://juice:3000", ready=True,
                                            readiness_source="http_probe",
                                            allowed_endpoints=profile.services["juice"].runtime_endpoints),
                })
                for finding in findings:
                    candidate, = verification_candidates({"target_profile": profile, "finding": finding,
                                                           "runtime_services": runtime})
                    action = ActionProposal(
                        id=stage + "-" + finding.id, target=profile.id, environment=profile.environment,
                        tool=candidate["tool"], parameters=candidate["parameters"],
                        service=candidate["service"], endpoint=candidate["endpoint"],
                        purpose=candidate["purpose"], expected_evidence="Controlled runtime observation",
                        verification_binding=candidate["verification_binding"],
                    )
                    validation = PolicyValidator.from_yaml("policies/default.yaml", target_profile=profile).validate(action)
                    approvals.record(action, validation)
                    sequence = executor.execute_sequence([action], runtime_services=runtime)
                    execution = sequence.results[0].execution
                    record = store.get_execution(execution.evidence_ref)
                    evidence = build_evidence(action=action, execution=execution, record=record,
                                              evidence_loaded=True, artifact_refs=execution.artifacts,
                                              hypothesis_id="b01-" + finding.id,
                                              sandbox_session_id=runtime.session_id)
                    write(output / (action.id + ".json"), {
                        "action": action.model_dump(mode="json"), "validation": validation.model_dump(),
                        "evidence": evidence.model_dump(mode="json"),
                    })
                    manifest["checks"].append({"stage": stage, "finding": finding.id,
                                               "verdict": evidence.verdict,
                                               "snapshot": action.verification_binding.source_snapshot})
                    if evidence.verdict != "confirmed":
                        raise RuntimeError("Expected real confirmation: " + action.id)
        if validate_target(repository, SimpleNamespace(target_commit=COMMIT)) != original:
            raise RuntimeError("Original source changed")
        manifest["original_unchanged"] = True
        manifest["status"] = "passed"
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        manifest["errors"].append(str(exc))
    finally:
        try:
            command(["docker", "rm", "-f", container], check=False)
            command(["docker", "network", "rm", network], check=False)
            manifest["cleanup_complete"] = (
                not command(["docker", "ps", "-aq", "--filter", "name=" + container])
                and not command(["docker", "network", "ls", "-q", "--filter", "name=" + network]))
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            manifest["errors"].append("Cleanup could not be verified: " + str(exc))
        if not manifest["cleanup_complete"]:
            manifest["status"] = "failed"
        write(output / "manifest.json", manifest)
        write(output / "seal.json", {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
                                     for p in output.rglob("*") if p.is_file()})
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path("artifacts/benchmark-target/juice-shop"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    result = run(args.repository, args.output)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "passed" and result["cleanup_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
