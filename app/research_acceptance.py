"""R02/R03 real Docker acceptance with canonical Validator/Executor/Evidence."""
from __future__ import annotations

import argparse
import json
import secrets
import subprocess
import tempfile
import time
from hashlib import sha256
from pathlib import Path
from threading import Timer
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
from pipeline.cancellation import CancellationToken, RunCancelled, cancellation_scope
from schemas.action import ActionProposal
from schemas.research import HttpServiceScope
from schemas.target import TargetProfile
from validator.validator import PolicyValidator

ROOT = Path(__file__).resolve().parents[1]
PYTHON_IMAGE = "python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"


def docker(args):
    result = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError("Acceptance Docker operation failed")
    return result.stdout.strip()


def run(output: Path, image: str):
    if output.exists():
        raise FileExistsError("Choose a fresh acceptance directory")
    output.mkdir(parents=True)
    token = secrets.token_hex(24)
    prefix = "r03-accept-" + uuid4().hex[:12]
    network, container = prefix + "-net", prefix + "-target"
    checks, events = {}, []
    docker(["network", "create", "--internal", "--label", "cft.research.acceptance=" + prefix, network])
    try:
        container_id = docker(["run", "--detach", "--pull=never", "--name", container,
                               "--network", network, "--network-alias", "fixture",
                               "--user=65534:65534", "--read-only", "--cap-drop=ALL",
                               "--security-opt=no-new-privileges:true", "--memory=64m",
                               "--pids-limit=8", "--env", "FIXTURE_TOKEN=" + token,
                               "--mount", f"type=bind,src={ROOT / 'executor/research_acceptance_target.py'},dst=/app/target.py,readonly",
                               image, "python3", "/app/target.py"])
        target_image = json.loads(docker(["inspect", container_id]))[0]["Image"]
        with tempfile.TemporaryDirectory(prefix="cft-r02-fixture-") as directory:
            source = Path(directory)
            (source / "app.ts").write_text("export const marker = 'acceptance-marker';\n")
            (source / "secret.ts").write_text("const api_key = 'sk-012345678901234567890';\n")
            (source / ".env").write_text("TOKEN=never-visible\n")
            profile = TargetProfile(id="research-acceptance", name="R02/R03 transport fixture",
                                    environment="sandbox", repository_path=source)
            service = HttpServiceScope(container_id=container_id, image_id=target_image,
                                       address="http://fixture:8080", read_prefixes=["/"],
                                       write_paths={"POST": ["/echo"]}, role_handles=["owner"])
            with ResearchRuntime(target=profile, source_files=["app.ts", "secret.ts", ".env"],
                                 worker_image=image, output=output / "runtime", services={"fixture": service},
                                 network_name=network, role_headers={"owner": {"Authorization": "Bearer " + token}},
                                 timeout=2, max_http_requests=8) as runtime:
                validator = PolicyValidator.from_yaml(ROOT / "policies/research.yaml", target_profile=profile)
                validator.bind_research_scope(runtime.scope)
                store = JsonExecutionEvidenceStore(output / "evidence")
                policy = SandboxPolicy(sandbox_image=PYTHON_IMAGE)
                executor = SafeExecutor(approvals=InMemoryApprovalStore(), targets=TargetRegistry([profile]),
                                        evidence_store=store, audit_log=JsonlAuditLog(output / "audit.jsonl"),
                                        sandbox=DockerSandbox(policy), run_limiter=RunLimiter(), policy=policy)
                executor.bind_research_runtime(runtime)

                def propose(tool, parameters, **kwargs):
                    return ActionProposal(id="accept-" + uuid4().hex, tool=tool, target=profile.id,
                                          environment="sandbox", parameters=parameters,
                                          purpose="Controlled transport acceptance",
                                          expected_evidence="A recorded observation", research_binding=runtime.binding,
                                          **kwargs)

                def perform(action):
                    validation = validator.validate(action)
                    assert validation.approved, validation.reason
                    executor.record_approval(action, validation)
                    execution = executor.execute(action)
                    record = store.get_execution(execution.evidence_ref)
                    evidence = build_evidence(action=action, execution=execution, record=record,
                                              evidence_loaded=True, artifact_refs=execution.artifacts,
                                              hypothesis_id="acceptance")
                    assert evidence.verdict == "inconclusive"
                    events.append({"action": action.model_dump(mode="json"),
                                   "validation": validation.model_dump(mode="json"),
                                   "execution": execution.model_dump(mode="json"),
                                   "evidence": evidence.model_dump(mode="json")})
                    return execution, json.loads(execution.stdout).get("observation", {}) if execution.stdout else {}

                def script(code, language="python3"):
                    path = "probe.py" if language == "python3" else "probe.js"
                    _, written = perform(propose("write_workspace_file", {"path": path, "content": code}))
                    return perform(propose("sandbox_command", {"argv": [language, "/workspace/" + path],
                                                                "cwd": "/workspace", "script_sha256": written["sha256"]}))

                _, listed = perform(propose("list_source_files", {}))
                checks["secret_files_excluded"] = listed["files"] == ["app.ts", "secret.ts"]
                _, read = perform(propose("read_source", {"path": "secret.ts"}))
                checks["source_secrets_redacted"] = "sk-012345678901234567890" not in read["content"]
                _, matched = perform(propose("search_source", {"literal": "acceptance-marker"}))
                checks["literal_search"] = len(matched["matches"]) == 1
                result, observed = script("from pathlib import Path\nprint(Path('/target/app.ts').read_text())\nprint('confirmed')\n")
                checks["python_script"] = result.exit_code == 0 and "acceptance-marker" in observed["stdout"]
                checks["stdout_has_no_verdict_authority"] = "confirmed" in observed["stdout"]
                result, observed = script("console.log('node-acceptance');", "node")
                checks["node_script"] = result.exit_code == 0 and "node-acceptance" in observed["stdout"]
                result, _ = script("from pathlib import Path\nPath('/workspace/persistent.txt').write_text('kept')\n")
                _, persisted = perform(propose("read_workspace_file", {"path": "persistent.txt"}))
                checks["workspace_persists_between_actions"] = result.exit_code == 0 and persisted["content"] == "kept"
                result, observed = script("from pathlib import Path\ntry:\n Path('/target/app.ts').write_text('bad')\nexcept OSError:\n print('read-only')\n")
                checks["source_read_only"] = "read-only" in observed["stdout"]
                result, observed = script("import socket\ntry:\n socket.create_connection(('1.1.1.1',80),.2)\nexcept OSError:\n print('egress-blocked')\n")
                checks["shell_egress_blocked"] = "egress-blocked" in observed["stdout"]
                result, observed = script("print('x'*100000)")
                checks["output_bounded"] = observed["truncated"]["stdout"] and len(observed["stdout"]) == 16384
                result, observed = script("import time\ntime.sleep(4)")
                checks["timeout_and_process_cleanup"] = result.timed_out and result.exit_code == 124
                result, observed = script("import subprocess,sys\nsubprocess.Popen([sys.executable,'-c',\"import time;from pathlib import Path;time.sleep(1);Path('/workspace/escaped-child').write_text('bad')\"],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\nprint('spawned')")
                _, observed = script("import time\nfrom pathlib import Path\ntime.sleep(1.3)\nprint('child-clean' if not Path('/workspace/escaped-child').exists() else 'child-leaked')")
                checks["detached_child_cleanup"] = "child-clean" in observed["stdout"]
                script("from pathlib import Path\nPath('/workspace/link').symlink_to('/etc/passwd')")
                result, _ = perform(propose("read_workspace_file", {"path": "link"}))
                checks["workspace_symlink_denied"] = result.status == "failed"
                _, written = perform(propose("write_workspace_file", {"path": "changed.py", "content": "print('old')"}))
                action = propose("sandbox_command", {"argv": ["python3", "/workspace/changed.py"],
                                                       "script_sha256": written["sha256"]})
                executor.record_approval(action, validator.validate(action))
                perform(propose("write_workspace_file", {"path": "changed.py", "content": "print('new')"}))
                changed = executor.execute(action)
                checks["changed_script_blocked"] = changed.status == "failed" and changed.exit_code != 0
                for bad in ["../app.ts", "/etc/passwd", "a/../../app.ts"]:
                    checks["path_denied_" + bad] = not validator.validate(propose("read_source", {"path": bad})).approved
                checks["unknown_role_denied"] = not validator.validate(propose("target_http", {"path": "/private", "role_handle": "foreign"}, service="fixture", endpoint="/private")).approved
                checks["ungranted_write_denied"] = not validator.validate(propose("target_http", {"path": "/private", "method": "DELETE"}, service="fixture", endpoint="/private")).approved
                for _ in range(20):
                    try:
                        result, health = perform(propose("target_http", {"path": "/health"}, service="fixture", endpoint="/health"))
                        if result.exit_code == 0:
                            break
                    except (AssertionError, ValueError):
                        pass
                    time.sleep(.1)
                checks["http_health"] = result.exit_code == 0 and health["status_code"] == 200
                _, anonymous = perform(propose("target_http", {"path": "/private"}, service="fixture", endpoint="/private"))
                _, owner = perform(propose("target_http", {"path": "/private", "role_handle": "owner"}, service="fixture", endpoint="/private"))
                checks["opaque_role_session"] = anonymous["status_code"] == 401 and owner["status_code"] == 200
                checks["role_tokens_redacted"] = token not in json.dumps(owner)
                _, redirect = perform(propose("target_http", {"path": "/redirect"}, service="fixture", endpoint="/redirect"))
                checks["redirect_not_followed"] = redirect["status_code"] == 302 and not redirect["redirect_followed"]
                _, echoed = perform(propose("target_http", {"path": "/echo", "method": "POST", "body": "owned-marker"}, service="fixture", endpoint="/echo"))
                checks["operator_write_grant"] = echoed["body"] == "owned-marker"
                while runtime.requests < runtime.scope.max_http_requests:
                    perform(propose("target_http", {"path": "/health"}, service="fixture", endpoint="/health"))
                exhausted, _ = perform(propose("target_http", {"path": "/health"}, service="fixture", endpoint="/health"))
                checks["http_budget_enforced"] = exhausted.status == "failed"
                checks["source_integrity"] = (source / "app.ts").read_text() == "export const marker = 'acceptance-marker';\n"
                (source / "app.ts").write_text("changed")
                stale = executor.execute(propose("read_source", {"path": "app.ts"}))
                checks["source_mutation_denied"] = stale.status == "denied"
            checks["workspace_cleanup"] = runtime.closed
            with ResearchRuntime(target=profile, source_files=["app.ts"], worker_image=image,
                                 output=output / "cancel-runtime", timeout=10) as cancellation_runtime:
                validator.bind_research_scope(cancellation_runtime.scope)
                executor.bind_research_runtime(cancellation_runtime)
                write = ActionProposal(id="cancel-write", tool="write_workspace_file", target=profile.id,
                                       environment="sandbox", purpose="Cancellation acceptance", expected_evidence="Observation",
                                       research_binding=cancellation_runtime.binding,
                                       parameters={"path": "slow.py", "content": "import time\ntime.sleep(9)"})
                executor.record_approval(write, validator.validate(write))
                stored = json.loads(executor.execute(write).stdout)["observation"]
                slow = write.model_copy(update={"id": "cancel-run", "tool": "sandbox_command", "parameters": {
                    "argv": ["python3", "/workspace/slow.py"], "script_sha256": stored["sha256"]}})
                executor.record_approval(slow, validator.validate(slow))
                token_cancel = CancellationToken()
                timer = Timer(.7, token_cancel.cancel)
                timer.start()
                try:
                    with cancellation_scope(token_cancel):
                        executor.execute(slow)
                except RunCancelled:
                    checks["cooperative_cancellation"] = cancellation_runtime.closed
                finally:
                    timer.cancel()
                    timer.join()
        (output / "actions.json").write_text(json.dumps(events, indent=2))
        assert token not in (output / "actions.json").read_text()
    finally:
        docker(["rm", "--force", container])
        docker(["network", "rm", network])
        checks["target_cleanup"] = True
    result = {"schema": "research-acceptance.v1", "checks": checks,
              "passed": all(checks.values()), "worker_image": image,
              "scope": "synthetic tool transport; not new Juice Shop quality metrics",
              "llm_calls": 0, "benchmark_runs": 0}
    (output / "result.json").write_text(json.dumps(result, indent=2))
    seal = {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in output.rglob("*") if p.is_file()}
    (output / "seal.json").write_text(json.dumps(seal, indent=2))
    if not result["passed"]:
        raise AssertionError("Acceptance checks failed: " + str([k for k, v in checks.items() if not v]))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--worker-image", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output.resolve(), args.worker_image), indent=2))


if __name__ == "__main__":
    main()
