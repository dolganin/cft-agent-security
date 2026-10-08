"""Disposable Docker target for operator-owned fix stages.

Source is mounted read-only, copied into container tmpfs, and never executed on
the host. Commands come from this adapter, not package.json or model output.
"""
from __future__ import annotations

import subprocess
from dataclasses import replace
from pathlib import Path
from time import monotonic
from uuid import uuid4

from executor.sandbox import SandboxRequest, SandboxResult, _communicate_bounded
from pipeline.cancellation import suspend_cancellation
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.target import TargetProfile
from security.error_redaction import redact_error_message

STAGES = {"prepare", "build", "tests", "start", "smoke"}
_PREPARE = (
    "import shutil,pathlib,hashlib; "
    "assert pathlib.Path('/input/package.json').read_bytes().replace(b'\\r\\n',b'\\n') == "
    "pathlib.Path('/opt/cft/package.json').read_bytes().replace(b'\\r\\n',b'\\n'), 'dependency manifest mismatch'; "
    "shutil.copytree('/input','/workspace/target'); "
    "pathlib.Path('/workspace/target/node_modules').symlink_to('/opt/cft/node_modules'); "
    "shutil.copytree('/opt/cft/frontend-dist','/workspace/target/frontend/dist',dirs_exist_ok=True)"
)
_SMOKE = """
const http=require('http'), assert=require('assert');
const get=q=>new Promise((resolve,reject)=>{
  const r=http.get('http://127.0.0.1:3000/rest/products/search?q='+encodeURIComponent(q),s=>{
    let b='';s.on('data',v=>{b+=v;if(b.length>262144)r.destroy()});
    s.on('end',()=>{try{assert.equal(s.statusCode,200);const p=JSON.parse(b);
      assert(Array.isArray(p.data));resolve(p.data.length)}catch(e){reject(e)}});
  });r.on('error',reject);r.setTimeout(1000,()=>r.destroy(new Error('timeout')));
});
(async()=>{let ready=false;for(let i=0;i<30;i++){
  try{assert((await get('Apple'))>0);ready=true;break}catch(e){await new Promise(r=>setTimeout(r,1000))}}
  assert(ready,'search startup/normal product search failed');
  assert.equal(await get('cft-functional-no-such-product'),0);
  console.log('normal search and no-match regression checks passed');
})().catch(e=>{console.error(e.message);process.exit(1)});
"""
_START = (
    "import subprocess,os; log=open('/workspace/startup.log','wb'); "
    "process=subprocess.Popen(['node','build/app.js'],stdout=log,stderr=subprocess.STDOUT,"
    "env=dict(os.environ,NODE_ENV='production'),start_new_session=True); "
    "print('target process started',process.pid)"
)


class DockerFixRuntime:
    def __init__(self, profile: TargetProfile):
        config = profile.fix_verification
        if config is None or config.service not in profile.services or profile.repository_path is None:
            raise ValueError("Trusted fix adapter configuration is required")
        if profile.environment not in {"local", "sandbox", "staging"}:
            raise ValueError("Fix runtime environment is not allowed")
        service = profile.services[config.service]
        if service.internal_port != 3000 or service.root != ".":
            raise ValueError("Juice adapter requires the registered root service on port 3000")
        self.profile = profile
        self.config = config
        self.id = "cft-fix-" + uuid4().hex[:20]
        self.network = self.id + "-net"
        self.connected = False
        self.closed = False
        self.deadline = monotonic() + config.wall_clock_budget_seconds

    def _control(self, argv: list[str], timeout: float = 30) -> SandboxResult:
        started = monotonic()
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, shell=False)
        out, cut_out, err, cut_err, timed_out = _communicate_bounded(process, b"", timeout, 16384)
        return SandboxResult(
            self.id, 124 if timed_out else process.returncode or 0,
            redact_error_message(out.decode(errors="replace") + ("\n[truncated]" if cut_out else ""), max_length=16384),
            redact_error_message(err.decode(errors="replace") + ("\n[truncated]" if cut_err else ""), max_length=16384),
            timed_out, self.id, int((monotonic() - started) * 1000), "docker",
        )

    def open(self):
        # --pull never prevents silent image replacement or network provisioning.
        result = self._control([
            "docker", "run", "--detach", "--pull", "never", "--name", self.id,
            "--network", "none", "--user", "1000:1000", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "256", "--memory", "2g", "--cpus", "2",
            "--tmpfs", "/workspace:rw,nosuid,size=2g,uid=1000,gid=1000",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m,uid=1000,gid=1000",
            "--mount", f"type=bind,source={self.profile.repository_path},target=/input,readonly",
            "--mount", f"type=bind,source={Path(__file__).with_name('fix_test_reporter.mjs')},target=/fix/reporter.mjs,readonly",
            "--env", "HOME=/tmp", "--env", "NODE_ENV=test",
            "--entrypoint", "python3", self.config.image,
            "-c", "import time; time.sleep(3600)",
        ])
        if result.exit_code:
            self.close()
            raise RuntimeError("Fix Docker image could not start: " + result.stderr)
        return self

    def run(self, request: SandboxRequest) -> SandboxResult:
        if request.tool != "fix_target_stage" or request.parameters.get("adapter") != self.config.adapter:
            raise ValueError("Fix runtime accepts only its registered stage capability")
        stage = request.parameters.get("stage")
        if set(request.parameters) != {"adapter", "stage"} or stage not in STAGES:
            raise ValueError("Invalid fix stage parameters")
        if self.closed or (self.connected and stage in {"prepare", "build", "tests"}):
            raise ValueError("Build and tests require a networkless fix container")
        commands = {
            "prepare": ["python3", "-c", _PREPARE],
            "build": ["node", "node_modules/typescript/bin/tsc"],
            "tests": ["node", "--import", "./test/server/helpers/test-env.mjs", "--import", "tsx",
                      "--test", "--test-concurrency=2", "--test-force-exit", "--test-reporter=/fix/reporter.mjs", "test/server/**/*.unit.test.ts"],
            "start": ["python3", "-c", _START],
            "smoke": ["node", "-e", _SMOKE],
        }
        if stage == "start":
            for command in (["docker", "network", "create", "--internal", self.network],
                            ["docker", "network", "disconnect", "none", self.id],
                            ["docker", "network", "connect", "--alias", self.config.service, self.network, self.id]):
                result = self._control(command)
                if result.exit_code:
                    return result
            self.connected = True
        argv = ["docker", "exec"]
        if stage != "prepare":
            argv.extend(["--workdir", "/workspace/target"])
        remaining = self.deadline - monotonic()
        if remaining <= 0:
            raise TimeoutError("Fix verification wall-clock budget exhausted")
        result = self._control([*argv, self.id, *commands[stage]], min(self.config.timeout_seconds, remaining))
        if stage == "smoke" and result.exit_code and not result.timed_out:
            diagnostic = self._control(["docker", "exec", self.id, "python3", "-c",
                "from pathlib import Path; p=Path('/workspace/startup.log'); print(p.read_bytes()[-4096:].decode(errors='replace') if p.exists() else 'startup log unavailable')"])
            result = replace(result, stderr=redact_error_message(result.stderr + "\n" + diagnostic.stdout, max_length=8192))
        if result.timed_out:
            self.close()  # kill target children, not just the docker exec client
        return result

    def runtime_services(self) -> RuntimeServiceMap:
        service = self.profile.services[self.config.service]
        return RuntimeServiceMap(session_id=self.id, network_name=self.network, services={
            service.id: RuntimeService(name=service.id, type=service.type,
                address=f"http://{service.id}:3000", ready=True, readiness_source="http_probe",
                allowed_endpoints=service.runtime_endpoints, request_host=service.request_host),
        })

    def close(self) -> bool:
        try:
            with suspend_cancellation():
                removed = self._control(["docker", "rm", "--force", self.id])
                network = self._control(["docker", "network", "rm", self.network])
        except (OSError, TimeoutError):
            return False
        # Missing resources are already clean; other failures cannot prove cleanup.
        self.closed = (removed.exit_code == 0 or "No such container" in removed.stderr) and (
            network.exit_code == 0 or "not found" in network.stderr)
        return self.closed
