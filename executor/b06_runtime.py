"""Operator lifecycle for two pre-bound B06 Docker generations."""
from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from evaluation.scanner_baseline import validate_target
from executor.access_fixture import COMMIT, ROOT, TARGET_IMAGE, WORKER_IMAGE
from executor.approvals import proposal_digest
from executor.b06_verdicts import evaluate
from executor.sandbox import SandboxResult
from schemas.access_fixture import AccessFixtureContext
from schemas.b06_verification import (
    B06_TOOLS,
    B06PreparationProof,
    B06TrialResult,
    B06VerificationResult,
    FixtureExecutionBinding,
    profile_digest,
)
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.target import TargetProfile
from security.verification_binding import digest, source_snapshot, validate_action_binding


class B06Runtime:
    def __init__(self, profile, tool, output, *, safe_control=False, max_readiness_attempts=None,
                 wall_time_budget_seconds=None):
        if (tool not in B06_TOOLS or profile.id != "juice-b06-verification"
                or profile.b06_verification is None or profile.environment != "sandbox"
                or profile.runtime.type != "operator_b06_fixture"
                or profile.runtime.base_url is not None or profile.runtime.compose_file is not None
                or set(profile.services) != {"juice"} or any(profile.constraints.model_dump().values())
                or profile.services["juice"].internal_port != 3000
                or profile.services["juice"].root != "."
                or set(profile.services["juice"].runtime_endpoints) != {"/", "/redirect", "/rest/user/change-password"}
                or profile.metadata.get("verification.target_commit") != COMMIT):
            raise ValueError("B06 requires the fixed operator target and protocol")
        if max_readiness_attempts is not None and not 1 <= max_readiness_attempts <= 90:
            raise ValueError("B06 readiness attempt cap must be between 1 and 90")
        self.max_readiness_attempts = max_readiness_attempts
        if wall_time_budget_seconds is not None and not 10 <= wall_time_budget_seconds <= 600:
            raise ValueError("B06 wall budget must be between 10 and 600 seconds")
        self.deadline = time.monotonic() + wall_time_budget_seconds if wall_time_budget_seconds else None
        registered_profile = TargetProfile.from_yaml(
            ROOT / "targets/juice-b06-verification.yaml",
            repository_path_override=profile.repository_path,
        )
        if profile_digest(profile) != profile_digest(registered_profile):
            raise ValueError("B06 target profile differs from the operator registry")
        self.original_profile = profile
        self.original = validate_target(profile.repository_path, SimpleNamespace(target_commit=COMMIT))
        self.output = Path(output).resolve()
        if (self.output.exists() or self.output.is_relative_to(profile.repository_path)
                or profile.repository_path.is_relative_to(self.output)):
            raise ValueError("B06 needs a fresh output outside the target checkout")
        self.output.mkdir(parents=True)
        raw, _ = source_snapshot(profile)
        snapshot = self.output / "source"
        for name, data in raw.items():
            path = snapshot / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.mounts = {}
        if safe_control:
            self._safe_patch(snapshot, tool)
        self.profile = profile.model_copy(update={"repository_path": snapshot})
        _, self.source_files = source_snapshot(self.profile)
        self.id = "b06-" + uuid4().hex[:20]
        self.tool = tool
        self.binding = FixtureExecutionBinding(
            fixture_id=self.id, session_id=self.id, target=self.profile.id, tool=tool,
            generations=(uuid4().hex[:16], uuid4().hex[:16]),
            source_snapshot=digest(self.source_files), profile_sha256=profile_digest(self.profile))
        self.resources = {}
        self.setup = {}
        self.preparations = {}
        self.ready = False
        self.consumed = False
        self.action = None
        self.records = []

    def docker(self, args, *, input=None, timeout=30, check=True):
        env = {k: v for k, v in os.environ.items() if k.upper() in {
            "PATH", "HOME", "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG",
            "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
        }}
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("B06 wall-time budget exhausted")
            timeout = min(timeout, remaining)
        result = subprocess.run(["docker", *args], input=input, capture_output=True,
                                text=True, timeout=timeout, env=env, check=False)
        if check and result.returncode:
            raise RuntimeError("B06 Docker operation failed")
        return result

    def persist(self, event):
        self.records.append(event)
        with (self.output / "lifecycle.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, separators=(",", ":")) + "\n")

    def _safe_patch(self, snapshot, tool):
        if tool == "verify_redirect_destination":
            source, built = "lib/insecurity.ts", "lib/insecurity.js"
            old, new = "url.includes(allowedUrl)", "url === allowedUrl"
        else:
            source, built = "routes/changePassword.ts", "routes/changePassword.js"
            old = "if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password)"
            new = "if (!currentPassword || security.hash(currentPassword) !== loggedInUser.data.password)"
        raw = (snapshot / source).read_text()
        if raw.count(old) != 1:
            raise ValueError("Safe-control source anchor must be unique")
        (snapshot / source).write_text(raw.replace(old, new), encoding="utf-8")
        # Read immutable compiled text in Docker, never import target code on host.
        program = "process.stdout.write(require('fs').readFileSync('/juice-shop/build/" + built + "','utf8'))"
        compiled = self.docker(["run", "--rm", "--pull=never", "--network=none",
                                "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                                "--memory=128m", "--pids-limit=16", "--entrypoint", "/nodejs/bin/node",
                                TARGET_IMAGE, "-e", program]).stdout
        if tool == "verify_redirect_destination":
            compiled_old, compiled_new = old, new
        else:
            compiled_old = "if (currentPassword && security.hash(currentPassword) !== loggedInUser.data.password)"
            compiled_new = "if (!currentPassword || security.hash(currentPassword) !== loggedInUser.data.password)"
        if compiled.count(compiled_old) != 1:
            raise ValueError("Safe-control compiled anchor must be unique")
        patched = self.output / "safe-control" / built
        patched.parent.mkdir(parents=True)
        patched.write_text(compiled.replace(compiled_old, compiled_new), encoding="utf-8")
        self.mounts[str(patched)] = "/juice-shop/build/" + built

    def open(self):
        fixture = TargetProfile.from_yaml(ROOT / "targets/juice-access-fixture.yaml").access_fixture
        try:
            for image in (TARGET_IMAGE, WORKER_IMAGE):
                self.docker(["image", "inspect", image])
            for generation in self.binding.generations:
                prefix = "b06-" + generation
                r = {"network": prefix + "-net", "target": prefix + "-juice", "worker": prefix + "-worker"}
                self.resources[generation] = r
                directory = self.output / generation
                directory.mkdir()
                config = {"profile": fixture.model_dump(mode="json"), "fixture_id": self.id,
                          "generation": generation, "source_snapshot": self.binding.source_snapshot}
                (directory / "profile.json").write_text(json.dumps(config), encoding="utf-8")
                label = "cft.b06.generation=" + generation
                self.docker(["network", "create", "--internal", "--label", label, r["network"]])
                mounts = [v for src, dst in self.mounts.items() for v in ("--mount", f"type=bind,src={src},dst={dst},readonly")]
                self.docker(["run", "-d", "--pull=never", "--name", r["target"], "--label", label,
                             "--network", r["network"], "--network-alias=juice", "--cap-drop=ALL",
                             "--security-opt=no-new-privileges:true", "--memory=768m", "--cpus=2",
                             "--pids-limit=128", "--log-driver=none", *mounts, TARGET_IMAGE])
                deadline, attempts = time.monotonic() + 90, 0
                while True:
                    attempts += 1
                    if self.max_readiness_attempts is not None and attempts > self.max_readiness_attempts:
                        raise RuntimeError("B06 readiness attempt budget exhausted")
                    ready = self.docker(["exec", r["target"], "/nodejs/bin/node", "-e",
                        "require('http').get('http://127.0.0.1:3000/',r=>{r.resume();if(r.statusCode===200)console.log('ready')}).on('error',()=>process.exit(1))"],
                        check=False, timeout=5)
                    if ready.stdout.strip() == "ready":
                        break
                    if time.monotonic() > deadline:
                        raise RuntimeError("B06 readiness timed out")
                    time.sleep(1)
                self.docker(["run", "-d", "--pull=never", "--name", r["worker"], "--label", label,
                             "--network", r["network"], "--network-alias=b06-sink", "--user=65532:65532",
                             "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                             "--memory=128m", "--cpus=1", "--pids-limit=32", "--log-driver=none",
                             "--tmpfs", "/state:rw,noexec,nosuid,size=1m,uid=65532,gid=65532,mode=0700",
                             "--env", "CFT_B06_CONTAINER=1", "--env", "PYTHONDONTWRITEBYTECODE=1",
                             "--mount", f"type=bind,src={directory},dst=/input,readonly",
                             "--mount", f"type=bind,src={ROOT / 'executor/b06_worker.py'},dst=/app/b06.py,readonly",
                             "--mount", f"type=bind,src={ROOT / 'executor/access_fixture_worker.py'},dst=/app/b04.py,readonly",
                             "--entrypoint", "python", WORKER_IMAGE, "-c", "import time; time.sleep(1800)"])
                self.setup[generation] = 0
                if self.tool == "verify_auth_reauthentication":
                    result = self.docker(["exec", r["worker"], "python", "/app/b06.py", "prepare"], timeout=130)
                    context = AccessFixtureContext.model_validate_json(result.stdout)
                    if (context.status != "ready" or context.generation != generation
                            or context.fixture_id != self.id or context.source_snapshot != self.binding.source_snapshot):
                        raise ValueError("B04 preparation did not bind to B06 generation")
                    self.setup[generation] = context.http_exchanges
                    objects = {o.id: o for o in context.objects}
                    controls = tuple(c.id for c in context.controls if c.passed)
                    self.preparations[generation] = B06PreparationProof(
                        fixture_id=self.id, generation=generation, source_snapshot=context.source_snapshot,
                        context_sha256=digest(context.model_dump(mode="json")), roles=context.roles,
                        controls=controls, owner_id=objects["negative-control-b"].server_owner_id,
                        object_sha256=objects["negative-control-b"].baseline_sha256,
                        http_exchanges=context.http_exchanges)
                    (directory / "preparation.json").write_text(context.model_dump_json(indent=2))
                self.persist({"phase": "ready", "generation": generation, "readiness_http_exchanges": attempts,
                              "setup_http_exchanges": self.setup[generation], "resources": r,
                              "source_snapshot": self.binding.source_snapshot, "target_image": TARGET_IMAGE})
            self.ready = True
            return self
        except Exception:
            self.close()
            raise

    def runtime_map(self):
        if not self.ready or self.consumed:
            raise ValueError("B06 fixture is not ready")
        return RuntimeServiceMap(session_id=self.id,
            network_name=self.resources[self.binding.generations[0]]["network"],
            source_files_sha256=self.source_files, verification_fixtures={self.tool: self.binding},
            services={"juice": RuntimeService(name="juice", address="http://juice:3000", ready=True,
                readiness_source="http_probe", allowed_endpoints=self.profile.services["juice"].runtime_endpoints)})

    def authorize_action(self, action):
        binding = validate_action_binding(self.profile, action)
        if (not self.ready or self.consumed or action.fixture_binding != self.binding
                or binding.source_snapshot != self.binding.source_snapshot
                or profile_digest(self.profile) != self.binding.profile_sha256):
            raise ValueError("B06 fixture binding is stale or changed")
        self.action = action.model_copy(deep=True)

    def code_support(self):
        r = self.resources[self.binding.generations[0]]
        program = ("const fs=require('fs'),yaml=require('js-yaml'),config=require('config'),u=require('./build/lib/utils');"
                   "const c=yaml.load(fs.readFileSync('data/static/challenges.yml','utf8')).find(c=>c.key==='usernameXssChallenge');"
                   "console.log(JSON.stringify({docker:fs.existsSync('/.dockerenv'),safety_mode:config.get('challenges.safetyMode'),"
                   "...u.getChallengeEnablementStatus(c)}))")
        raw = self.docker(["exec", r["target"], "/nodejs/bin/node", "-e", program]).stdout
        observed = json.loads(raw)
        return {"status": "unsupported_runtime" if observed.get("enabled") is False else "runtime_gate_required",
                "image": TARGET_IMAGE, "observed": observed,
                "source_files_sha256": {name: self.original[name] for name in (
                    "routes/userProfile.ts", "lib/utils.ts", "data/static/challenges.yml", "config/default.yml")},
                "reason": "Evaluation branch availability observed in the pinned Docker image; no marker executed."}

    def _close_generation(self, generation):
        r = self.resources[generation]
        deadline = self.deadline
        self.deadline = None  # Best-effort teardown must still run after the protocol budget expires.
        try:
            for key in ("worker", "target"):
                self.docker(["rm", "-f", "-v", r[key]], check=False)
            self.docker(["network", "rm", r["network"]], check=False)
            label = "label=cft.b06.generation=" + generation
            remaining = self.docker(["ps", "-aq", "--filter", label]).stdout.strip()
            networks = self.docker(["network", "ls", "-q", "--filter", label]).stdout.strip()
            complete = not remaining and not networks
        except (OSError, RuntimeError, subprocess.SubprocessError):
            complete = False
        finally:
            self.deadline = deadline
        self.persist({"phase": "destroy", "generation": generation, "cleanup_complete": complete})
        return complete

    def close(self):
        self.ready = False
        results = [self._close_generation(g) for g in self.resources]
        return all(results)

    def run(self, request):
        started = time.monotonic()
        if (self.action is None or request.tool != self.tool or request.parameters != self.action.parameters
                or request.endpoint != self.action.endpoint or request.base_url != "http://juice:3000"
                or request.network_access != "target"):
            raise ValueError("B06 runtime requires its approved action")
        self.authorize_action(self.action)
        self.consumed = True
        trials = []
        aborted = False
        try:
            for generation in self.binding.generations:
                r = self.resources[generation]
                try:
                    if aborted:
                        raise ValueError("Earlier B06 trial failed; subsequent probe stopped")
                    operation = "auth" if self.tool == "verify_auth_reauthentication" else "redirect"
                    raw = self.docker(["exec", r["worker"], "python", "/app/b06.py", operation],
                                      timeout=25, check=False)
                    trial = B06TrialResult.model_validate_json(raw.stdout)
                    if trial.generation != generation:
                        raise ValueError("B06 trial generation mismatch")
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
                    trial = B06TrialResult(generation=generation, exchanges=[], http_exchanges=0,
                        setup_http_exchanges=self.setup[generation], sink_requests=0,
                        redirect_followed=False, destination_dns=False,
                        cleanup_complete=False, error="technical_failure")
                cleanup = self._close_generation(generation)
                trial = trial.model_copy(update={"cleanup_complete": cleanup,
                                                "setup_http_exchanges": self.setup[generation],
                                                "preparation": self.preparations.get(generation)})
                trials.append(trial)
                aborted = not cleanup or trial.error != "none"
                (self.output / generation / "trial.json").write_text(trial.model_dump_json(indent=2))
        finally:
            self.ready = False
        try:
            unchanged = (validate_target(self.original_profile.repository_path, SimpleNamespace(target_commit=COMMIT))
                         == self.original and source_snapshot(self.profile)[1] == self.source_files)
        except (OSError, ValueError, RuntimeError):
            unchanged = False
        result = B06VerificationResult(binding=self.binding, action_digest=proposal_digest(self.action),
            trials=trials, original_unchanged=unchanged, verdict="inconclusive", explanation="Pending interpretation",
            scope="runtime_password_reauthentication" if self.tool == "verify_auth_reauthentication" else "runtime_redirect_destination")
        verdict, explanation = evaluate(result)
        result = result.model_copy(update={"verdict": verdict, "explanation": explanation})
        stdout = json.dumps(result.model_dump(mode="json", exclude_none=True), separators=(",", ":"))
        return SandboxResult(request.run_id, 0, stdout, "", False, self.id,
                             int((time.monotonic() - started) * 1000), "docker")
