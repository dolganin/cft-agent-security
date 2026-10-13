"""Operator-owned disposable fixture lifecycle. Not registered as an agent tool."""
import json
import os
import subprocess
import time
from functools import wraps
from hashlib import sha256
from pathlib import Path
from threading import RLock
from types import SimpleNamespace
from uuid import uuid4

from evaluation.scanner_baseline import validate_target
from schemas.access_fixture import AccessFixtureContext
from schemas.target import TargetProfile

COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
TARGET_IMAGE = "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
WORKER_IMAGE = "python@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7"
ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("server.ts", "lib/insecurity.ts", "routes/currentUser.ts", "routes/address.ts",
           "routes/basket.ts", "models/user.ts", "models/basket.ts", "models/address.ts")


def digest(value):
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def serialized(method):
    @wraps(method)
    def call(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)
    return call


class AccessFixtureLab:
    """A broker holding opaque generation IDs only; tokens remain in Docker tmpfs.

    B05 can use this operator-managed lifetime; preparing fixtures is intentionally
    absent from model tools. Reset destroys the whole lab, never a model write.
    """
    def __init__(self, repository, output, profile_file=ROOT / "targets/juice-access-fixture.yaml"):
        self.repository = Path(repository).resolve()
        self.output = Path(output).resolve()
        if (self.output.exists() or self.output.is_relative_to(self.repository)
                or self.repository.is_relative_to(self.output)):
            raise ValueError("Fixture outputs need a fresh directory outside the source checkout")
        self.profile = TargetProfile.from_yaml(profile_file, repository_path_override=self.repository)
        if (self.profile.id != "juice-access-fixture" or self.profile.access_fixture is None
                or self.profile.environment != "sandbox"
                or self.profile.runtime.type != "operator_access_fixture"
                or self.profile.runtime.base_url is not None or self.profile.runtime.compose_file is not None
                or set(self.profile.services) != {"juice"}
                or self.profile.services["juice"].internal_port != 3000
                or self.profile.services["juice"].runtime_endpoints != ["/"]
                or any(self.profile.constraints.model_dump().values())):
            raise ValueError("The operator access fixture profile is required")
        self.fixture_id = "fixture-" + uuid4().hex
        self.generation = None
        self.context = None
        self.resources = None
        self.source_files = {}
        self.records = []
        self._lock = RLock()
        self.output.mkdir(parents=True)

    def _docker(self, args, *, check=True, timeout=30):
        # No provider credentials are required by this lifecycle.
        env = {k: v for k, v in os.environ.items() if k.upper() in {
            "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
            "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "APPDATA", "LOCALAPPDATA",
            "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
        }}
        result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                encoding="utf-8", timeout=timeout, check=False, env=env)
        if check and result.returncode:
            raise RuntimeError("Docker lifecycle operation failed")
        return result

    def _persist(self, event):
        self.records.append(event)
        path = self.output / "lifecycle.jsonl"
        with path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _snapshot(self):
        result = {}
        for name in SOURCES:
            path = self.repository / name
            resolved = path.resolve(strict=True)
            if (not resolved.is_relative_to(self.repository)
                    or resolved.relative_to(self.repository).as_posix() != name or path.is_symlink()):
                raise ValueError("Noncanonical source path")
            with path.open("rb") as stream:
                raw = stream.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError("Source size limit exceeded")
            result[name] = sha256(raw).hexdigest()
        return result

    def _inconclusive(self, reason):
        return AccessFixtureContext(fixture_id=self.fixture_id, generation=self.generation or "unprepared",
                                    status="inconclusive", http_exchanges=0, reason=reason,
                                    source_snapshot=digest(self.source_files),
                                    profile_sha256=digest(self.profile.access_fixture.model_dump(mode="json")))

    @serialized
    def prepare(self):
        if self.resources is not None:
            raise ValueError("Destroy the previous fixture before preparation")
        self.generation = uuid4().hex[:16]
        prefix = "b04-" + self.generation
        self.resources = {"network": prefix + "-net", "target": prefix + "-juice", "worker": prefix + "-worker"}
        directory = self.output / self.generation
        directory.mkdir()
        label = "cft.b04.generation=" + self.generation
        try:
            validate_target(self.repository, SimpleNamespace(target_commit=COMMIT))
            self.source_files = self._snapshot()
            for image in [TARGET_IMAGE, WORKER_IMAGE]:
                self._docker(["image", "inspect", image])
            config = {"profile": self.profile.access_fixture.model_dump(mode="json"),
                      "fixture_id": self.fixture_id, "generation": self.generation,
                      "source_snapshot": digest(self.source_files)}
            (directory / "profile.json").write_text(json.dumps(config), encoding="utf-8")
            self._persist({"phase": "prepare", "generation": self.generation,
                           "resources": self.resources, "source_files": self.source_files,
                           "source_snapshot": digest(self.source_files), "target_commit": COMMIT,
                           "profile_digest": digest(self.profile.access_fixture.model_dump(mode="json")),
                           "target_image": TARGET_IMAGE, "worker_image": WORKER_IMAGE})
            self._docker(["network", "create", "--internal", "--label", label, self.resources["network"]])
            self._docker(["run", "-d", "--pull=never", "--name", self.resources["target"],
                          "--label", label, "--network", self.resources["network"], "--network-alias=juice",
                          "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=768m",
                          "--log-driver=local", "--log-opt=max-size=10m", "--log-opt=max-file=2",
                          "--cpus=2", "--pids-limit=128", TARGET_IMAGE])
            deadline = time.monotonic() + 90
            readiness_attempts = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("Fixture target readiness timed out")
                readiness_attempts += 1
                result = self._docker(["exec", self.resources["target"], "/nodejs/bin/node", "-e",
                                       "require('http').get('http://127.0.0.1:3000/',r=>{r.resume();if(r.statusCode===200)console.log('ready')}).on('error',()=>process.exit(1))"], check=False, timeout=min(5, remaining))
                if result.stdout.strip() == "ready":
                    break
                time.sleep(1)
            self._persist({"phase": "readiness", "generation": self.generation,
                           "readiness_probe_attempts": readiness_attempts, "budget_seconds": 90})
            self._docker(["run", "-d", "--pull=never", "--name", self.resources["worker"],
                          "--label", label, "--network", self.resources["network"], "--user=65532:65532",
                          "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                          "--memory=128m", "--cpus=1", "--pids-limit=32",
                          "--log-driver=local", "--log-opt=max-size=10m", "--log-opt=max-file=2",
                          "--tmpfs", "/state:rw,noexec,nosuid,size=1m,uid=65532,gid=65532,mode=0700",
                          "--env", "CFT_B04_CONTAINER=1", "--env", "PYTHONDONTWRITEBYTECODE=1",
                          "--mount", f"type=bind,src={directory},dst=/input,readonly",
                          "--mount", f"type=bind,src={ROOT / 'executor/access_fixture_worker.py'},dst=/app/fixture.py,readonly",
                          "--entrypoint", "python", WORKER_IMAGE, "-c", "import time; time.sleep(1800)"])
            self.context = self._operation("prepare")
            if self.context.status != "ready":
                self.close()
            return self.context
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            self.context = self._inconclusive("fixture_preparation_failed")
            self._persist({"phase": "failure", "generation": self.generation, "reason": self.context.reason})
            self.close()
            return self.context

    def _operation(self, operation):
        if operation not in {"prepare", "control", "lost-session", "changed-identity"}:
            raise ValueError("Only fixed operator fixture operations are supported")
        if self.resources is None:
            return self._inconclusive("fixture_closed_or_stale")
        try:
            if self._snapshot() != self.source_files:
                raise ValueError("Source snapshot changed")
            result = self._docker(["exec", self.resources["worker"], "python", "/app/fixture.py", operation],
                                  check=False, timeout=self.profile.access_fixture.wall_time_seconds + 10)
            context = AccessFixtureContext.model_validate_json(result.stdout)
            if (context.fixture_id != self.fixture_id or context.generation != self.generation
                    or context.profile_id != self.profile.access_fixture.id
                    or context.profile_sha256 != digest(self.profile.access_fixture.model_dump(mode="json"))
                    or context.source_snapshot != digest(self.source_files)
                    or context.permissions != self.profile.access_fixture.permissions
                    or (context.status == "ready" and result.returncode != 0)
                    or self._snapshot() != self.source_files):
                raise ValueError("Fixture output binding mismatch")
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError):
            context = self._inconclusive("fixture_control_technical_failure")
            self.close()
        self._persist({"phase": operation, "generation": self.generation,
                       "source_snapshot": digest(self.source_files), "context": context.model_dump(mode="json")})
        return context

    @serialized
    def controls(self, context, *, diagnostic="control"):
        if diagnostic not in {"control", "lost-session", "changed-identity"}:
            raise ValueError("Unsupported fixture diagnostic")
        if (not isinstance(context, AccessFixtureContext) or self.resources is None or context.fixture_id != self.fixture_id
                or context.generation != self.generation or context.status != "ready"):
            return self._inconclusive("fixture_closed_or_stale")
        # Diagnostic injection is operator-only and never modifies saved sessions.
        result = self._operation(diagnostic)
        if diagnostic == "control":
            self.context = result
            if result.status != "ready":
                self.close()
        return result

    @serialized
    def reset(self):
        if not self.close():
            raise RuntimeError("Cannot reset a fixture with unverified cleanup")
        return self.prepare()

    @serialized
    def close(self):
        if self.resources is None:
            return True
        resources = self.resources
        complete = False
        try:
            for key in ["worker", "target"]:
                self._docker(["rm", "-f", "-v", resources[key]], check=False)
            self._docker(["network", "rm", resources["network"]], check=False)
            remaining = self._docker(["ps", "-aq", "--filter", "label=cft.b04.generation=" + self.generation]).stdout.strip()
            networks = self._docker(["network", "ls", "-q", "--filter", "label=cft.b04.generation=" + self.generation]).stdout.strip()
            complete = not remaining and not networks
        except (OSError, RuntimeError, subprocess.SubprocessError):
            complete = False
        try:
            unchanged = self._snapshot() == self.source_files if self.source_files else None
        except (OSError, ValueError):
            unchanged = False
        self._persist({"phase": "destroy", "generation": self.generation,
                       "cleanup_complete": complete, "original_unchanged": unchanged})
        if complete:
            self.resources = None
        return complete

    def __enter__(self):
        return self

    def __exit__(self, *args):
        if not self.close():
            raise RuntimeError("Fixture cleanup could not be verified")
