"""Operator-owned disposable fixture lifecycle. Not registered as an agent tool."""
import json
import os
import re
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
from schemas.access_verification import AccessWorkerStep
from schemas.target import TargetProfile

COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
TARGET_IMAGE = "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
WORKER_IMAGE = "python@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7"
ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("server.ts", "lib/insecurity.ts", "routes/currentUser.ts", "routes/address.ts",
           "routes/basket.ts", "routes/basketItems.ts", "models/user.ts", "models/basket.ts",
           "models/address.ts", "models/basketitem.ts", "models/relations.ts", "models/index.ts", "lib/utils.ts")


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
    def __init__(self, repository, output, profile_file=ROOT / "targets/juice-access-fixture.yaml",
                 active_check_id="juice-basket-own-read-v1", max_readiness_attempts=None,
                 wall_time_budget_seconds=None):
        self.repository = Path(repository).resolve()
        self.output = Path(output).resolve()
        if (self.output.exists() or self.output.is_relative_to(self.repository)
                or self.repository.is_relative_to(self.output)):
            raise ValueError("Fixture outputs need a fresh directory outside the source checkout")
        self.profile = TargetProfile.from_yaml(profile_file, repository_path_override=self.repository)
        if active_check_id not in {
            "juice-basket-own-read-v1", "juice-address-own-write-v1",
            "juice-basket-own-write-v2", "juice-basket-own-write-v3",
            "juice-address-ownership-transfer-v1", "juice-basket-insert-owner-check-v1",
        }:
            raise ValueError("B05 active check is not registered")
        self.active_check_id = active_check_id
        if max_readiness_attempts is not None and not 1 <= max_readiness_attempts <= 90:
            raise ValueError("Readiness attempt cap must be between 1 and 90")
        self.max_readiness_attempts = max_readiness_attempts
        if wall_time_budget_seconds is not None and not 10 <= wall_time_budget_seconds <= 600:
            raise ValueError("Fixture wall budget must be between 10 and 600 seconds")
        self.deadline = time.monotonic() + wall_time_budget_seconds if wall_time_budget_seconds else None
        expected_endpoints = ["/"]
        if self.profile.access_fixture:
            if (self.profile.access_fixture.b05_write_candidate
                    or self.profile.access_fixture.b05_ownership_transfer_candidate):
                expected_endpoints.append("/api/Addresss/:id")
            if (self.profile.access_fixture.b05_basket_write_candidate
                    or self.profile.access_fixture.b05_basket_write_v3_candidate):
                expected_endpoints.extend(["/rest/basket/:id", "/api/BasketItems/:id"])
            if self.profile.access_fixture.b05_basket_insert_candidate:
                expected_endpoints.extend(["/api/BasketItems", "/rest/basket/:id"])
        if (self.profile.id != "juice-access-fixture" or self.profile.access_fixture is None
                or self.profile.environment != "sandbox"
                or self.profile.runtime.type != "operator_access_fixture"
                or self.profile.runtime.base_url is not None or self.profile.runtime.compose_file is not None
                or set(self.profile.services) != {"juice"}
                or self.profile.services["juice"].internal_port != 3000
                or set(self.profile.services["juice"].runtime_endpoints) != set(expected_endpoints)
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
        if self.deadline is not None:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise RuntimeError("Fixture wall-time budget exhausted")
            timeout = min(timeout, remaining)
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
            worker_image = self.profile.access_fixture.worker_image
            for image in [TARGET_IMAGE, worker_image]:
                self._docker(["image", "inspect", image])
            config = {"profile": self.profile.access_fixture.model_dump(mode="json"),
                      "active_check_id": self.active_check_id,
                      "fixture_id": self.fixture_id, "generation": self.generation,
                      "source_snapshot": digest(self.source_files)}
            (directory / "profile.json").write_text(json.dumps(config), encoding="utf-8")
            self._persist({"phase": "prepare", "generation": self.generation,
                           "resources": self.resources, "source_files": self.source_files,
                           "source_snapshot": digest(self.source_files), "target_commit": COMMIT,
                           "profile_digest": digest(self.profile.access_fixture.model_dump(mode="json")),
                           "target_image": TARGET_IMAGE, "worker_image": worker_image})
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
                if self.max_readiness_attempts is not None and readiness_attempts > self.max_readiness_attempts:
                    raise RuntimeError("Fixture readiness attempt budget exhausted")
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
                          "--entrypoint", "python", worker_image, "-c", "import time; time.sleep(1800)"])
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
        if operation not in {"prepare", "control", "lost-session", "changed-identity", "b05-provision"}:
            raise ValueError("Only fixed operator fixture operations are supported")
        if self.resources is None:
            return self._inconclusive("fixture_closed_or_stale")
        failure_type = None
        validation_errors = None
        result = None
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
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            failure_type = type(exc).__name__
            if hasattr(exc, "errors"):
                validation_errors = [
                    {"loc": list(item.get("loc", ())), "type": item.get("type")}
                    for item in exc.errors(include_input=False)[:12]
                ]
            context = self._inconclusive("fixture_control_technical_failure")
            self.close()
        self._persist({"phase": operation, "generation": self.generation,
                       "source_snapshot": digest(self.source_files), "context": context.model_dump(mode="json"),
                       "failure_type": failure_type,
                       "validation_errors": validation_errors,
                       "worker_returncode": result.returncode if result is not None else None,
                       "worker_stdout_bytes": len(result.stdout) if result is not None else None,
                       "worker_stderr_bytes": len(getattr(result, "stderr", "")) if result is not None else None})
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
    def provision_b05(self):
        """Create candidate data only after the existing B04 controls passed."""
        if self.active_check_id not in {
            "juice-address-own-write-v1", "juice-basket-own-write-v2", "juice-basket-own-write-v3",
            "juice-basket-insert-owner-check-v1",
        } or self.resources is None or self.context is None or self.context.status != "ready":
            raise ValueError("B05 candidate provisioning requires the ready registered fixture")
        result = self._operation("b05-provision")
        if result.status != "ready":
            raise RuntimeError("B05 candidate provisioning failed")
        self.context = result
        return result

    @serialized
    def b05_step(self, operation):
        """Invoke only a fixed B05 schedule fragment in the existing B04 worker."""
        allowed = {"b05-own-read-first", "b05-own-read-second", "b05-own-write-first",
                   "b05-own-write-second", "b05-own-write-cleanup", "b05-basket-write-first",
                   "b05-basket-write-second", "b05-basket-write-cleanup",
                   "b05-basket-write-v3-first", "b05-basket-write-v3-second", "b05-basket-write-v3-cleanup",
                   "b05-basket-insert-first", "b05-basket-insert-second",
                   "b05-ownership-transfer-first", "b05-ownership-transfer-second"}
        requires_address = operation.startswith(("b05-own-write", "b05-ownership-transfer"))
        requires_basket = operation.startswith("b05-basket-write")
        requires_basket = requires_basket or operation.startswith("b05-basket-insert")
        if (operation not in allowed or self.resources is None or self.context is None
                or self.context.status != "ready"
                or (requires_address and not (self.profile.access_fixture.b05_write_candidate
                                               or self.profile.access_fixture.b05_ownership_transfer_candidate))
                or (requires_basket and not (self.profile.access_fixture.b05_basket_write_candidate
                                              or self.profile.access_fixture.b05_basket_write_v3_candidate
                                              or self.profile.access_fixture.b05_basket_insert_candidate))):
            raise ValueError("B05 requires a ready operator-owned B04 fixture")
        allowed_for_check = {
            "juice-basket-own-read-v1": operation.startswith("b05-own-read"),
            "juice-address-own-write-v1": operation.startswith("b05-own-write"),
            "juice-basket-own-write-v2": operation.startswith("b05-basket-write"),
            "juice-basket-own-write-v3": operation.startswith("b05-basket-write-v3"),
            "juice-basket-insert-owner-check-v1": operation.startswith("b05-basket-insert"),
            "juice-address-ownership-transfer-v1": operation.startswith("b05-ownership-transfer"),
        }
        if not allowed_for_check[self.active_check_id]:
            raise ValueError("B05 step differs from the operator-bound check ID")
        if self._snapshot() != self.source_files:
            raise ValueError("B05 source snapshot changed before execution")
        result = self._docker(["exec", self.resources["worker"], "python", "/app/fixture.py", operation],
                              check=False, timeout=30)
        try:
            step = AccessWorkerStep.model_validate_json(result.stdout)
        except ValueError as exc:
            worker_result = None
            try:
                worker_result = json.loads(result.stdout)
            except (TypeError, ValueError):
                pass
            reason = worker_result.get("reason") if isinstance(worker_result, dict) else None
            reason_code = reason.split(":", 1)[0] if isinstance(reason, str) else None
            if not isinstance(reason_code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{1,63}", reason_code):
                reason_code = None
            validation_errors = [
                {"loc": list(item.get("loc", ())), "type": item.get("type")}
                for item in exc.errors(include_input=False)[:16]
            ] if hasattr(exc, "errors") else []
            self._persist({"phase": operation, "generation": self.generation,
                           "source_snapshot": digest(self.source_files),
                           "worker_returncode": result.returncode,
                           "worker_stdout_bytes": len(result.stdout),
                           "worker_stderr_bytes": len(result.stderr),
                           "worker_status": worker_result.get("status") if isinstance(worker_result, dict) else None,
                           "worker_reason_code": reason_code,
                           "validation_errors": validation_errors})
            raise ValueError("B05 worker output schema validation failed") from None
        if (step.operation != operation or step.status != "completed"
                or step.generation_sha256 != digest(self.generation)
                or step.source_snapshot_digest != digest(self.source_files)
                or step.profile_sha256 != digest(self.profile.access_fixture.model_dump(mode="json"))
                or step.http_exchanges != len(step.exchanges)
                or result.returncode != 0 or self._snapshot() != self.source_files):
            raise ValueError("B05 worker output failed generation, profile or source binding")
        self._persist({"phase": operation, "generation": self.generation,
                       "source_snapshot": digest(self.source_files),
                       "step": step.model_dump(mode="json")})
        return step

    @serialized
    def observe_address_owner(self, *, phase, object_ref="address-b"):
        """Read only Address id/UserId from the disposable target's SQLite DB."""
        if (object_ref != "address-b" or self.resources is None or self.context is None
                or self.context.status != "ready" or not self.profile.access_fixture.b05_ownership_transfer_candidate):
            raise ValueError("B05 ownership observation is not registered for this fixture")
        if self._snapshot() != self.source_files:
            raise ValueError("B05 source snapshot changed before ownership observation")
        objects = {item.id: item for item in self.context.objects}
        obj = objects.get(object_ref)
        if obj is None or obj.kind != "address":
            raise ValueError("Registered Address proof is missing")
        object_id = obj.server_object_id
        if type(object_id) is not int or not 0 < object_id < 1_000_000_000:
            raise ValueError("Registered Address identifier is invalid")
        script = (
            "const sqlite3=require('sqlite3');const raw=process.argv[1];"
            "if(!/^[1-9][0-9]{0,8}$/.test(raw))process.exit(2);"
            "const db=new sqlite3.Database('data/juiceshop.sqlite',sqlite3.OPEN_READONLY,(e)=>{"
            "if(e){process.exit(3)};db.get('SELECT id, UserId FROM Addresses WHERE id = ?',"
            "[Number(raw)],(err,row)=>{if(err){process.exit(4)};"
            "console.log(JSON.stringify(row?{id:row.id,UserId:row.UserId}:null));"
            "db.close(()=>{})})})"
        )
        result = self._docker(["exec", self.resources["target"], "/nodejs/bin/node", "-e", script,
                               str(object_id)], check=False, timeout=10)
        if result.returncode != 0 or self._snapshot() != self.source_files:
            raise RuntimeError("Read-only ownership observation failed")
        try:
            import json
            row = json.loads(result.stdout)
        except (TypeError, ValueError):
            raise RuntimeError("Read-only ownership observation was malformed") from None
        if (not isinstance(row, dict) or row.get("id") != object_id
                or type(row.get("UserId")) is not int or not 0 < row["UserId"] < 1_000_000_000):
            raise RuntimeError("Read-only ownership row was missing or invalid")
        from schemas.access_verification import DatabaseOwnershipProof
        role_by_id = {role.server_user_id: role.id for role in self.context.roles}
        proof = DatabaseOwnershipProof(
            generation_sha256=digest(self.generation), object_ref=object_ref,
            phase=phase,
            object_id=row["id"], owner_user_id=row["UserId"],
            owner_role=role_by_id.get(row["UserId"]), row_found=True,
        )
        self._persist({"phase": "b05-readonly-owner-observation",
                       "generation": self.generation, "proof": proof.model_dump(mode="json")})
        return proof

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
        deadline = self.deadline
        self.deadline = None  # Cleanup remains mandatory after an execution timeout.
        try:
            for key in ["worker", "target"]:
                self._docker(["rm", "-f", "-v", resources[key]], check=False)
            self._docker(["network", "rm", resources["network"]], check=False)
            remaining = self._docker(["ps", "-aq", "--filter", "label=cft.b04.generation=" + self.generation]).stdout.strip()
            networks = self._docker(["network", "ls", "-q", "--filter", "label=cft.b04.generation=" + self.generation]).stdout.strip()
            complete = not remaining and not networks
        except (OSError, RuntimeError, subprocess.SubprocessError):
            complete = False
        finally:
            self.deadline = deadline
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
