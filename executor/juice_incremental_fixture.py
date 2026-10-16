"""Disposable operator-only Docker lab for the first two Juice Shop proof protocols."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

from evaluation.scanner_baseline import validate_target
from schemas.juice_incremental_proof import (
    ProductPutTrial,
    RoleRegistrationTrial,
    product_put_disposition,
    role_registration_disposition,
)

ROOT = Path(__file__).resolve().parents[1]
TARGET_COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
TARGET_IMAGE = "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
WORKER_IMAGE = "python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"
WORKER = ROOT / "executor/juice_incremental_worker.py"
PROTOCOLS = {
    "role-registration": {
        "id": "juice-role-registration-v1",
        "sources": ("server.ts", "routes/login.ts", "routes/currentUser.ts",
                    "models/user.ts", "lib/insecurity.ts"),
    },
    "anonymous-product-put": {
        "id": "juice-anonymous-product-put-v1",
        "sources": ("server.ts", "models/product.ts", "models/user.ts", "lib/insecurity.ts"),
    },
}


def _sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_digest(value: object) -> str:
    return _sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


class JuiceIncrementalFixture:
    """One fixed protocol in one isolated target generation; no agent capability."""

    def __init__(self, *, repository: Path, output: Path, protocol: str,
                 wall_time_seconds: int = 240):
        if protocol not in PROTOCOLS:
            raise ValueError("Juice mini-proof protocol is not registered")
        if not 90 <= wall_time_seconds <= 600:
            raise ValueError("Juice mini-proof time budget must be 90-600 seconds")
        self.repository = Path(repository).resolve(strict=True)
        self.output = Path(output).resolve()
        if (self.output.exists() or self.output.is_relative_to(self.repository)
                or self.repository.is_relative_to(self.output)):
            raise ValueError("Proof output must be fresh and outside the target checkout")
        if any(char in str(path) for path in (self.output, WORKER) for char in (",", "\n", "\r")):
            raise ValueError("Docker bind paths contain unsupported delimiter characters")
        self.protocol = protocol
        self.protocol_config = PROTOCOLS[protocol]
        self.wall_time_seconds = wall_time_seconds
        self.generation = uuid4().hex[:16]
        self.name_prefix = "j01-" + self.generation
        self.resources = {
            "target": self.name_prefix + "-juice",
            "worker": self.name_prefix + "-worker",
            "network": self.name_prefix + "-net",
        }
        self.label = "cft.j01.generation=" + self.generation
        self.source_files: dict[str, str] = {}
        self.worker_sha256: str | None = None
        self.profile_sha256: str | None = None
        self.output.mkdir(parents=True)
        self._write_event({"phase": "created", "generation": self.generation,
                           "protocol_id": self.protocol_config["id"],
                           "target_commit": TARGET_COMMIT, "target_image": TARGET_IMAGE,
                           "worker_image": WORKER_IMAGE})

    def _docker(self, args: list[str], *, timeout: int = 30, check: bool = True):
        env = {key: value for key, value in os.environ.items() if key.upper() in {
            "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP", "HOME", "USERPROFILE",
            "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "APPDATA", "LOCALAPPDATA",
            "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH",
        }}
        result = subprocess.run(
            ["docker", *args], capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, check=False, env=env,
        )
        if check and result.returncode:
            raise RuntimeError("Docker mini-proof operation failed")
        return result

    def _write_event(self, event: dict) -> None:
        with (self.output / "lifecycle.jsonl").open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

    def _snapshot(self) -> dict[str, str]:
        result = {}
        for relative in self.protocol_config["sources"]:
            path = self.repository / relative
            resolved = path.resolve(strict=True)
            if (path.is_symlink() or not resolved.is_relative_to(self.repository)
                    or resolved.relative_to(self.repository).as_posix() != relative
                    or not resolved.is_file()):
                raise ValueError("Mini-proof source path is not canonical")
            raw = resolved.read_bytes()
            if len(raw) > 1_048_576:
                raise ValueError("Mini-proof source size limit exceeded")
            result[relative] = _sha(raw)
        return result

    def _prepare(self) -> dict:
        target_files = validate_target(
            self.repository, SimpleNamespace(target_commit=TARGET_COMMIT),
        )
        if any(relative not in target_files for relative in self.protocol_config["sources"]):
            raise ValueError("Mini-proof source set is not in the frozen target")
        self.source_files = self._snapshot()
        worker_bytes = WORKER.read_bytes()
        self.worker_sha256 = _sha(worker_bytes)
        profile = {
            "schema_version": "juice.incremental.proof-profile.v1",
            "protocol_id": self.protocol_config["id"],
            "generation": self.generation,
            "source_snapshot_sha256": _canonical_digest(self.source_files),
            "source_files": self.source_files,
            "target_commit": TARGET_COMMIT,
            "target_image": TARGET_IMAGE,
            "worker_sha256": self.worker_sha256,
            "worker_image": WORKER_IMAGE,
        }
        self.profile_sha256 = _canonical_digest(profile)
        config = {**profile, "profile_sha256": self.profile_sha256}
        self._docker(["image", "inspect", TARGET_IMAGE])
        self._docker(["image", "inspect", WORKER_IMAGE])
        profile_path = self.output / "profile.json"
        profile_path.write_text(json.dumps(config, sort_keys=True), encoding="utf-8")
        self._write_event({"phase": "prepare", "generation": self.generation,
                           "protocol_id": self.protocol_config["id"],
                           "source_files": self.source_files,
                           "source_snapshot_sha256": _canonical_digest(self.source_files),
                           "profile_sha256": self.profile_sha256,
                           "worker_sha256": self.worker_sha256,
                           "target_commit": TARGET_COMMIT, "target_image": TARGET_IMAGE,
                           "worker_image": WORKER_IMAGE})
        self._docker(["network", "create", "--internal", "--label", self.label,
                      self.resources["network"]])
        self._docker([
            "run", "-d", "--pull=never", "--name", self.resources["target"],
            "--label", self.label, "--network", self.resources["network"], "--network-alias=juice",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=768m",
            "--cpus=2", "--pids-limit=128", "--log-driver=local", "--log-opt=max-size=10m",
            "--log-opt=max-file=2", TARGET_IMAGE,
        ])
        readiness_attempts = 0
        ready = False
        for _ in range(90):
            readiness_attempts += 1
            result = self._docker([
                "exec", self.resources["target"], "/nodejs/bin/node", "-e",
                (
                    "require('http').get('http://127.0.0.1:3000/',r=>{r.resume();"
                    "if(r.statusCode===200)console.log('ready')}).on('error',()=>process.exit(1))"
                ),
            ], timeout=5, check=False)
            if result.stdout.strip() == "ready":
                ready = True
                break
            time.sleep(1)
        if not ready:
            raise RuntimeError("Juice Shop mini-proof target did not become ready")
        self._write_event({"phase": "readiness", "generation": self.generation,
                           "attempts": readiness_attempts, "ready": True})
        return config

    def _execute_worker(self) -> dict:
        if self._snapshot() != self.source_files or _sha(WORKER.read_bytes()) != self.worker_sha256:
            raise ValueError("Source or worker changed after proof binding")
        profile_path = self.output / "profile.json"
        result = self._docker([
            "run", "--name", self.resources["worker"], "--pull=never",
            "--network", self.resources["network"], "--user=65532:65532", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=128m",
            "--cpus=1", "--pids-limit=32", "--log-driver=local", "--log-opt=max-size=1m",
            # Docker Desktop may enable local-log compression, which rejects max-file=1.
            "--log-opt=max-file=2", "--tmpfs", "/tmp:rw,noexec,nosuid,size=8m,uid=65532,gid=65532,mode=0700",
            "--tmpfs", "/state:rw,noexec,nosuid,size=1m,uid=65532,gid=65532,mode=0700",
            "--env", "CFT_JUICE_MINI_CONTAINER=1",
            "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--mount", f"type=bind,src={profile_path},dst=/input/profile.json,readonly",
            "--mount", f"type=bind,src={WORKER},dst=/app/proof.py,readonly",
            "--entrypoint", "python", WORKER_IMAGE, "/app/proof.py",
        ], timeout=self.wall_time_seconds, check=False)
        if len(result.stdout) > 65_536 or result.returncode != 0:
            self._write_event({"phase": "worker-failed", "generation": self.generation,
                               "returncode": result.returncode,
                               "stdout_bytes": len(result.stdout), "stderr_bytes": len(result.stderr)})
            raise RuntimeError("Fixed mini-proof worker failed")
        try:
            envelope = json.loads(result.stdout)
        except (ValueError, TypeError):
            raise RuntimeError("Fixed mini-proof worker returned malformed JSON") from None
        if (not isinstance(envelope, dict) or set(envelope) != {"status", "trial"}
                or envelope.get("status") != "completed"):
            self._write_event({"phase": "worker-failed", "generation": self.generation,
                               "returncode": result.returncode, "status": (
                                   envelope.get("status") if isinstance(envelope, dict) else None
                               )})
            raise RuntimeError("Fixed mini-proof did not complete")
        if (self._snapshot() != self.source_files or _sha(WORKER.read_bytes()) != self.worker_sha256):
            raise ValueError("Source or worker changed during proof execution")
        if self.protocol == "role-registration":
            trial = RoleRegistrationTrial.model_validate(envelope["trial"])
            if (trial.generation_sha256 != _canonical_digest(self.generation)
                    or trial.source_snapshot_sha256 != _canonical_digest(self.source_files)
                    or trial.profile_sha256 != self.profile_sha256
                    or trial.worker_sha256 != self.worker_sha256):
                raise ValueError("Role-registration trial binding mismatch")
            disposition = role_registration_disposition(trial)
        else:
            trial = ProductPutTrial.model_validate(envelope["trial"])
            if (trial.generation_sha256 != _canonical_digest(self.generation)
                    or trial.source_snapshot_sha256 != _canonical_digest(self.source_files)
                    or trial.profile_sha256 != self.profile_sha256
                    or trial.worker_sha256 != self.worker_sha256):
                raise ValueError("Product-PUT trial binding mismatch")
            disposition = product_put_disposition(trial)
        normalized = {"trial": trial.model_dump(mode="json"), "disposition": disposition}
        (self.output / "trial.json").write_text(
            json.dumps(normalized, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        self._write_event({"phase": "proof", "generation": self.generation,
                           "protocol_id": self.protocol_config["id"],
                           "disposition": disposition, "http_exchanges": trial.http_exchanges,
                           "trial_sha256": _canonical_digest(normalized)})
        return normalized

    def _cleanup(self) -> bool:
        try:
            self._docker(["rm", "-f", self.resources["worker"]], check=False, timeout=15)
            self._docker(["rm", "-f", self.resources["target"]], check=False, timeout=15)
            self._docker(["network", "rm", self.resources["network"]], check=False, timeout=15)
            containers = self._docker([
                "ps", "-aq", "--filter", "label=" + self.label,
            ], timeout=15, check=False).stdout.strip()
            networks = self._docker([
                "network", "ls", "-q", "--filter", "label=" + self.label,
            ], timeout=15, check=False).stdout.strip()
            complete = not containers and not networks
        except (OSError, RuntimeError, subprocess.SubprocessError):
            complete = False
        self._write_event({"phase": "cleanup", "generation": self.generation,
                           "cleanup_complete": complete})
        return complete

    def run(self) -> dict:
        result = None
        failure = None
        cleanup_complete = False
        try:
            self._prepare()
            if self._snapshot() != self.source_files:
                raise ValueError("Target source changed after fixture preparation")
            result = self._execute_worker()
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
            failure = type(exc).__name__
        finally:
            cleanup_complete = self._cleanup()
        target_unchanged = bool(self.source_files) and self._safe_snapshot_matches()
        if result is not None and (not cleanup_complete or not target_unchanged):
            result["pre_cleanup_disposition"] = result["disposition"]
            result["disposition"] = "inconclusive"
        if not cleanup_complete and failure is None:
            failure = "CleanupUnverified"
        output = {
            "protocol": self.protocol,
            "generation": self.generation,
            "result": result,
            "failure_type": failure,
            "cleanup_complete": cleanup_complete,
            "target_source_unchanged": target_unchanged,
        }
        self._write_event({"phase": "complete", "generation": self.generation,
                           "protocol": self.protocol, "failure_type": failure,
                           "cleanup_complete": cleanup_complete,
                           "target_source_unchanged": output["target_source_unchanged"]})
        (self.output / "result.json").write_text(
            json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
        return output

    def _safe_snapshot_matches(self) -> bool:
        try:
            return self._snapshot() == self.source_files
        except (OSError, ValueError):
            return False
