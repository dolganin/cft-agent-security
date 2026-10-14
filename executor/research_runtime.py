"""Operator-owned research workspace and HTTP broker behind SafeExecutor."""
from __future__ import annotations

import ipaddress
import json
import subprocess
import tempfile
import time
from hashlib import sha256
from pathlib import Path
from threading import RLock
from urllib.parse import urlsplit
from uuid import uuid4

from executor.sandbox import SandboxResult
from pipeline.cancellation import RunCancelled, current_token, suspend_cancellation
from schemas.research import HttpServiceScope, ResearchFile, ResearchScope, content_digest
from schemas.runtime import RuntimeServiceMap
from security.error_redaction import redact_error_message, redact_observation
from security.research_scope import binding_for, expand_search_paths, validate_research_action
from security.source_paths import normalize_source_path
from tools.repository_source import _safe_lines, _source_path

WORKER = Path(__file__).with_name("research_worker.py")


class ResearchRuntime:
    """No provider handles; model-visible source is an explicit redacted projection."""
    def __init__(self, *, target, source_files: list[str], worker_image: str, output: Path,
                 services: dict[str, HttpServiceScope] | None = None, network_name=None,
                 role_headers: dict[str, dict[str, str]] | None = None,
                 runtime_services: RuntimeServiceMap | None = None,
                 timeout=10.0, wall_seconds=300, max_actions=64, max_http_requests=32):
        self.target = target
        self.root = target.repository_path.resolve(strict=True)
        self.output = output.resolve()
        if (self.output.exists() or self.output.is_relative_to(self.root)
                or self.root.is_relative_to(self.output) or target.environment != "sandbox"):
            raise ValueError("A fresh output directory outside a sandbox source is required")
        self.output.mkdir(parents=True)
        self._projection_temp = tempfile.TemporaryDirectory(prefix="cft-research-source-")
        self.projection = Path(self._projection_temp.name)
        self.projection.chmod(0o755)
        self._roles = role_headers or {}
        self._roles = {name: dict(headers) for name, headers in self._roles.items()}
        self._lock = RLock()
        self._runtime_services = runtime_services
        self.container = "cft-research-" + uuid4().hex
        self.ready = False
        self.closed = False
        self.started = time.monotonic()
        self.timeout = timeout
        if not .1 <= timeout <= 30:
            raise ValueError("Research per-action timeout must be 0.1-30s")
        self.actions = 0
        self.requests = 0
        self.seen_actions: set[str] = set()
        inventory = {}
        total = 0
        for path in sorted(set(source_files)):
            path = normalize_source_path(path, self.root)
            if not _source_path(path):
                continue
            raw = (self.root / path).read_bytes()
            total += len(raw)
            if len(raw) > 1048576 or total > 20 * 1048576 or b"\0" in raw:
                raise ValueError("Research source exceeds bounded text inventory")
            visible = ("\n".join(_safe_lines(raw.decode("utf-8"))) + "\n").encode()
            destination = self.projection / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(visible)
            inventory[path] = ResearchFile(original_sha256=sha256(raw).hexdigest(),
                                           visible_sha256=sha256(visible).hexdigest())
        self.scope = ResearchScope(target_id=target.id, session_id="research-" + uuid4().hex,
                                   worker_image=worker_image, source_files=inventory,
                                   worker_sha256=sha256(WORKER.read_bytes()).hexdigest(),
                                   services=services or {}, network_name=network_name,
                                   wall_seconds=wall_seconds, max_actions=max_actions,
                                   runtime_services_sha256=(content_digest(runtime_services.model_dump(mode="json")) if runtime_services else None),
                                   target_runtime_session_id=runtime_services.session_id if runtime_services else None,
                                   max_http_requests=max_http_requests)
        if any(handle not in self._roles for service in self.scope.services.values()
               for handle in service.role_handles):
            raise ValueError("Operator role material is missing")
        if any(k.lower() not in {"authorization", "cookie"}
               or "\r" in v or "\n" in v
               for headers in self._roles.values() for k, v in headers.items()):
            raise ValueError("Invalid private role material")
        (self.output / "scope.json").write_text(self.scope.model_dump_json(indent=2))
        self._scope_digest = self.scope.digest

    @staticmethod
    def services_from_runtime_map(target, runtime_services, grants):
        """Resolve each approved service uniquely; no model URL/container selection."""
        if (not isinstance(runtime_services, RuntimeServiceMap) or not runtime_services.network_name
                or not set(grants).issubset(runtime_services.services)
                or not set(grants).issubset(target.services)):
            raise ValueError("Research HTTP grants require registered ready runtime services")
        network = subprocess.run(["docker", "network", "inspect", runtime_services.network_name],
                                 capture_output=True, text=True, check=True, timeout=10)
        network_info = json.loads(network.stdout)[0]
        if not network_info.get("Internal"):
            raise ValueError("RuntimeServiceMap must refer to an internal network")
        services = {}
        for name, grant in grants.items():
            service = runtime_services.services[name]
            if (not service.ready or service.request_host is not None
                    or set(grant) - {"read_prefixes", "write_paths", "role_handles"}):
                raise ValueError("Unsupported or unavailable runtime service grant")
            host = urlsplit(service.address).hostname
            matches = []
            for container_id in network_info.get("Containers", {}):
                result = subprocess.run(["docker", "inspect", container_id], capture_output=True,
                                        text=True, check=True, timeout=10)
                info = json.loads(result.stdout)[0]
                entry = info["NetworkSettings"]["Networks"][runtime_services.network_name]
                aliases = set(entry.get("Aliases") or []) | {info["Name"].lstrip("/"), entry["IPAddress"]}
                if host in aliases:
                    matches.append(info)
            if len(matches) != 1:
                raise ValueError("Runtime service container identity is absent or ambiguous")
            info = matches[0]
            services[name] = HttpServiceScope(container_id=info["Id"], image_id=info["Image"],
                                              address=service.address, **grant)
        return services

    @property
    def binding(self):
        return binding_for(self.scope)

    def _docker(self, args, *, input=None, timeout=30, check=True):
        process = subprocess.Popen(["docker", *args], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + timeout
        data = input
        try:
            while True:
                token = current_token()
                if token is not None and token.is_cancelled():
                    raise RunCancelled("Research action was cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("docker", timeout)
                try:
                    stdout, stderr = process.communicate(input=data, timeout=min(.1, remaining))
                    break
                except subprocess.TimeoutExpired:
                    data = None
        except BaseException:
            process.kill()
            process.communicate()
            raise
        result = subprocess.CompletedProcess(["docker", *args], process.returncode, stdout, stderr)
        if check and result.returncode:
            raise RuntimeError("Research Docker operation failed: " +
                               redact_error_message(result.stderr, max_length=240))
        return result

    def _event(self, event):
        with (self.output / "lifecycle.jsonl").open("a") as stream:
            stream.write(json.dumps({"session_id": self.scope.session_id, **event}) + "\n")

    def start(self):
        try:
            self._worker_image_id = json.loads(self._docker(["image", "inspect", self.scope.worker_image]).stdout)[0]["Id"]
            for service in self.scope.services.values():
                self._endpoint(service)
            self._docker(["run", "--detach", "--pull=never", "--name", self.container,
                          "--label", "cft.research.session=" + self.scope.session_id,
                          "--network=none", "--user=65534:65534", "--read-only",
                          "--log-driver=none",
                          "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                          "--memory=256m", "--cpus=1", "--pids-limit=32",
                          "--tmpfs", "/workspace:rw,noexec,nosuid,nodev,size=16m,uid=65534,gid=65534,mode=0700",
                          "--mount", f"type=bind,src={self.projection},dst=/target,readonly",
                          "--mount", f"type=bind,src={WORKER},dst=/app/research_worker.py,readonly",
                          self.scope.worker_image, "python3", "-c", "import time; time.sleep(3600)"])
            self.ready = True
            self.started = time.monotonic()
            self._event({"phase": "ready", "container": self.container,
                         "scope_sha256": self.scope.digest})
            return self
        except BaseException:
            self.close()
            raise

    def _endpoint(self, service):
        network = json.loads(self._docker(["network", "inspect", self.scope.network_name]).stdout)[0]
        if network.get("Internal") is not True:
            raise ValueError("HTTP broker requires an internal Docker network")
        targets = {value.container_id for value in self.scope.services.values()}
        for peer_id in network.get("Containers", {}):
            if peer_id in targets:
                continue
            peer = json.loads(self._docker(["inspect", peer_id]).stdout)[0]
            if (peer["Config"].get("Labels", {}).get("cft.research.session") != self.scope.session_id
                    or peer["Image"] != self._worker_image_id):
                raise ValueError("Unregistered peer in the research target network")
        info = json.loads(self._docker(["inspect", service.container_id]).stdout)[0]
        entry = info.get("NetworkSettings", {}).get("Networks", {}).get(self.scope.network_name)
        if (not info["State"]["Running"] or info["Image"] != service.image_id or not entry
                or set(info["NetworkSettings"]["Networks"]) != {self.scope.network_name}
                or any(info.get("NetworkSettings", {}).get("Ports", {}).values())
                or service.container_id not in network.get("Containers", {})):
            raise ValueError("HTTP target identity/network generation changed")
        ip = ipaddress.ip_address(entry["IPAddress"])
        url = urlsplit(service.address)
        if (url.scheme != "http" or not url.hostname or not url.port or url.username
                or url.password or url.path not in {"", "/"} or url.query or url.fragment
                or not ip.is_private or ip.is_loopback or ip.is_link_local):
            raise ValueError("Invalid registered local HTTP service")
        # The address hostname must be this container's own alias/name/IP.
        aliases = set(entry.get("Aliases") or []) | {info["Name"].lstrip("/"), str(ip)}
        if url.hostname not in aliases:
            raise ValueError("Runtime service address does not identify the registered container")
        return f"http://{ip}:{url.port}", url.hostname

    def execute(self, action, run_id):
        with self._lock:
            self.validate_live_scope()
            request = validate_research_action(self.scope, action)
            if (not self.ready or self.closed or action.id in self.seen_actions
                    or self.actions >= self.scope.max_actions
                    or time.monotonic() - self.started >= self.scope.wall_seconds):
                raise ValueError("Research session is closed, exhausted or action was replayed")
            self._check_source()
            self.actions += 1
            self.seen_actions.add(action.id)
            payload = {"tool": action.tool, "request": request.model_dump(mode="json"),
                       "visible_hashes": {p: f.visible_sha256 for p, f in self.scope.source_files.items()},
                       "timeout": min(self.timeout, self.scope.wall_seconds -
                                      (time.monotonic() - self.started))}
            if action.tool == "search_source" and request.paths:
                payload["request"]["paths"] = expand_search_paths(self.scope, request.paths)
            container = self.container
            ephemeral = False
            http_start = None
            if action.tool == "target_http":
                if self.requests >= self.scope.max_http_requests:
                    raise ValueError("Research HTTP request budget exhausted")
                self.requests += 1
                service = self.scope.services[action.service]
                address, host = self._endpoint(service)
                payload.update(address=address, request_host=host,
                               role_headers=self._roles.get(request.role_handle, {}))
                container = "cft-research-http-" + uuid4().hex
                ephemeral = True
                http_start = ["run", "--detach", "--pull=never", "--name", container,
                              "--label", "cft.research.session=" + self.scope.session_id,
                              "--network", self.scope.network_name, "--user=65534:65534",
                              "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                              "--memory=64m", "--pids-limit=8", "--cpus=.5",
                              "--mount", f"type=bind,src={WORKER},dst=/app/research_worker.py,readonly",
                              self.scope.worker_image, "python3", "-c", "import time; time.sleep(60)"]
            started = time.monotonic()
            timed_out = False
            try:
                if http_start is not None:
                    self._docker(http_start)
                result = self._docker(["exec", "-i", container, "python3", "/app/research_worker.py"],
                                      input=json.dumps(payload), timeout=payload["timeout"] + 3,
                                      check=False)
                self._check_source()
                if action.tool == "target_http":
                    self._endpoint(service)
                stdout, stderr, exit_code = result.stdout, result.stderr, result.returncode
                if action.tool == "sandbox_command" and exit_code == 0:
                    observation = json.loads(stdout)["observation"]
                    exit_code = observation["exit_code"]
                    timed_out = observation["timed_out"]
                if action.tool == "sandbox_command":
                    self._docker(["exec", "-i", container, "python3", "/app/research_worker.py"],
                                 input=json.dumps({"tool": "operator_cleanup", "request": {}}))
            except RunCancelled:
                if not ephemeral:
                    self.close()
                raise
            except subprocess.TimeoutExpired:
                timed_out = True
                stdout, stderr, exit_code = "", "Research worker timed out", 124
                if not ephemeral:
                    self.close()
            finally:
                if ephemeral:
                    with suspend_cancellation():
                        self._remove_container(container)
                        self._event({"phase": "http_cleanup", "container": container,
                                     "cleanup_verified": True})
            for headers in self._roles.values():
                for secret in headers.values():
                    stdout = stdout.replace(secret, "<redacted>")
                    for piece in secret.split():
                        if len(piece) > 8:
                            stdout = stdout.replace(piece, "<redacted>")
            self._event({"phase": "action", "action_id": action.id, "run_id": run_id,
                         "tool": action.tool, "requests": self.requests, "exit_code": exit_code})
            try:
                stdout = json.dumps(redact_observation(json.loads(stdout)), ensure_ascii=False)
            except (ValueError, TypeError):
                stdout = redact_error_message(stdout, max_length=32768)
            return SandboxResult(run_id=run_id, exit_code=exit_code,
                                 stdout=stdout,
                                 stderr=redact_error_message(stderr, max_length=16384),
                                 timed_out=timed_out, workspace_id=self.scope.session_id,
                                 duration_ms=int((time.monotonic() - started) * 1000),
                                 runtime_backend="docker")

    def _check_source(self):
        if (self._runtime_services is not None and
                content_digest(self._runtime_services.model_dump(mode="json")) != self.scope.runtime_services_sha256):
            raise ValueError("RuntimeServiceMap changed after research scope freeze")
        if sha256(WORKER.read_bytes()).hexdigest() != self.scope.worker_sha256:
            raise ValueError("Trusted research worker changed after scope freeze")
        for path, expected in self.scope.source_files.items():
            normalize_source_path(path, self.root)
            if sha256((self.root / path).read_bytes()).hexdigest() != expected.original_sha256:
                raise ValueError("Original source changed after research scope freeze")
            if (self._runtime_services and path in self._runtime_services.source_files_sha256
                    and self._runtime_services.source_files_sha256[path] != expected.original_sha256):
                raise ValueError("Research source differs from the RuntimeServiceMap snapshot")
            if sha256((self.projection / path).read_bytes()).hexdigest() != expected.visible_sha256:
                raise ValueError("Projected source changed after research scope freeze")

    def validate_live_scope(self):
        if not self.ready or self.closed or self.scope.digest != self._scope_digest:
            raise ValueError("Research runtime/scope is unavailable or mutated")
        self._check_source()

    def _remove_container(self, container):
        self._docker(["rm", "--force", container], check=False)
        remaining = self._docker(["container", "inspect", container], check=False)
        if remaining.returncode == 0 or "No such" not in remaining.stderr:
            self.ready = False
            raise RuntimeError("Research container cleanup unverified")

    def close(self):
        with self._lock, suspend_cancellation():
            if self.closed:
                return
            self.ready = False
            self._remove_container(self.container)
            remaining = self._docker(["ps", "--all", "--quiet", "--filter",
                                      "label=cft.research.session=" + self.scope.session_id]).stdout.strip()
            if remaining:
                raise RuntimeError("Research cleanup unverified")
            self.closed = True
            self._projection_temp.cleanup()
            self._roles.clear()
            self._event({"phase": "closed", "cleanup_verified": True})

    def __enter__(self):
        return self.start()

    def __exit__(self, *_):
        self.close()
