"""Docker-only networkless Chromium plus deterministic registered HTTP bridge."""
import base64
import json
import queue
import subprocess
import threading
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from executor.sandbox import SandboxResult
from pipeline.cancellation import check_cancelled, suspend_cancellation
from security.error_redaction import redact_observation
from security.research_scope import validate_research_action

WORKER = Path(__file__).with_name("research_browser_worker.py")


class BrowserTransport:
    """One fixed Docker worker process per action, no model access to this channel."""
    def __init__(self, container):
        self.process = subprocess.Popen(["docker", "exec", "-i", container, "python3", "/app/worker.py", "--browser-server"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.messages = queue.Queue(maxsize=2)

        def reader():
            try:
                while data := self.process.stdout.readline(3145729):
                    if len(data) > 3145728:
                        break
                    self.messages.put(data, timeout=1)
            except (OSError, ValueError, queue.Full):
                pass

        self.thread = threading.Thread(target=reader, daemon=True)
        self.thread.start()

    def request(self, payload, deadline):
        self.process.stdin.write(json.dumps(payload).encode()+b"\n")
        self.process.stdin.flush()
        while time.monotonic() < deadline:
            check_cancelled()
            try:
                return json.loads(self.messages.get(timeout=.1))
            except queue.Empty:
                if self.process.poll() is not None:
                    raise RuntimeError("Browser transport exited")
        raise subprocess.TimeoutExpired("browser transport", 3)

    def close(self):
        self.process.kill()
        self.process.wait(timeout=5)
        self.thread.join(timeout=1)
        try:
            self.process.stdin.close()
        except BrokenPipeError:
            pass  # Child exit is verified; flushing its already closed pipe is not a cleanup failure.
        self.process.stdout.close()


def check_pinned_target(runtime, service, expected_network_id, expected_address):
    info = json.loads(runtime._docker(["inspect", service.container_id]).stdout)[0]
    networks = info["NetworkSettings"]["Networks"]
    entry = networks.get(runtime.scope.network_name, {})
    if (not info["State"]["Running"] or info["Image"] != service.image_id
            or set(networks) != {runtime.scope.network_name}
            or entry.get("NetworkID") != expected_network_id
            or "http://"+entry.get("IPAddress", "")+":"+expected_address.rsplit(":",1)[1] != expected_address
            or any(info["NetworkSettings"].get("Ports", {}).values())):
        raise ValueError("Browser target generation/network changed")


def browser_bridge_request(runtime, action, message):
    """Browser cannot pick origin/container/credentials; revalidate every request."""
    if set(message) != {"method", "path", "body", "headers"}:
        raise ValueError("Malformed browser bridge request")
    subaction = action.model_copy(update={"tool": "target_http", "endpoint": message["path"],
                                         "parameters": message})
    request = validate_research_action(runtime.scope, subaction)
    if runtime.requests >= runtime.scope.max_http_requests:
        raise ValueError("Browser exhausted the shared HTTP request budget")
    runtime.requests += 1
    return request


def execute_browser(runtime, action, request, run_id, transport_worker):
    started = time.monotonic()
    # Includes all resource requests, browser bootstrap, observations and cleanup.
    deadline = min(runtime.started + runtime.scope.wall_seconds, started + runtime.timeout)
    browser_name, broker = "cft-browser-" + uuid4().hex, "cft-browser-http-" + uuid4().hex
    process = None
    transport = None
    ledger = []
    service = runtime.scope.services[action.service]
    observation = None
    timed_out = False
    exit_code = 2
    stages = []
    transport_bytes = 0
    try:
        address, host = runtime._endpoint(service)
        target_info = json.loads(runtime._docker(["inspect", service.container_id]).stdout)[0]
        network_id = target_info["NetworkSettings"]["Networks"][runtime.scope.network_name]["NetworkID"]
        runtime._docker(["run", "--detach", "--pull=never", "--name", broker,
            "--label", "cft.research.session=" + runtime.scope.session_id,
            "--network", runtime.scope.network_name, "--user=65534:65534", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--log-driver=none",
            "--memory=96m", "--cpus=.5", "--pids-limit=8",
            "--mount", f"type=bind,src={transport_worker},dst=/app/worker.py,readonly",
            runtime.scope.worker_image, "python3", "-c", "import time;time.sleep(120)"])
        transport = BrowserTransport(broker)
        runtime._docker(["run", "--detach", "--init", "--pull=never", "--name", browser_name,
            "--label", "cft.research.session=" + runtime.scope.session_id,
            "--network=none", "--user=65534:65534", "--read-only", "--log-driver=none",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=768m",
            "--cpus=1", "--pids-limit=128", "--shm-size=128m",
            "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m,mode=1777",
            "--env", "HOME=/tmp", "--env", "PYTHONDONTWRITEBYTECODE=1",
            "--mount", f"type=bind,src={WORKER},dst=/app/browser.py,readonly",
            runtime.scope.browser_image, "python3", "-c", "import time;time.sleep(120)"])
        isolated = json.loads(runtime._docker(["inspect", browser_name]).stdout)[0]
        if (isolated["HostConfig"]["NetworkMode"] != "none"
                or not isolated["HostConfig"]["ReadonlyRootfs"]
                or isolated["HostConfig"].get("Privileged")
                or isolated["Image"] != runtime._browser_image_id
                or isolated["Config"]["User"] != "65534:65534"):
            raise ValueError("Browser Docker isolation does not match operator requirements")
        process = subprocess.Popen(["docker", "exec", "-i", browser_name, "python3", "/app/browser.py"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        messages = queue.Queue(maxsize=4)

        def reader():
            try:
                while True:
                    data = process.stdout.readline(2097153)
                    if not data:
                        break
                    if len(data) > 2097152:
                        messages.put(None, timeout=1)
                        return
                    messages.put(data, timeout=1)
            except (OSError, ValueError, queue.Full):
                pass
            finally:
                try:
                    messages.put(None, timeout=1)
                except queue.Full:
                    pass

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        process.stdin.write(json.dumps({"request": request.model_dump(mode="json"),
            "max_requests": min(64, runtime.scope.max_http_requests - runtime.requests)}).encode() + b"\n")
        process.stdin.flush()
        count = 0
        while time.monotonic() < deadline:
            check_cancelled()
            try:
                line = messages.get(timeout=.1)
            except queue.Empty:
                continue
            if line is None:
                break
            message = json.loads(line)
            if "progress" in message:
                if len(stages) < 16:
                    stages.append(message["progress"])
                continue
            if "result" in message:
                observation = message["result"]
                exit_code = 0
                break
            if "error" in message:
                stages.append("worker_error:" + str(message["error"])[:64])
                break
            if "transport" not in message or count >= 64:
                break
            count += 1
            incoming = message["transport"]
            transport_started = time.monotonic()
            try:
                allowed = browser_bridge_request(runtime, action, incoming)
            except ValueError:
                response = {"denied": True}
                ledger.append({"ordinal": count, "allowed": False})
            else:
                check_pinned_target(runtime, service, network_id, address)
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired("browser", runtime.timeout)
                result = transport.request({"tool": "target_http", "request": allowed.model_dump(mode="json"),
                        "address": address, "request_host": host, "browser_transport": True,
                        "timeout": min(3, remaining)}, min(deadline, time.monotonic()+4))
                check_pinned_target(runtime, service, network_id, address)
                if "observation" not in result:
                    response = {"denied": True}
                    ledger.append({"ordinal": count, "allowed": True, "failed": True, "path":allowed.path[:240]})
                else:
                    response = result["observation"]
                    transport_bytes += len(base64.b64decode(response["body_base64"]))
                    ledger.append({"ordinal": count, "allowed": True, "method": allowed.method,
                        "path": allowed.path[:240], "path_sha256": sha256(allowed.path.encode()).hexdigest(),
                        "status": response["status"],
                        "response_sha256": sha256(base64.b64decode(response["body_base64"])).hexdigest()})
                    if 300 <= response["status"] < 400:
                        response = {"denied":True}
                        ledger[-1]["redirect_blocked"] = True
                    if transport_bytes > 16777216:
                        response = {"denied":True}
                        ledger[-1]["transport_budget_exhausted"] = True
            ledger[-1]["duration_ms"] = int((time.monotonic()-transport_started)*1000)
            process.stdin.write(json.dumps(response).encode() + b"\n")
            process.stdin.flush()
        else:
            timed_out = True
    except subprocess.TimeoutExpired:
        timed_out = True
    except OSError as exc:
        stages.append("transport_error:" + type(exc).__name__)
    finally:
        with suspend_cancellation():
            cleanup_errors = []
            for cleanup in (
                lambda: close_process(process),
                lambda: transport.close() if transport is not None else None,
                lambda: runtime._remove_container(browser_name),
                lambda: runtime._remove_container(broker),
            ):
                try:
                    cleanup()
                except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
                    cleanup_errors.append(type(exc).__name__)
            if cleanup_errors:
                raise RuntimeError("Browser cleanup unverified: " + ",".join(cleanup_errors))
    runtime._check_source()
    runtime._endpoint(service)
    observation = observation or {"kind": "failed_browser_observation", "timed_out": timed_out}
    png = observation.pop("screenshot_base64", None)
    if png:
        raw = base64.b64decode(png, validate=True)
        if len(raw) > 1048576 or not raw.startswith(b"\x89PNG\r\n\x1a\n"):
            raise ValueError("Invalid bounded browser screenshot")
        path = runtime.output / (run_id + ".png")
        path.write_bytes(raw)
        observation["screenshot_ref"] = str(path)
        observation["screenshot_sha256"] = sha256(raw).hexdigest()
    observation.update(network_ledger=ledger, stages=stages, transport_bytes=transport_bytes,
                       cleanup_verified=True, isolation_validated=True,
                       anonymous_context=True, independent_verification="pending")
    stdout = json.dumps(redact_observation({"observation": observation, "verdict": "inconclusive"}))
    runtime._event({"phase": "browser_action", "action_id": action.id, "run_id": run_id,
                    "requests": runtime.requests, "cleanup_verified": True})
    return SandboxResult(run_id=run_id, exit_code=124 if timed_out else exit_code, stdout=stdout,
        stderr="Browser observation incomplete" if exit_code else "", timed_out=timed_out,
        workspace_id=runtime.scope.session_id, duration_ms=int((time.monotonic()-started)*1000),
        runtime_backend="docker")


def close_process(process):
    if process is None:
        return
    process.kill()
    process.wait(timeout=5)
    try:
        process.stdin.close()
    except BrokenPipeError:
        pass  # Child is already reaped, and both containers are independently removed.
    process.stdout.close()
