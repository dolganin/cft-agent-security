"""Fixed stdlib worker. Model source runs only in the networkless Docker workspace."""
from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import resource
import selectors
import signal
import subprocess
import sys
import time
from pathlib import Path
from urllib.parse import urlsplit

LIMIT = 16384


def file_at(root: Path, name: str) -> Path:
    if (not name or name.startswith("/") or "\\" in name
            or any(p in {"", ".", ".."} or ":" in p for p in name.split("/"))):
        raise ValueError("Noncanonical worker file")
    current = root
    for part in name.split("/"):
        current = current / part
        if current.is_symlink():
            raise ValueError("Linked worker file")
    if not current.resolve().is_relative_to(root):
        raise ValueError("Worker path escaped root")
    return current


def read_file(path: Path, limit: int = 1048576) -> bytes:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit or b"\0" in data:
        raise ValueError("Oversized/binary worker file")
    return data


def source(path: str, hashes: dict) -> bytes:
    if path not in hashes:
        raise ValueError("Unregistered source")
    data = read_file(file_at(Path("/target"), path))
    if hashlib.sha256(data).hexdigest() != hashes[path]:
        raise ValueError("Projected source changed")
    return data


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    resource.setrlimit(resource.RLIMIT_CPU, (8, 8))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def script(request: dict, timeout: float) -> dict:
    argv = request["argv"]
    if argv[0] not in {"python3", "node"} or not argv[1].startswith("/workspace/"):
        raise ValueError("Unsupported script runner")
    path = file_at(Path("/workspace"), argv[1][len("/workspace/"):])
    data = read_file(path, 65536)
    if hashlib.sha256(data).hexdigest() != request["script_sha256"]:
        raise ValueError("Workspace script changed after approval")
    # Freeze the exact approved bytes; node/python read noexec tmpfs through the interpreter.
    import tempfile
    suffix = ".py" if argv[0] == "python3" else ".js"
    with tempfile.TemporaryDirectory(prefix=".exec-", dir="/workspace") as directory:
        frozen = Path(directory) / ("script" + suffix)
        frozen.write_bytes(data)
        limits()
        process = subprocess.Popen([argv[0], str(frozen), *argv[2:]], cwd="/workspace",
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env={"PATH": "/usr/local/bin:/usr/bin:/bin",
                                        "PYTHONDONTWRITEBYTECODE": "1"}, start_new_session=True)
        selector = selectors.DefaultSelector()
        buffers = {"stdout": bytearray(), "stderr": bytearray()}
        truncated = {"stdout": False, "stderr": False}
        for pipe, label in [(process.stdout, "stdout"), (process.stderr, "stderr")]:
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        deadline = time.monotonic() + timeout
        timed_out = False
        try:
            while selector.get_map():
                if time.monotonic() >= deadline:
                    timed_out = True
                    break
                for key, _ in selector.select(min(.05, max(0, deadline - time.monotonic()))):
                    chunk = os.read(key.fileobj.fileno(), 8192)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    buffer = buffers[key.data]
                    remaining = LIMIT - len(buffer)
                    buffer.extend(chunk[:remaining])
                    truncated[key.data] |= len(chunk) > remaining
            if not timed_out:
                process.wait(timeout=max(.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
        finally:
            # Terminate the process group even if the parent exited leaving descendants.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=2)
            selector.close()
            process.stdout.close()
            process.stderr.close()
        return {"exit_code": 124 if timed_out else process.returncode, "timed_out": timed_out,
                "stdout": buffers["stdout"].decode(errors="replace"),
                "stderr": buffers["stderr"].decode(errors="replace"), "truncated": truncated,
                "script_sha256": request["script_sha256"], "argv": argv, "cwd": "/workspace"}


def http_observation(payload: dict) -> dict:
    request = payload["request"]
    address = urlsplit(payload["address"])
    ip = ipaddress.ip_address(address.hostname)
    if address.scheme != "http" or not ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("HTTP worker requires a pinned private container IP")
    headers = {**request.get("headers", {}), **payload.get("role_headers", {})}
    headers["Host"] = payload["request_host"]
    connection = http.client.HTTPConnection(str(ip), address.port, timeout=payload["timeout"])
    try:
        connection.request(request["method"], request["path"],
                           body=request.get("body", "").encode() or None, headers=headers)
        response = connection.getresponse()
        limit = 2097152 if payload.get("browser_transport") else LIMIT
        data = response.read(limit + 1)
        if payload.get("browser_transport"):
            import base64
            if len(data) > limit:
                raise ValueError("Browser resource exceeded bounded transport")
            return {"status": response.status, "body_base64": base64.b64encode(data).decode(),
                    "headers": {k: v[:8192] for k, v in response.getheaders()
                        if k.lower() in {"content-type", "location", "content-security-policy",
                            "content-security-policy-report-only", "x-content-type-options",
                            "x-frame-options", "referrer-policy", "permissions-policy"}}}
        return {"method": request["method"], "path": request["path"],
                "status_code": response.status, "body": data[:LIMIT].decode(errors="replace"),
                "response_sha256": hashlib.sha256(data[:LIMIT]).hexdigest(),
                "body_truncated": len(data) > LIMIT,
                "headers": {k: v[:2048] for k, v in response.getheaders()
                            if k.lower() in {"location", "content-type"}},
                "redirect_followed": False, "role_handle": request.get("role_handle")}
    finally:
        connection.close()


def work(payload: dict) -> dict:
    tool, request = payload["tool"], payload["request"]
    if tool == "operator_cleanup":
        # Only operator code dispatches this lifecycle operation. Kill detached children too.
        own = os.getpid()
        for entry in Path("/proc").iterdir():
            if entry.name.isdecimal() and int(entry.name) not in {1, own}:
                try:
                    os.kill(int(entry.name), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        return {"cleanup_complete": True}
    hashes = payload.get("visible_hashes", {})
    if tool == "target_http":
        return http_observation(payload)
    if tool == "list_source_files":
        paths = sorted(hashes)
        offset, count = request["offset"], request["limit"]
        return {"files": paths[offset:offset + count], "total": len(paths),
                "next_offset": offset + count if offset + count < len(paths) else None}
    if tool == "read_source":
        lines = source(request["path"], hashes).decode().splitlines()
        content = "\n".join(f"{i + 1}: {line}" for i, line in enumerate(lines)
                            if request["line_start"] <= i + 1 <= request["line_end"])
        return {"path": request["path"], "content": content[:LIMIT],
                "truncated": len(content) > LIMIT, "visible_sha256": hashes[request["path"]]}
    if tool == "search_source":
        matches = []
        for path in request["paths"] or sorted(hashes):
            for line, content in enumerate(source(path, hashes).decode().splitlines(), 1):
                if request["literal"] in content:
                    matches.append({"path": path, "line": line, "content": content[:160]})
                    if len(matches) == request["max_matches"]:
                        return {"matches": matches, "limit_reached": True}
        return {"matches": matches, "limit_reached": False}
    if tool == "write_workspace_file":
        path = file_at(Path("/workspace"), request["path"])
        data = request["content"].encode()
        if len(data) > 65536:
            raise ValueError("Workspace file exceeds byte budget")
        path.parent.mkdir(parents=True, exist_ok=True)
        # A process from an earlier action cannot survive a completed command.
        import tempfile
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as stream:
            stream.write(data)
            temporary = Path(stream.name)
        os.replace(temporary, path)
        return {"path": request["path"], "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data)}
    if tool == "read_workspace_file":
        data = read_file(file_at(Path("/workspace"), request["path"]), 65536)
        return {"path": request["path"], "content": data[:LIMIT].decode(errors="replace"),
                "truncated": len(data) > LIMIT, "sha256": hashlib.sha256(data).hexdigest()}
    if tool == "sandbox_command":
        return script(request, payload["timeout"])
    raise ValueError("Unknown research worker operation")


if __name__ == "__main__":
    if sys.argv[1:] == ["--browser-server"]:
        for _ in range(64):
            line = sys.stdin.readline(65537)
            if not line:
                break
            try:
                payload = json.loads(line)
                if payload.get("tool") != "target_http" or payload.get("browser_transport") is not True:
                    raise ValueError("Only fixed browser transport is supported")
                print(json.dumps({"observation":http_observation(payload)}), flush=True)
            except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
                print(json.dumps({"error":type(exc).__name__}), flush=True)
        sys.exit(0)
    try:
        payload = json.loads(sys.stdin.buffer.read(262145))
        result = work(payload)
        print(json.dumps({"observation": result, "verdict": "inconclusive"}))
    except (ValueError, KeyError, TypeError, OSError, RuntimeError) as exc:
        print(json.dumps({"error": type(exc).__name__, "detail": str(exc)[:240]}))
        sys.exit(2)
