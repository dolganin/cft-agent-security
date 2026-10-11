"""Operator-only OpenCode experiment launcher; not an agent execution capability."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from dotenv import dotenv_values

ROOT = Path(__file__).resolve().parents[1]
MODEL = "qwen3.8-flash-next"
VERSION = "1.19.0"
ASSIGNMENT = ROOT / "docs/k01-k02-qwen-assignment.md"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--task", choices=("k01-k02", "r01"), default="k01-k02")
    args = parser.parse_args()
    assignment = ASSIGNMENT if args.task == "k01-k02" else ROOT / "docs/r01-qwen-acceptance-assignment.md"
    key = dotenv_values(ROOT / ".env").get("NSU_OPENWEBUI_KEY")
    if not key:
        print("Worker not started: project credential missing")
        return 2
    started = time.monotonic()
    request = urllib.request.Request(
        "https://deepcode.ci.nsu.ru/api/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        data=json.dumps({
            "model": MODEL,
            "messages": [{"role": "user", "content": "Reply only READY"}],
            "max_tokens": 32,
            "stream": False,
        }).encode(),
    )
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            result = json.load(response)
            ready = "READY" in str(result.get("choices", [{}])[0].get("message", {}).get("content", ""))
            status = response.status
    except (urllib.error.URLError, ValueError, IndexError):
        print("Worker not started: neutral provider probe failed; no fallback used")
        return 2
    if not ready:
        print("Worker not started: neutral provider probe did not return READY")
        return 2
    print(f"NSU model probe: HTTP {status}, READY, {time.monotonic() - started:.2f}s", flush=True)
    output = ROOT / "artifacts" / ("qwen-" + args.task + "-" + datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid4().hex[:8])
    output.mkdir(parents=True, exist_ok=False)
    allowed_files = [
        "evaluation/baseline_diagnostics.py", "app/baseline_diagnostics.py",
        "app/stage1_e2e.py", "schemas/target.py", "tests/test_baseline_diagnostics.py",
        "tests/test_k01_environment.py", "tests/test_stage1_e2e.py", "tests/test_target_profile.py",
        "docs/k02-baseline-diagnostics.md", "docs/k01-environment-passport.md",
        "docs/k01-k02-qwen-result.md", "docs/demo/README.md",
    ]
    if args.task == "r01":
        allowed_files = ["docs/r01-verification-specifications.md", "contracts/examples/r01/*",
                         "tests/test_r01_specifications.py", "docs/r01-acceptance-result.md"]
    edit_permissions = {"*": "deny"}
    for name in allowed_files:
        edit_permissions[name] = "allow"
        edit_permissions[str(ROOT / name)] = "allow"
    configuration = {
        "$schema": "https://opencode.ai/config.json",
        "enabled_providers": ["nsu"], "share": "disabled", "autoupdate": False,
        "model": "nsu/" + MODEL,
        "compaction": {"auto": True, "prune": True, "reserved": 16384},
        "provider": {"nsu": {
            "npm": "@ai-sdk/openai-compatible",
            "options": {"baseURL": "https://deepcode.ci.nsu.ru/api", "apiKey": "{env:CFT_QWEN_WORKER_KEY}"},
            "models": {MODEL: {"name": "NSU Qwen Flash Next", "tool_call": True,
                "limit": {"context": 262144, "output": 8192},
                "variants": {"xhigh": {"reasoningEffort": "xhigh"}}}},
        }},
        "permission": {
            "*": "deny", "glob": "allow", "grep": "allow", "list": "allow",
            "read": {"*": "allow", "*.env": "deny", "*.env.*": "deny", "*/.env": "deny",
                     "*opencode.json*": "deny", "*auth.json": "deny"},
            "edit": edit_permissions,
            "bash": {
                "*": "deny", "pwd": "allow", "ls *": "allow", "rg *": "allow",
                "git status*": "allow", "git diff*": "allow", "git rev-parse*": "allow",
                "git ls-files*": "allow", "git log*": "allow", "git -C * status*": "allow",
                "git -C * rev-parse*": "allow", "git -C * ls-files*": "allow",
                "docker info*": "allow", "docker version*": "allow", "docker ps*": "allow",
                "docker image inspect*": "allow", "docker network ls*": "allow",
                "PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m *": "allow",
                "env -u NSU_OPENWEBUI_KEY PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m *": "allow",
                ".venv/bin/python -m pytest*": "allow", ".venv/bin/python -m ruff*": "allow",
                "git *push*": "deny", "git *commit*": "deny", "git *reset*": "deny",
                "*prune*": "deny", "*rm -rf*": "deny", "*printenv*": "deny",
                "*cat .env*": "deny", "*cat */.env*": "deny",
            },
            "external_directory": "deny", "task": "deny", "webfetch": "deny",
        },
    }
    env = dict(os.environ)
    env.pop("NSU_OPENWEBUI_KEY", None)
    env.update({"CFT_QWEN_WORKER_KEY": key, "OPENCODE_CONFIG_CONTENT": json.dumps(configuration),
                "OPENCODE_DISABLE_AUTOUPDATE": "true", "OPENCODE_DISABLE_DEFAULT_PLUGINS": "true",
                "PYTHONDONTWRITEBYTECODE": "1"})
    prompt = (
        f"Implement the assignment in {assignment.relative_to(ROOT)} now. Read it and AGENTS.md completely first. "
        "You are a coding worker, not a security-policy workaround. Preserve all boundaries. "
        "Use only allowed file edits; do not commit/push or edit the other worker's scope. Use apply_patch if available. "
        "Do not read or print .env, credentials or environment variables. "
        "Inspect the specified files and implement only the assigned work; keep file reads small and focused. "
        "If an operation is denied, report the needed operation rather than retrying via shell/python to bypass it. "
        "Write the assigned result document with actual tests and honest blockers."
    )
    argv = ["npm", "exec", "--yes", "--package=opencode-ai@" + VERSION, "--", "opencode",
            "run", "--pure", "--model", "nsu/" + MODEL, "--variant", "xhigh",
            "--format", "json", "--title", args.task + " NSU Qwen acceptance", prompt]
    (output / "launch.json").write_text(json.dumps({
        "model": MODEL, "requested_reasoning": "xhigh", "opencode_version": VERSION,
        "branch": subprocess.check_output(["git", "branch", "--show-current"], cwd=ROOT, text=True).strip(),
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        "assignment": str(assignment.relative_to(ROOT)), "probe_http_status": status,
        "started_at": datetime.now(UTC).isoformat(),
    }, indent=2) + "\n", encoding="utf-8")
    print(f"Worker events: {output / 'events.jsonl'}", flush=True)
    process = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True)
    assert process.stdout is not None
    with (output / "events.jsonl").open("w", encoding="utf-8") as log:
        for line in process.stdout:
            safe = line.replace(key, "[REDACTED]")
            log.write(safe)
            log.flush()
            # Preserve full events on disk, keep terminal output compact.
            try:
                event = json.loads(safe)
                part = event.get("part", {})
                print(json.dumps({"type": event.get("type"), "sessionID": event.get("sessionID"),
                                  "tool": part.get("tool"), "text": str(part.get("text", ""))[:500]}), flush=True)
            except json.JSONDecodeError:
                print(safe[:500], end="", flush=True)
    code = process.wait()
    print(f"OpenCode exit={code}; elapsed={time.monotonic() - started:.1f}s", flush=True)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
