"""R01 reproducible static shortlist from pinned upstream source checkouts."""
from __future__ import annotations

import argparse
import json
import subprocess
from hashlib import sha256
from pathlib import Path

CANDIDATES = {
    "strix": {"repository": "https://github.com/usestrix/strix", "commit": "87f2d783d6595d0aa557809e02c67d94e52bda05",
              "license": "Apache-2.0", "files": ["LICENSE", "pyproject.toml", "uv.lock", "strix/runtime/docker_client.py", "strix/runtime/session_manager.py", "strix/agents/factory.py"],
              "decision": "component/design reference; full runtime fails current isolation acceptance",
              "observations": ["Docker adapter adds NET_ADMIN/NET_RAW and host-gateway", "Source bind mounts default to writable unless caller overrides", "Current core depends on openai-agents, not a drop-in LangGraph node"]},
    "software-agent-sdk": {"repository": "https://github.com/OpenHands/software-agent-sdk", "commit": "95cb37b7f04ff281e92bfb3c3fc66573db2df38a",
                           "license": "MIT", "files": ["LICENSE", "pyproject.toml", "uv.lock", "openhands-sdk/pyproject.toml", "openhands-tools/pyproject.toml", "openhands-sdk/openhands/sdk/agent/agent.py", "openhands-sdk/openhands/sdk/workspace/base.py", "openhands-sdk/openhands/sdk/llm/llm.py"],
                           "decision": "shortlist for R04/R07 custom-tool harness adapter",
                           "observations": ["Typed tools dispatch through _execute_action_event", "Confirmation policy/security analyzer exist; deterministic CFT Validator must be installed as a custom tool boundary", "Custom model base_url is configurable; actual NSU compatibility remains a runtime check", "SDK requires Python >=3.12 and pydantic >=2.13.5; isolate its dependencies from the current >=3.11 application"]},
    "PentestGPT": {"repository": "https://github.com/GreyDGL/PentestGPT", "commit": "e8b1bb77d1ac00329675cec3b060aba971ec1ac8",
                   "license": "MIT", "files": ["LICENSE.md", "docs/architecture.md", "pentestgpt_agent/pyproject.toml"],
                   "decision": "state/coverage architecture reference",
                   "observations": ["Maintained two-role loop uses deterministic leases/evidence/state", "FULL_ACCESS relies on deployment isolation", "Current provider wrappers target Claude Code/Codex; NSU support is not established"]},
}


def audit(checkouts: Path, output: Path):
    if output.exists():
        raise FileExistsError("Choose a fresh R01 audit directory")
    result = {"schema": "research-harness-audit.v1", "method": "static source audit; no upstream code execution",
              "candidates": {}, "shortlist": ["current-python-langgraph", "OpenHands custom tools adapter"],
              "implementation_choice": "backend-neutral CFT research tools behind existing Validator/Executor",
              "quality_winner": None, "quality_comparison_stage": "R07",
              "upstream_code_copied": False, "new_runtime_dependencies": [],
              "license_scope": "root licenses and direct dependency manifests checked; transitive NOTICE audit required before code adoption"}
    for name, specification in CANDIDATES.items():
        directory = checkouts / ("cft-r01-" + name + "-20261015")
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=directory, text=True).strip()
        if commit != specification["commit"]:
            raise ValueError("Upstream commit mismatch: " + name)
        evidence = {}
        for file in specification["files"]:
            evidence[file] = {"sha256": sha256((directory / file).read_bytes()).hexdigest(),
                              "url": specification["repository"] + "/blob/" + commit + "/" + file}
        result["candidates"][name] = {**specification, "source_evidence": evidence}
    strix_source = (checkouts / "cft-r01-strix-20261015/strix/runtime/docker_client.py").read_text()
    if any(value not in strix_source for value in ["NET_ADMIN", "NET_RAW", "host-gateway"]):
        raise ValueError("Strix isolation observation no longer matches pinned source")
    output.mkdir(parents=True)
    (output / "harness-audit.json").write_text(json.dumps(result, indent=2) + "\n")
    (output / "seal.json").write_text(json.dumps({"harness-audit.json": sha256((output / "harness-audit.json").read_bytes()).hexdigest()}, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkouts", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(audit(args.checkouts.resolve(), args.output.resolve()), indent=2))


if __name__ == "__main__":
    main()
