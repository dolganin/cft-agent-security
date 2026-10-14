"""R03 public HTTP smoke against immutable Juice Shop; no LLM or vulnerability probes."""
from __future__ import annotations

import argparse
import json
import subprocess
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from app.research_acceptance import docker
from app.research_plan import execute_plan
from schemas.target import TargetProfile

COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"
IMAGE = "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"


def smoke(checkout: Path, worker_image: str, output: Path):
    if output.exists():
        raise FileExistsError("Choose a fresh smoke output directory")
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=checkout, text=True).strip()
    if commit != COMMIT or subprocess.check_output(["git", "diff", "HEAD", "--name-only"], cwd=checkout, text=True).strip():
        raise ValueError("Juice smoke requires the unchanged pinned target checkout")
    prefix = "r03-juice-" + uuid4().hex[:12]
    network, container = prefix + "-net", prefix + "-target"
    docker(["network", "create", "--internal", "--label", "cft.research.smoke=" + prefix, network])
    try:
        docker(["run", "--detach", "--pull=never", "--name", container,
                               "--network", network, "--network-alias", "juice", "--cap-drop=ALL",
                               "--security-opt=no-new-privileges:true", "--memory=768m", "--cpus=2",
                               "--pids-limit=128", "--log-driver=none", IMAGE])
        for _ in range(60):
            result = subprocess.run(["docker", "exec", container, "/nodejs/bin/node", "-e",
                                     "require('http').get('http://127.0.0.1:3000/',r=>{r.resume();process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"],
                                    capture_output=True, timeout=5, check=False)
            if not result.returncode:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Juice readiness failed")
        image_id = json.loads(docker(["inspect", container]))[0]["Image"]
        profile = TargetProfile(id="juice-research-smoke", name="Pinned Juice Shop public transport smoke",
                                repository_path=checkout, environment="sandbox", services={"juice": {"internal_port": 3000}})
        configuration = {"worker_image": worker_image,
                         "source_files": ["server.ts", "routes/search.ts"],
                         "runtime_service_map": {"session_id": prefix, "network_name": network,
                            "services": {"juice": {"name": "juice", "address": "http://juice:3000", "ready": True,
                                                    "readiness_source": "http_probe"}}},
                         "http_grants": {"juice": {"read_prefixes": ["/rest/products/search"]}}}
        actions = [
            {"tool": "read_source", "parameters": {"path": "routes/search.ts", "line_start": 1, "line_end": 60},
             "purpose": "Inspect a real pinned route", "expected_evidence": "Source window and hashes"},
            {"tool": "target_http", "service": "juice", "endpoint": "/rest/products/search?q=apple",
             "parameters": {"path": "/rest/products/search?q=apple"},
             "purpose": "Ordinary public product search", "expected_evidence": "Recorded HTTP 200 JSON response"},
        ]
        records = execute_plan(profile=profile, configuration=configuration, actions=actions, output=output)
        observed = json.loads(records[-1]["execution"]["stdout"])["observation"]
        passed = observed["status_code"] == 200 and isinstance(json.loads(observed["body"])["data"], list)
        result = {"passed": passed, "target_commit": commit, "target_image": IMAGE,
                  "runtime_image_id": image_id, "operator_source_image_binding_only": True,
                  "status_code": observed["status_code"], "llm_calls": 0, "benchmark_run": False}
    finally:
        docker(["rm", "--force", container])
        docker(["network", "rm", network])
    result["cleanup_verified"] = True
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    seal = {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in output.rglob("*") if p.is_file()}
    (output / "seal.json").write_text(json.dumps(seal, indent=2) + "\n")
    if not passed:
        raise AssertionError("Juice public transport smoke failed")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", type=Path, required=True)
    parser.add_argument("--worker-image", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(smoke(args.checkout.resolve(), args.worker_image, args.output.resolve()), indent=2))


if __name__ == "__main__":
    main()
