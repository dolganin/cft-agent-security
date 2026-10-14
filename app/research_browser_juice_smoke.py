"""Pinned Juice Shop UI smoke, not vulnerability discovery or R09 metrics."""
import json
import subprocess
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from app.research_acceptance import docker
from app.research_browser_acceptance import observe
from app.research_juice_smoke import COMMIT, IMAGE
from app.research_plan import execute_plan
from sast.profiles import validate_target_snapshot
from schemas.target import TargetProfile


def run(checkout, image, browser_image, output):
    checkout, output = Path(checkout).resolve(), Path(output).resolve()
    if output.exists():
        raise FileExistsError("Choose fresh smoke output")
    before = validate_target_snapshot(checkout, COMMIT)
    output.mkdir(parents=True)
    prefix = "r08-juice-"+uuid4().hex[:12]
    network, target = prefix+"-net", prefix+"-target"
    docker(["network", "create", "--internal", network])
    try:
        cid = docker(["run", "--detach", "--pull=never", "--name", target, "--network", network,
            "--network-alias", "juice", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--memory=768m", "--cpus=2", "--pids-limit=128", "--log-driver=none", IMAGE])
        for _ in range(60):
            ready = subprocess.run(["docker", "exec", target, "/nodejs/bin/node", "-e",
                "require('http').get('http://127.0.0.1:3000/',r=>{r.resume();process.exit(r.statusCode===200?0:1)}).on('error',()=>process.exit(1))"],
                capture_output=True, timeout=5, check=False)
            if ready.returncode == 0:
                break
            time.sleep(.5)
        else:
            raise RuntimeError("Juice readiness failed")
        profile = TargetProfile(id="juice-browser-smoke", environment="sandbox", repository_path=checkout,
                                services={"juice":{"internal_port":3000}})
        info = json.loads(docker(["inspect", cid]))[0]
        config = {"worker_image":image, "browser_image":browser_image, "source_files":["app.ts"],
            "network_name":network, "action_timeout":30, "services":{"juice":{
                "container_id":cid, "image_id":info["Image"], "address":"http://juice:3000",
                "read_prefixes":["/"], "denied_prefixes":["/socket.io", "/rest/challenges", "/score-board"]}}}
        entry = execute_plan(profile=profile, configuration=config, output=output / "plan", actions=[{
            "tool":"browser_interact", "parameters":{"path":"/", "fragment":"/search", "screenshot":True},
            "service":"juice", "endpoint":"/", "purpose":"Observe pinned local Juice Shop UI",
            "expected_evidence":"UI DOM snapshot and screenshot; no vulnerability verdict"}])[0]
        observation = observe(entry)
        text = "\n".join(s["text"] for s in observation["snapshots"])
        checks = {"ui-rendered":"Juice Shop" in text, "screenshot":bool(observation.get("screenshot_ref")),
                  "browser-isolation":observation["isolation_validated"], "cleanup":observation["cleanup_verified"]}
    finally:
        docker(["rm", "--force", target])
        docker(["network", "rm", network])
    checks["source-unchanged"] = before == validate_target_snapshot(checkout, COMMIT)
    result = {"checks":checks, "passed":all(checks.values()), "target":before,
        "target_image":IMAGE, "research_image":image, "browser_image":browser_image,
        "benchmark_measurement":False, "live_llm":False}
    (output / "acceptance.json").write_text(json.dumps(result, indent=2)+"\n")
    seal = {p.relative_to(output).as_posix():sha256(p.read_bytes()).hexdigest() for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "seal.json").write_text(json.dumps(seal, indent=2)+"\n")
    if not result["passed"]:
        raise RuntimeError("Juice UI smoke incomplete; artifacts retained")
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--checkout", required=True, type=Path)
    parser.add_argument("--image", required=True)
    parser.add_argument("--browser-image", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(run(args.checkout, args.image, args.browser_image, args.output), indent=2))
