"""Real Docker browser roundtrip, controls and graph integration. No live LLM/benchmark."""
import json
import tempfile
import time
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from app.research_acceptance import docker
from app.research_plan import execute_plan
from app.research_run import run_research
from schemas.finding import Finding
from schemas.research_agent import ResearchChoice, ResearchLimits, ResearchTurn
from schemas.target import TargetProfile

ROOT = Path(__file__).resolve().parents[1]
MARKER = "owned-dom-effect-r08"


def observe(entry):
    execution = entry["execution"]
    if execution is None or execution["exit_code"] != 0:
        raise RuntimeError("Browser action failed; inspect persisted execution/audit")
    return json.loads(execution["stdout"])["observation"]


def item(path, *, interact=True, screenshot=False):
    steps = [{"operation":"fill", "selector":"#probe", "value":f'<img src="x" onerror="alert(\'{MARKER}\')">'},
             {"operation":"click", "selector":"#apply"}, {"operation":"snapshot"}] if interact else []
    return {"tool":"browser_interact", "parameters":{"path":path, "steps":steps, "screenshot":screenshot},
            "service":"fixture", "endpoint":path, "purpose":"Observe owned test UI",
            "expected_evidence":"DOM and dialog observations, not a model verdict"}


class BrowserClient:
    max_output_tokens = 4096

    def __init__(self, recoverable_error=False):
        self.recoverable_error = recoverable_error

    def complete_model(self, **kwargs):
        ledger = kwargs["user_payload"]["observations"]
        if not ledger or (self.recoverable_error and len(ledger) == 1):
            choice = item("/ui", screenshot=True)
            if self.recoverable_error and not ledger:
                choice["parameters"]["steps"][0]["selector"] = "#not-an-element"
            return ResearchTurn(summary="Inspect the owned UI", hypothesis="Observe DOM behavior",
                                action=ResearchChoice(**choice))
        return ResearchTurn(summary="Browser behavior observed, independent review remains required",
            hypothesis="No universal security verdict", finish=True,
            observation_refs=[ledger[-1]["action_id"]])


def run(output, image, browser_image):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("Choose fresh browser acceptance output")
    output.mkdir(parents=True)
    prefix = "cft-r08-" + uuid4().hex[:12]
    network, target = prefix + "-net", prefix + "-target"
    checks = {}
    fixture = ROOT / "executor/research_browser_fixture.py"
    docker(["network", "create", "--internal", network])
    try:
        cid = docker(["run", "--detach", "--pull=never", "--name", target, "--network", network,
            "--network-alias", "fixture", "--read-only", "--user=65534:65534", "--cap-drop=ALL",
            "--security-opt=no-new-privileges:true", "--memory=96m", "--pids-limit=16", "--log-driver=none",
            "--mount", f"type=bind,src={fixture},dst=/app/fixture.py,readonly",
            image, "python3", "/app/fixture.py"])
        time.sleep(.5)
        info = json.loads(docker(["inspect", cid]))[0]
        with tempfile.TemporaryDirectory(prefix="cft-r08-source-") as temporary:
            source = Path(temporary)
            (source / "app.ts").write_text("// Synthetic owned browser acceptance\n")
            profile = TargetProfile(id="r08-fixture", environment="sandbox", repository_path=source,
                                    services={"fixture":{"internal_port":8080}})
            config = {"worker_image":image, "browser_image":browser_image, "action_timeout":30,
                "source_files":["app.ts"], "network_name":network, "services":{"fixture":{
                    "container_id":cid, "image_id":info["Image"], "address":"http://fixture:8080",
                    "read_prefixes":["/ui", "/ui-safe", "/assets", "/counts", "/redirect-local", "/redirect-external"]}}}
            actions = []
            for ordinal, proposed in enumerate([item("/ui", screenshot=True), item("/ui-safe"),
                    item("/redirect-local", interact=False), item("/redirect-external", interact=False)]):
                entry = execute_plan(profile=profile, configuration=config, output=output / f"operator-plan-{ordinal}",
                                     actions=[proposed])[0]
                actions.append(entry)
                if ordinal < 2:
                    observe(entry)
            vulnerable, safe = [observe(x) for x in actions[:2]]
            checks["positive-dom-dialog"] = any(d["message"] == MARKER for d in vulnerable["dialogs"])
            checks["safe-dom-control"] = not safe["dialogs"] and MARKER in safe["snapshots"][-1]["text"]
            checks["redirect-requires-explicit-navigation"] = actions[2]["execution"]["exit_code"] != 0
            checks["external-redirect-not-success"] = actions[-1]["execution"]["exit_code"] != 0
            checks["forbidden-subrequests-denied"] = any(not row["allowed"] for row in vulnerable["network_ledger"])
            screenshot = Path(vulnerable["screenshot_ref"])
            checks["screenshot-digest"] = sha256(screenshot.read_bytes()).hexdigest() == vulnerable["screenshot_sha256"]
            checks["anonymous-networkless-cleanup"] = all(x["network_mode"] == "none" and x["cleanup_verified"]
                and not x["storage_persisted"] for x in (vulnerable, safe))
            counts = docker(["exec", cid, "python3", "-c",
                "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8080/counts').read().decode())"])
            checks["private-endpoint-never-reached"] = "/private" not in json.loads(counts)
            state, summary = run_research(profile=profile, configuration=config,
                finding=Finding(id="browser-question", source="operator", rule_id="dom-observation",
                    title="Observe an owned UI", description="Functional acceptance", file="app.ts", line_start=1),
                output=output / "graph", client=BrowserClient(), limits=ResearchLimits(max_steps=2))
            progress = state["research_progress"]
            checks["canonical-graph-browser-ledger"] = len(progress.ledger) == 1 and progress.ledger[0].tool == "browser_interact"
            checks["no-automatic-confirmation"] = state["final_report"].status == "inconclusive"
            checks["graph-cleanup"] = summary["cleanup_verified"]
            recovered, recovery_summary = run_research(profile=profile, configuration=config,
                finding=Finding(id="browser-recovery", source="operator", rule_id="dom-observation",
                    title="Recover from a missing selector", description="Functional acceptance", file="app.ts", line_start=1),
                output=output / "graph-recovery", client=BrowserClient(recoverable_error=True),
                limits=ResearchLimits(max_steps=3))
            recovery = recovered["research_progress"].ledger
            checks["invalid-selector-retained"] = len(recovery) == 2 and recovery[0].category == "failed_experiment"
            checks["next-browser-experiment-completes"] = len(recovery) == 2 and recovery[1].category == "observation"
            checks["browser-recovery-cleanup"] = recovery_summary["cleanup_verified"] and not recovered.get("workflow_errors")
        (output / "counts.json").write_text(counts)
        (output / "provenance.json").write_text(json.dumps({"worker_image":image, "browser_image":browser_image,
            "target_image":info["Image"], "target_container":cid, "fixture_sha256":sha256(fixture.read_bytes()).hexdigest(),
            "benchmark_measurement":False, "reasoning":"synthetic graph client"}, indent=2))
    finally:
        docker(["rm", "--force", target])
        docker(["network", "rm", network])
    result = {"checks":checks, "passed":all(checks.values()), "benchmark_measurement":False,
              "live_llm":False, "independent_vulnerability_verdict":"not_claimed"}
    (output / "acceptance.json").write_text(json.dumps(result, indent=2)+"\n")
    seal = {p.relative_to(output).as_posix():sha256(p.read_bytes()).hexdigest() for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "seal.json").write_text(json.dumps(seal, indent=2)+"\n")
    if not result["passed"]:
        raise RuntimeError("Browser acceptance failed; artifacts retained")
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--browser-image", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.image, args.browser_image), indent=2))
