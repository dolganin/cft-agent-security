"""R07 deterministic provider-fault injection through real LangGraph and Docker."""
import json
import tempfile
from hashlib import sha256
from pathlib import Path

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.research_campaign import campaign
from schemas.finding import Finding
from schemas.research_agent import ResearchChoice, ResearchLimits, ResearchTurn
from schemas.research_campaign import CampaignLimits
from schemas.target import TargetProfile


def run(output, image):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("Choose fresh recovery acceptance output")
    output.mkdir(parents=True)
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:synthetic-fault-injection"),
        credentials={"NSU_OPENWEBUI_KEY":"synthetic"}, max_output_tokens=4096)
    calls = []

    def response(_route, _system, prompt):
        calls.append(len(calls)+1)
        if len(calls) <= 2:
            return '{"summary":"deliberately missing required fields"}'
        if len(calls) == 3:
            return ResearchTurn(summary="Read source after the previous question failed",
                hypothesis="Inspect an owned fixture", action=ResearchChoice(tool="read_source",
                    parameters={"path":"app.ts"}, purpose="Read source", expected_evidence="Numbered source")).model_dump_json()
        payload = json.loads(prompt.split("Input data:\n", 1)[1])
        return ResearchTurn(summary="Useful observation retained", hypothesis="No verdict claimed", finish=True,
            observation_refs=[payload["observations"][-1]["action_id"]]).model_dump_json()

    client._request_route = response
    with tempfile.TemporaryDirectory(prefix="cft-r07-recovery-") as temporary:
        source = Path(temporary)
        (source / "app.ts").write_text("const alpha = 1;\nconst beta = 2;\n")
        profile = TargetProfile(id="recovery-fixture", environment="sandbox", repository_path=source)
        findings = [Finding(id=f"owned-{i}", source="operator", rule_id=f"fixture-{i}", title=f"Question {i}",
            description="Synthetic fault-injection acceptance, not a vulnerability", file="app.ts", line_start=i+1)
            for i in range(2)]
        summary = campaign(profile=profile, configuration={"worker_image":image, "source_files":["app.ts"]},
            client=client, output=output / "campaign", sast=findings,
            limits=CampaignLimits(max_questions=2, max_model_calls=8),
            research_limits=ResearchLimits(max_steps=2, max_model_calls=8, max_schema_corrections=1))
    questions = json.loads((output / "campaign/questions.json").read_text())
    reports = json.loads((output / "campaign/reports.json").read_text())
    checks = {"failed-question-retained":sum(q["status"] == "failed" for q in questions) == 1,
        "next-question-completed":sum(q["status"] == "researched" for q in questions) == 1,
        "both-reports-retained":len(reports) == 2,
        "degradation-explicit":summary["degraded"] and len(summary["model_failures"]) == 1,
        "correction-counted":summary["model_calls"] == 4 == len(calls),
        "next-question-executed":summary["actions"] == 1,
        "cleanup":summary["cleanup_verified"],
        "no-fabricated-verdict":all(r["report"]["status"] == "inconclusive" for r in reports)}
    result = {"checks":checks, "passed":all(checks.values()), "live_llm":False,
              "benchmark_measurement":False, "provider":"synthetic response fault injection"}
    (output / "acceptance.json").write_text(json.dumps(result, indent=2)+"\n")
    seal = {p.relative_to(output).as_posix():sha256(p.read_bytes()).hexdigest() for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "seal.json").write_text(json.dumps(seal, indent=2)+"\n")
    if not result["passed"]:
        raise RuntimeError("R07 recovery acceptance failed; artifacts retained")
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.image), indent=2))
