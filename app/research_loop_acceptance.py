"""Real Docker R04 acceptance with a SCRIPTED reasoning test double, not an LLM run."""
import argparse
import json
import tempfile
from hashlib import sha256
from pathlib import Path

from app.research_run import ROOT, run_research
from schemas.finding import Finding
from schemas.research_agent import ResearchChoice, ResearchLimits, ResearchTurn
from schemas.target import TargetProfile


class AdaptiveClient:
    max_output_tokens = 4096

    def complete_model(self, **kwargs):
        observations = kwargs["user_payload"]["observations"]
        refs = [x["action_id"] for x in observations]
        last = observations[-1] if observations else None
        if last is None:
            tool, parameters = "read_source", {"path": "app.ts"}
        elif last["tool"] == "read_source":
            assert "acceptance-marker" in last["observation"]["content"]
            tool, parameters = "write_workspace_file", {"path": "experiment.py", "content": "raise ValueError('trial failed')\n"}
        elif last["tool"] == "write_workspace_file":
            tool, parameters = "sandbox_command", {"argv": ["python3", "/workspace/experiment.py"],
                                                     "script_sha256": last["observation"]["sha256"]}
        elif last["tool"] == "sandbox_command":
            if "trial failed" in last["observation"].get("stderr", ""):
                tool, parameters = "write_workspace_file", {"path": "experiment.py",
                    "content": "from pathlib import Path\ns = Path('/target/app.ts').read_text()\nPath('/workspace/result.txt').write_text('marker present' if 'acceptance-marker' in s else 'absent')\n"}
            else:
                assert last["observation"]["exit_code"] == 0
                tool, parameters = "read_workspace_file", {"path": "result.txt"}
        else:
            assert last["observation"]["content"] == "marker present"
            return ResearchTurn(summary="Synthetic research complete; independent verification remains necessary",
                hypothesis="Marker was observed, no security claim", finish=True, observation_refs=refs)
        return ResearchTurn(summary="Observe and revise a bounded experiment", hypothesis="Marker is present",
            observation_refs=refs, action=ResearchChoice(tool=tool, parameters=parameters,
            purpose="Bounded synthetic experiment", expected_evidence="Persisted observation"))


class RepeatingClient:
    max_output_tokens = 4096

    def complete_model(self, **kwargs):
        return ResearchTurn(summary="Repeated operation", hypothesis="Marker exists",
            action=ResearchChoice(tool="read_source", parameters={"path": "app.ts"},
                                 purpose="Read the source", expected_evidence="Numbered source"))


class InvalidRefClient:
    max_output_tokens = 4096

    def complete_model(self, **kwargs):
        return ResearchTurn(summary="Unsupported conclusion", hypothesis="Unknown", finish=True,
                            observation_refs=["never-executed-action"])


def run(output, image):
    output = Path(output).resolve()
    if output.exists():
        raise FileExistsError("Choose a fresh directory")
    output.mkdir(parents=True)
    checks = {}
    with tempfile.TemporaryDirectory(prefix="cft-r04-fixture-") as directory:
        source = Path(directory)
        path = source / "app.ts"
        path.write_text("export const marker = 'acceptance-marker';\n")
        initial = sha256(path.read_bytes()).hexdigest()
        # Existing specialized verification routes MUST NOT cause research early stop.
        profile = TargetProfile.from_yaml(ROOT / "targets/juice-verification.yaml",
                                          repository_path_override=source)
        finding = Finding(id="r04-synthetic", source="operator", rule_id="research-marker",
            title="Read a marker", description="Synthetic acceptance, not vulnerability benchmark",
            file="app.ts", line_start=1)
        configuration = {"worker_image": image, "source_files": ["app.ts"]}
        scenarios = [("adaptive", AdaptiveClient(), ResearchLimits(), "research_complete", 6),
                     ("repeat", RepeatingClient(), ResearchLimits(), "repeated_action", 1),
                     ("call-budget", AdaptiveClient(), ResearchLimits(max_model_calls=2), "research_budget_exhausted", 2),
                     ("step-budget", AdaptiveClient(), ResearchLimits(max_steps=2), "step_budget_exhausted", 2),
                     ("invalid-ref", InvalidRefClient(), ResearchLimits(), "model_failure", 0)]
        for name, client, limits, expected, actions in scenarios:
            state, summary = run_research(profile=profile, configuration=configuration,
                finding=finding, output=output / name, client=client, limits=limits)
            checks[name] = (summary["stop_reason"] == expected and summary["actions"] == actions
                           and summary["cleanup_verified"] and summary["status"] == "inconclusive"
                           and all(x.verdict == "inconclusive" for x in state.get("evidence", [])))
            if name == "adaptive":
                ledger = state["research_progress"].ledger
                checks["failure-followed-by-new-experiment"] = len(ledger) >= 4 and ledger[2].category == "failed_experiment" and ledger[3].tool == "write_workspace_file"
                checks["script-output-read-back"] = bool(ledger) and ledger[-1].observation.get("content") == "marker present"
                checks["all-actions-approved-and-audited"] = all(x.validation.approved and x.execution for x in state["action_history"])
                checks["one-model-call-per-turn"] = summary["model_calls"] == 7
                checks["expected-script-failure-not-pipeline-error"] = not state.get("workflow_errors")
        checks["original-source-unchanged"] = sha256(path.read_bytes()).hexdigest() == initial
    summary = {"schema_version": "cft.research.r04.acceptance.v1", "reasoning": "scripted test double",
               "real_docker_execution": True, "live_llm": False, "benchmark_measurement": False,
               "checks": checks, "passed": all(checks.values())}
    (output / "acceptance.json").write_text(json.dumps(summary, indent=2) + "\n")
    seal = {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob("*")) if p.is_file()}
    (output / "seal.json").write_text(json.dumps(seal, indent=2) + "\n")
    if not summary["passed"]:
        raise RuntimeError("R04 acceptance failed; persisted artifacts retained")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output, args.image), indent=2))


if __name__ == "__main__":
    main()
