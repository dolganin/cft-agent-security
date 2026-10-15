"""R04 graph regression, budgets, provenance and opt-in Docker adaptive loop."""
import json
import os
from hashlib import sha256
from types import SimpleNamespace

import pytest

from agent.nodes import load_context
from agent.research import ResearchAgentModel, ResearchBudgetExhausted, research_context
from app.research_run import run_research
from executor.executor import SafeExecutor
from executor.sandbox_audit import calculate_sha256_digest
from schemas.execution import ExecutionResult
from schemas.finding import Finding
from schemas.research import ResearchFile, ResearchScope
from schemas.research_agent import ResearchChoice, ResearchLimits, ResearchObservation, ResearchTurn
from schemas.target import TargetProfile
from security.error_redaction import redact_observation
from tools.research import research_proposal


def scope():
    return ResearchScope(target_id="r04-test", session_id="research-" + "a" * 32,
                         worker_image="sha256:" + "b" * 64, worker_sha256="c" * 64,
                         source_files={"app.ts": ResearchFile(original_sha256="d" * 64,
                                                               visible_sha256="e" * 64)})


def finding():
    return Finding(id="r04-finding", source="operator", rule_id="research-marker",
                   title="Inspect a source marker", description="Synthetic graph acceptance, not a vulnerability",
                   file="app.ts", line_start=1)


class Client:
    max_output_tokens = 4096

    def __init__(self, turn):
        self.turn, self.calls = turn, 0

    def complete_model(self, **kwargs):
        self.calls += 1
        return self.turn


def finish(**kwargs):
    return ResearchTurn(summary="Research is complete, independent review remains necessary",
                        hypothesis="No security verdict", finish=True, **kwargs)


def test_one_model_call_shared_by_reasoning_nodes():
    client = Client(ResearchTurn(summary="Read source first", hypothesis="Inspect source",
        action=ResearchChoice(tool="read_source", parameters={"path": "app.ts"},
                              purpose="Inspect source", expected_evidence="Numbered source")))
    adapter = ResearchAgentModel(client=client, scope=scope(), validator=None)
    state = {"finding": finding(), "iteration_count": 0}
    analysis = adapter.analyse(state)
    hypothesis = adapter.form_hypothesis(state, analysis)
    plan = adapter.build_plan(state, analysis, hypothesis)
    assert client.calls == 1
    assert plan.steps[0].action.research_binding.scope_sha256 == scope().digest
    assert plan.steps[0].action.target == scope().target_id


def test_finding_context_removes_juice_shop_solution_annotations_without_mutating_source():
    original = finding().model_copy(update={
        "title": "Inspect handler // vuln-code-snippet vuln-line hiddenChallenge",
        "description": "Keep this behavior\n"
                      "// vuln-code-snippet hide-start hiddenChallenge\n"
                      "secret solution body\n"
                      "// vuln-code-snippet hide-end hiddenChallenge\n"
                      "Keep this control",
    })
    adapter = ResearchAgentModel(client=Client(finish()), scope=scope(), validator=None,
        surface_context={"source_hint": "// vuln-code-snippet hide-line hiddenCampaignAnswer"})

    payload = adapter.context({"finding": original})

    rendered = json.dumps(payload, ensure_ascii=False)
    assert "hiddenChallenge" not in rendered
    assert "secret solution body" not in rendered
    assert "vuln-code-snippet" not in rendered
    assert "hiddenCampaignAnswer" not in rendered
    assert "Keep this behavior" in rendered and "Keep this control" in rendered
    assert "hiddenChallenge" in original.title and "secret solution body" in original.description


def test_fabricated_observation_refs_rejected():
    adapter = ResearchAgentModel(client=Client(finish(observation_refs=["imaginary"])),
                                 scope=scope(), validator=None)
    with pytest.raises(ValueError, match="never persisted"):
        adapter.analyse({"finding": finding()})


def test_provider_validation_context_checks_observation_provenance():
    raw = finish(observation_refs=["future-action"]).model_dump()
    with pytest.raises(ValueError, match="persisted action IDs"):
        ResearchTurn.model_validate(raw, context={"observation_refs": ["read-1"]})
    raw["observation_refs"] = ["read-1"]
    assert ResearchTurn.model_validate(raw, context={"observation_refs": ["read-1"]}).finish


def test_provider_receives_only_real_observation_ids_for_correction():
    class RecordingClient(Client):
        def complete_model(self, **kwargs):
            assert kwargs["validation_context"] == {"observation_refs": []}
            return super().complete_model(**kwargs)

    adapter = ResearchAgentModel(client=RecordingClient(finish()), scope=scope(), validator=None)
    adapter.analyse({"finding": finding()})
    assert adapter.progress.model_diagnostic is None


def test_provider_repairs_future_refs_without_relaxing_provenance(monkeypatch):
    from agent.llm import ProviderFailoverClient, parse_route_specs

    replies = iter([finish(observation_refs=["future-action"]).model_dump_json(),
                    finish(observation_refs=["read-1"]).model_dump_json()])
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next"),
                                   credentials={"NSU_OPENWEBUI_KEY": "synthetic"})
    monkeypatch.setattr(client, "_request_route", lambda *_args: next(replies))
    result = client.complete_model(output_model=ResearchTurn, system_prompt="test", user_payload={},
        operation="test", schema_retries=1, validation_context={"observation_refs": ["read-1"]})
    assert result.observation_refs == ["read-1"]
    assert len(client.last_attempts) == 2
    assert client.last_schema_errors


def test_dev_acceptance_rejects_invalid_scope_before_output_creation(tmp_path):
    from app.research_dev_acceptance import run

    output = tmp_path / "result"
    with pytest.raises(ValueError, match="one to four"):
        run(tmp_path, "unused", output, max_questions=0)
    assert not output.exists()


def test_structured_redaction_preserves_json_and_failure_reason():
    value = {"observation": {"stderr": "Traceback (most recent call last):\n/private/error\nValueError: trial failed\n",
            "content": "line1\nline2\n", "body": 'Authorization: Bearer secret-value',
            "token": "private-token"}}
    result = redact_observation(value)
    assert result["observation"]["stderr"] == "ValueError: trial failed"
    assert result["observation"]["content"] == "line1\nline2\n"
    assert "secret-value" not in json.dumps(result)
    assert "private-token" not in json.dumps(result)


@pytest.mark.parametrize("limits", [ResearchLimits(max_model_calls=1), ResearchLimits(max_model_io_bytes=4096)])
def test_model_budget_stops_before_additional_request(limits):
    client = Client(finish())
    adapter = ResearchAgentModel(client=client, scope=scope(), validator=None, limits=limits)
    if limits.max_model_calls == 1:
        adapter.analyse({"finding": finding()})
    with pytest.raises(ResearchBudgetExhausted):
        adapter.analyse({"finding": finding()})
    assert client.calls == (1 if limits.max_model_calls == 1 else 0)


def test_scope_cannot_be_enabled_by_state_alone():
    state = {"finding": finding(), "research_scope": scope(),
             "target_profile": TargetProfile(id=scope().target_id, environment="sandbox")}
    with pytest.raises(ValueError, match="live operator"):
        load_context(state)


def test_research_step_budget_and_context_have_no_synthetic_source():
    adapter = ResearchAgentModel(client=Client(finish()), scope=scope(), validator=None,
                                 limits=ResearchLimits(max_steps=20))
    with research_context(adapter):
        result = load_context({"finding": finding(), "research_scope": scope(),
            "target_profile": TargetProfile(id=scope().target_id, environment="sandbox")})
    assert result["max_steps"] == 20
    assert "Synthetic" not in result["code_context"]
    assert result["sandbox_session_id"] == scope().session_id


def test_action_budgets_and_repeat_semantics():
    adapter = ResearchAgentModel(client=Client(finish()), scope=scope(), validator=None,
                                 limits=ResearchLimits(max_write_bytes=1))
    action = research_proposal(scope=scope(), action_id="test-action", tool="write_workspace_file",
                               parameters={"path": "test.py", "content": "print(1)"},
                               purpose="Write experiment", expected_evidence="File digest")
    with pytest.raises(ResearchBudgetExhausted, match="write"):
        adapter.check_action_budget(action)
    action = action.model_copy(update={"tool": "read_workspace_file", "parameters": {"path": "test.py"}})
    adapter.progress.ledger.append(ResearchObservation(action_id=action.id, tool=action.tool,
        fingerprint=adapter.fingerprint(action), workspace_revision=0, evidence_ids=[], artifact_refs=[],
        execution_status="completed", exit_code=0, observation={}, bytes_observed=2, category="observation"))
    assert adapter.repeated(action)
    adapter.progress.workspace_revision += 1
    assert not adapter.repeated(action)


def test_newest_large_observation_is_sampled_not_silently_forgotten():
    adapter = ResearchAgentModel(client=Client(finish()), scope=scope(), validator=None)
    adapter.progress.ledger.append(ResearchObservation(action_id="read-1", tool="read_source",
        fingerprint="first", workspace_revision=0, evidence_ids=["evidence-1"], artifact_refs=[],
        execution_status="completed", exit_code=0, observation={"content": "x" * 60000},
        bytes_observed=60000, category="observation"))
    context = adapter.context({"finding": finding()})
    assert context["observations"][0]["action_id"] == "read-1"
    assert context["observations"][0]["context_truncated"]
    assert len(json.dumps(context).encode()) < adapter.limits.max_context_bytes


def test_repeated_script_cannot_create_its_own_fresh_revision():
    adapter = ResearchAgentModel(client=Client(finish()), scope=scope(), validator=None)
    action = research_proposal(scope=scope(), action_id="script-1", tool="sandbox_command",
        parameters={"argv": ["python3", "/workspace/test.py"], "script_sha256": "f" * 64},
        purpose="Run script", expected_evidence="Output")
    adapter.progress.ledger.append(ResearchObservation(action_id=action.id, tool=action.tool,
        fingerprint=adapter.fingerprint(action), workspace_revision=0, evidence_ids=[], artifact_refs=[],
        execution_status="completed", exit_code=0, observation={}, bytes_observed=2, category="observation"))
    adapter.progress.workspace_revision += 1
    assert adapter.repeated(action)


@pytest.mark.parametrize("mutation", [None, "missing", "duplicate", "payload", "proposal", "session"])
def test_research_readback_requires_independent_matching_audit(mutation):
    action = research_proposal(scope=scope(), action_id="read-1", tool="read_source",
        parameters={"path": "app.ts"}, purpose="Read source", expected_evidence="Numbered source")
    execution = ExecutionResult(run_id="test-run", action_id=action.id, status="completed", exit_code=0,
        evidence_ref="execution-test", audit_ref="audit:test-run")
    payload = {"stdout": '{"observation": {"content": "source"}}'}
    record = {"id": "execution-test", "type": "executor_result", "created_at": "timestamp", **payload}
    audit = {"run_id": execution.run_id, "action_id": action.id,
        "proposal_digest": calculate_sha256_digest(action.model_dump()),
        "evidence_digest": calculate_sha256_digest(payload), "session_id": scope().session_id,
        "evidence_ref": execution.evidence_ref, "runtime_backend": "docker"}
    records = [audit]
    if mutation == "missing":
        records = []
    elif mutation == "duplicate":
        records = [audit, audit]
    elif mutation == "payload":
        record["stdout"] = "changed result"
    elif mutation == "proposal":
        audit["proposal_digest"] = "changed proposal"
    elif mutation == "session":
        audit["session_id"] = "stale-session"
    executor = object.__new__(SafeExecutor)
    executor._evidence_store = SimpleNamespace(get_execution=lambda ref: record)
    executor._audit_log = SimpleNamespace(records=lambda: records)
    if mutation is None:
        assert executor.read_research_execution(action, execution) == record
    else:
        with pytest.raises(ValueError):
            executor.read_research_execution(action, execution)


class AdaptiveClient:
    """Scripted test double reacts to persisted output. NOT live LLM evidence."""
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
            return finish(observation_refs=refs)
        return ResearchTurn(summary="Observe and revise the bounded experiment", hypothesis="Marker is present",
            observation_refs=refs, action=ResearchChoice(tool=tool, parameters=parameters,
            purpose="Bounded synthetic experiment", expected_evidence="Persisted observation"))


@pytest.mark.skipif(not os.getenv("CFT_RESEARCH_IMAGE"), reason="Opt-in immutable research Docker image required")
def test_actual_graph_changes_experiment_after_failure(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    path = source / "app.ts"
    path.write_text("export const marker = 'acceptance-marker';\n")
    before = sha256(path.read_bytes()).hexdigest()
    output = tmp_path / "run"
    state, summary = run_research(profile=TargetProfile(id=scope().target_id, environment="sandbox",
        repository_path=source), configuration={"worker_image": os.environ["CFT_RESEARCH_IMAGE"],
        "source_files": ["app.ts"]}, finding=finding(), output=output, client=AdaptiveClient())
    assert summary["stop_reason"] == "research_complete", json.dumps(summary)
    assert summary["actions"] == 6
    assert summary["model_calls"] == 7
    assert summary["cleanup_verified"]
    assert state["status"] == "inconclusive"
    assert not state["workflow_errors"]
    assert len(state["research_progress"].ledger) == 6
    assert state["research_progress"].ledger[2].category == "failed_experiment"
    assert all(x.verdict == "inconclusive" for x in state["evidence"])
    assert sha256(path.read_bytes()).hexdigest() == before
    assert (output / "events.jsonl").is_file()
