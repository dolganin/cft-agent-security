"""Fault injection at real graph boundaries; no target or provider traffic."""

import json
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from test_agent_loop import _AdaptiveModel, _finding, _profile
from test_ci_pipeline import _args
from test_ci_pipeline import _profile as pipeline_profile
from test_evidence_guard import _evidence
from test_evidence_guard import _state as evidence_state

from agent import budget, graph, nodes
from agent.llm import LLMUnavailableError, ProviderFailoverClient, parse_route_specs
from agent.llm_model import FallbackLLMAgentModel
from agent.model import DeterministicAgentModel
from agent.recovery import protected_node
from app.config import settings
from evaluation.artifact_history import persist_agent_trace
from pipeline.cancellation import RunCancelled
from reporting.builder import build_final_report
from schemas.errors import ErrorDetail
from schemas.execution import ExecutionResult
from security.access_verification import ACCESS_CHECKS


class Executor:
    def __init__(self, *, fail_first=False, crash=False):
        self.actions = []
        self.records = {}
        self.fail_first = fail_first
        self.crash = crash

    def verification_fixture(self, target):
        return None

    def record_approval(self, action, validation):
        assert validation.approved and action.id == validation.action_id

    def execute(self, action):
        self.actions.append(action)
        if self.crash:
            raise TimeoutError("api_key=never-include-this")
        failed = self.fail_first and len(self.actions) == 1
        result = ExecutionResult(
            run_id="run-" + action.id,
            action_id=action.id,
            status="failed" if failed else "completed",
            exit_code=124 if failed else 0,
            timed_out=failed,
            stdout="first-observation" if len(self.actions) == 1 else "second-observation",
            evidence_ref="evidence-" + action.id,
            audit_ref="audit-" + action.id,
            error=ErrorDetail(code="TIMEOUT", layer="executor", message="Bounded timeout")
            if failed
            else None,
        )
        self.records[result.evidence_ref] = {
            **result.model_dump(),
            "session_id": "session-" + action.id,
        }
        return result


def setup(monkeypatch, model=None, executor=None):
    model = model or _AdaptiveModel()
    executor = executor or Executor()
    monkeypatch.setattr(nodes, "get_agent_model", lambda: model)
    monkeypatch.setattr(nodes, "active_executor", lambda: executor)
    monkeypatch.setattr(
        nodes,
        "JsonExecutionEvidenceStore",
        lambda path: SimpleNamespace(get_execution=lambda ref: executor.records[ref]),
    )
    monkeypatch.setattr(settings, "agent_mode", "stub")
    return executor


def state(steps=2):
    return {
        "finding": _finding(),
        "target_profile": _profile(),
        "max_steps": steps,
        "max_iterations": steps,
        "iteration_count": 0,
        "evidence": [],
    }


def test_replanned_commands_results_and_sessions_survive_trace(monkeypatch, tmp_path):
    executor = setup(monkeypatch)
    result = graph.build_graph().invoke(state())
    assert len(executor.actions) == len(result["action_history"]) == 2
    assert executor.actions[0].parameters != executor.actions[1].parameters
    report = result["final_report"]
    assert report.status == "inconclusive" and report.stop_reason == "insufficient_evidence"
    assert len({item.sandbox_session_id for item in report.sandbox_actions}) == 2
    assert [item.stdout for item in report.sandbox_actions] == [
        "first-observation",
        "second-observation",
    ]
    trace = json.loads(persist_agent_trace(tmp_path, _finding().id, result).read_text())
    assert len(trace["plans"]) == len(trace["actions"]) == len(trace["decisions"]) == 2
    assert all(item["validation"]["approved"] for item in trace["actions"])
    assert all(item["execution"] and item["evidence_ids"] for item in trace["actions"])


def test_timeout_allows_a_different_action_and_retains_error(monkeypatch):
    executor = setup(monkeypatch, executor=Executor(fail_first=True))
    result = graph.build_graph().invoke(state())
    assert len(executor.actions) == 2
    assert result["action_history"][0].execution.timed_out
    assert result["final_report"].workflow_errors[0].code == "TIMEOUT"
    assert result["final_report"].status == "inconclusive"


def test_same_operation_with_new_id_stops_before_second_execution(monkeypatch):
    class Repeating(_AdaptiveModel):
        def build_plan(self, state, analysis, hypothesis):
            plan = super().build_plan(state, analysis, hypothesis)
            plan.steps[0].action.parameters = {
                "argv": ["python", "-c", "print('first')"],
                "cwd": "/target",
            }
            return plan

    executor = setup(monkeypatch, Repeating())
    result = graph.build_graph().invoke(state(3))
    assert len(executor.actions) == 1
    assert len(result["plan_history"]) == 2
    assert (
        result["plan_history"][0].steps[0].action.id != result["plan_history"][1].steps[0].action.id
    )
    assert result["final_report"].stop_reason == "repeated_action"


def test_executor_exception_keeps_approved_action_without_inventing_execution(monkeypatch):
    setup(monkeypatch, executor=Executor(crash=True))
    result = graph.build_graph().invoke(state())
    report = result["final_report"]
    assert report.status == "inconclusive" and report.stop_reason == "execution_timeout"
    assert report.policy_decisions[0].decision == "approved"
    assert result["action_history"][0].execution is None
    assert report.workflow_errors[0].code == "TIMEOUT"
    assert "never-include-this" not in report.model_dump_json()


@pytest.mark.parametrize(
    "node",
    [
        "analyse",
        "form_hypothesis",
        "propose_action",
        "validate_action",
        "collect_evidence",
        "reevaluate",
    ],
)
def test_each_failure_boundary_preserves_previous_evidence_and_cancellation(node):
    def fail(state):
        raise RuntimeError("api_key=never-include-this")

    initial = {"iteration_count": 1, "evidence": [_evidence(verdict=None)]}
    result = protected_node(node, fail)(initial)
    assert result["status"] == "inconclusive"
    assert result["decision_history"][0].evidence_ids == [initial["evidence"][0].id]
    assert result["workflow_errors"][0].layer == (
        "llm"
        if node in {"analyse", "form_hypothesis", "propose_action", "reevaluate"}
        else "validator"
        if node == "validate_action"
        else "storage"
    )
    assert "never-include-this" not in result["workflow_errors"][0].message

    def cancel(state):
        raise RunCancelled("operator cancel")

    with pytest.raises(RunCancelled):
        protected_node(node, cancel)(initial)


def test_deadline_between_approval_and_execution_preserves_approval(monkeypatch):
    executor = setup(monkeypatch)
    original = graph.validate_action

    def delayed_validation(state):
        return {**original(state), "started_at": datetime.now(UTC) - timedelta(hours=1)}

    monkeypatch.setattr(graph, "validate_action", delayed_validation)
    result = graph.build_graph().invoke(state())
    assert not executor.actions
    assert result["final_report"].stop_reason == "wall_clock_budget_exhausted"
    assert result["action_history"][0].validation.approved
    assert result["action_history"][0].execution is None


def test_missing_persisted_evidence_is_a_visible_storage_error(monkeypatch):
    setup(monkeypatch)

    def missing(ref):
        raise FileNotFoundError(ref)

    monkeypatch.setattr(
        nodes, "JsonExecutionEvidenceStore", lambda path: SimpleNamespace(get_execution=missing)
    )
    result = graph.build_graph().invoke(state(1))
    assert result["final_report"].status == "inconclusive"
    assert result["final_report"].workflow_errors[0].code == "PERSISTENCE_ERROR"
    assert result["action_history"][0].execution is not None


@pytest.mark.parametrize("verdict", ["confirmed", "rejected"])
def test_report_cannot_promote_an_unsupported_model_claim(verdict):
    initial = evidence_state(evidence=[])
    initial.update(finding=_finding(), status=verdict)
    report = build_final_report(initial)
    assert report.status == "inconclusive"


@pytest.mark.parametrize(
    "field, value", [("scope", "other-target"), ("tool", "other-tool"), ("run", "other-run")]
)
def test_terminal_evidence_must_match_target_tool_and_execution(field, value):
    from evidence.guard import evaluate_evidence

    evidence = _evidence(verdict="confirmed")
    if field == "scope":
        evidence = evidence.model_copy(
            update={"scope": evidence.scope.model_copy(update={"target": value})}
        )
    else:
        key = "tool" if field == "tool" else "run_id"
        evidence = evidence.model_copy(
            update={"action": evidence.action.model_copy(update={key: value})}
        )
    assert evaluate_evidence(evidence_state(evidence=[evidence])).status == "continue"


def test_provider_fallback_is_persisted_as_degradation(monkeypatch):
    class Client:
        def complete_model(self, **kwargs):
            raise LLMUnavailableError("api_key=never-include-this")

    setup(monkeypatch, FallbackLLMAgentModel(Client()))
    result = nodes.analyse(state())
    assert result["analysis"].needs_verification
    assert result["reasoning_events"][0].status == "fallback"
    assert result["reasoning_events"][0].category == "LLMUnavailableError"


@pytest.mark.parametrize("mode", ["fallback", "schema", "network_retry"])
def test_provider_chain_and_corrections_share_one_deadline(monkeypatch, mode):
    from agent import llm
    from schemas.agent_outputs import AnalysisResult

    now = [0.0]
    monkeypatch.setattr(budget, "monotonic", lambda: now[0])
    calls = []

    def post(*args, **kwargs):
        calls.append(kwargs["timeout"])
        now[0] = 11.0
        if mode == "schema":
            return {"choices": [{"message": {"content": "{}"}}]}
        raise RuntimeError("network timeout")

    monkeypatch.setattr(llm, "_post_json", post)
    client = ProviderFailoverClient(
        routes=parse_route_specs("nsu:model-a,nsu:model-b"),
        credentials={"NSU_OPENWEBUI_KEY": "disposable-test"},
    )
    with (
        budget.reasoning_budget({"wall_clock_budget_seconds": 10}),
        pytest.raises(budget.ReasoningBudgetExpired),
    ):
        client.complete_model(
            output_model=AnalysisResult,
            system_prompt="test",
            user_payload={},
            operation="analyse",
            schema_retries=int(mode == "schema"),
            network_retries=int(mode == "network_retry"),
        )
    assert calls == [10.0]
    assert budget.bounded_timeout(25) == 25  # Context cannot leak to the next finding.


@pytest.mark.parametrize("mode", ["node", "escaped"])
def test_pipeline_keeps_two_reports_when_first_finding_fails(monkeypatch, tmp_path, mode):
    from app import pipeline_run

    class Model(DeterministicAgentModel):
        def analyse(self, state):
            if mode == "node" and state["finding"].id == "first":
                raise LLMUnavailableError("controlled provider failure")
            return super().analyse(state)

    setup(monkeypatch, Model())
    target = tmp_path / "target"
    target.mkdir()
    (target / "app.py").write_text("print('fixture')\n")
    args = _args(tmp_path, target, pipeline_profile(tmp_path, target))
    findings = [
        _finding().model_copy(
            update={
                "id": name,
                "file": "app.py",
                "service": "backend",
                "severity": "TEST_CONFIRMED",
            }
        )
        for name in ["first", "second"]
    ]
    findings_path = tmp_path / "findings.json"
    findings_path.write_text(json.dumps([item.model_dump(mode="json") for item in findings]))
    args.findings = str(findings_path)
    for field in ["target_file", "target_repository_path", "agent_mode"]:
        monkeypatch.setattr(settings, field, getattr(settings, field))
    real_graph = graph.build_graph()

    class Graph:
        def invoke(self, state):
            if mode == "escaped" and state["finding"].id == "first":
                raise RuntimeError("controlled bootstrap failure")
            return real_graph.invoke(state)

    monkeypatch.setattr(pipeline_run, "build_graph", lambda: Graph())
    assert pipeline_run.run_pipeline(args) == 2
    root = tmp_path / "artifacts"
    reports = json.loads((root / "reports-index.json").read_text())
    assert len(reports) == 2
    gate = json.loads((root / "gate.json").read_text())
    assert gate["reports_total"] == 2 and gate["technical_errors"] >= 1
    first = json.loads((root / "traces/first.json").read_text())
    assert first["status"] == "inconclusive" and first["workflow_errors"]


@pytest.mark.parametrize("unsupported", [False, True])
def test_binding_and_missing_operator_capability_are_distinct(monkeypatch, unsupported):
    import agent.verification
    import security.verification_binding

    binding = (
        SimpleNamespace(route_id=ACCESS_CHECKS["juice-basket-own-write-v3"].route_id)
        if unsupported
        else None
    )
    resolution = SimpleNamespace(
        status="bound" if unsupported else "inconclusive",
        binding=binding,
        reason="ambiguous source",
    )
    monkeypatch.setattr(security.verification_binding, "resolve_binding", lambda *args: resolution)
    monkeypatch.setattr(agent.verification, "verification_candidates", lambda state: [])
    initial = {"finding": _finding(), "target_profile": SimpleNamespace(verification_routes=[1])}
    result = nodes.propose_action(initial)
    assert result["stop_reason"] == ("missing_capability" if unsupported else "binding_unavailable")


def test_validator_denial_never_reaches_executor_or_replanning(monkeypatch):
    class Denied(_AdaptiveModel):
        def build_plan(self, state, analysis, hypothesis):
            plan = super().build_plan(state, analysis, hypothesis)
            plan.steps[0].action.tool = "unregistered-action"
            return plan

        def reevaluate(self, state):
            pytest.fail("Denied proposals must terminate before reevaluation")

    executor = setup(monkeypatch, Denied())
    result = graph.build_graph().invoke(state(3))
    assert not executor.actions
    assert result["final_report"].status == "policy_blocked"
    assert result["action_history"][0].validation.approved is False
    assert result["decision_history"][-1].stop_reason == "policy_blocked"
    assert not result["final_report"].workflow_errors


def test_reusing_action_id_for_different_parameters_is_also_blocked(monkeypatch):
    class ReusedId(_AdaptiveModel):
        def build_plan(self, state, analysis, hypothesis):
            plan = super().build_plan(state, analysis, hypothesis)
            plan.steps[0].action.id = "constant-action-id"
            return plan

    executor = setup(monkeypatch, ReusedId())
    result = graph.build_graph().invoke(state(3))
    assert len(executor.actions) == 1
    assert (
        result["plan_history"][0].steps[0].action.parameters
        != result["plan_history"][1].steps[0].action.parameters
    )
    assert result["final_report"].stop_reason == "repeated_action"


def test_report_failure_retains_completed_history_in_failure_report(monkeypatch):
    setup(monkeypatch)

    def fail(state):
        raise RuntimeError("controlled report failure")

    monkeypatch.setattr(graph, "build_report", fail)
    result = graph.build_graph().invoke(state())
    report = result["final_report"]
    assert report.status == "inconclusive" and report.stop_reason == "workflow_failure"
    assert len(report.sandbox_actions) == len(report.evidence) == 2
    assert report.workflow_errors[-1].message.endswith("report")
