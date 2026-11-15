"""Speedups must preserve candidate scope, observations and fresh reasoning inputs."""
import shutil
from contextvars import ContextVar
from threading import Barrier, Lock

import pytest

from agent.compact_model import CompactRegisteredAgentModel, RegisteredReasoningTurn
from agent.model import get_agent_model, reasoning_model_context
from agent.nodes import load_context, score_finding
from agent.verification import register_source_artifacts, verification_candidates
from app.config import settings
from app.demo import ORDER_PROFILE, ORDER_TEMPLATE
from discovery.scout import coalesce_bound_scout_findings
from sast.identity import normalize_finding
from schemas.agent_outputs import AnalysisResult
from schemas.finding import Finding
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.target import TargetProfile
from security.verification_binding import source_snapshot, validate_action_binding


@pytest.fixture
def prepared(tmp_path):
    root = tmp_path / "store"
    shutil.copytree(ORDER_TEMPLATE, root)
    profile = TargetProfile.from_yaml(ORDER_PROFILE, repository_path_override=root)
    finding = normalize_finding(Finding(
        id="scanner-search", source="semgrep", rule_id="demo-sql-injection.search",
        title="SQL", description="Search query", file="routes/search.js",
        line_start=4, line_end=7, service="store",
    ), repository_root=root)
    profile = register_source_artifacts(profile, [finding], root)
    _, hashes = source_snapshot(profile)
    runtime = RuntimeServiceMap(session_id="compact-test", source_files_sha256=hashes,
        services={"store": RuntimeService(name="store", address="http://store:3000", ready=True,
            readiness_source="http_probe", allowed_endpoints=profile.services["store"].runtime_endpoints)})
    state = {"finding": finding, "target_profile": profile, "runtime_services": runtime,
             "code_context": "query(criteria)", "max_iterations": 2}
    state.update(load_context(state))
    state.update(score_finding(state))
    return state


def response(state):
    candidate, = verification_candidates(state)
    return RegisteredReasoningTurn.model_validate({
        "analysis": {"summary": "Требуется проверка SQL", "risk_signals": ["input_to_query"]},
        "hypothesis": {"id": "test-hypothesis", "statement": "Ввод изменяет запрос",
            "based_on": ["source"], "expected_evidence": "Контролируемая разница", "confidence": 0.8},
        "plan": {"goal": "Проверить SQL", "max_steps": 1,
            "continuation_reason": "Оценить доказательства", "stop_conditions": ["terminal_evidence"],
            "steps": [{"candidate_id": candidate["candidate_id"],
                "expected_observation": "Контролируемая разница", "continue_if": "Недостаточно данных"}]},
    })


class Client:
    trace = False
    diagnostics_path = None

    def __init__(self, turn):
        self.turn = turn
        self.calls = []

    def complete_model(self, **kwargs):
        self.calls.append(kwargs["operation"])
        return self.turn.model_copy(deep=True)


def test_one_request_still_builds_the_exact_operator_bound_action(prepared):
    client = Client(response(prepared))
    model = CompactRegisteredAgentModel(client)
    prepared["analysis"] = model.analyse(prepared)
    prepared["hypothesis"] = model.form_hypothesis(prepared, prepared["analysis"])
    plan = model.build_plan(prepared, prepared["analysis"], prepared["hypothesis"])
    assert client.calls == ["registered_reasoning_turn"]
    assert validate_action_binding(prepared["target_profile"], plan.steps[0].action)
    # Later graph nodes can add diagnostics without forcing another request.
    prepared["reasoning_events"] = ["diagnostic-only"]
    assert model._cached(prepared) is not None
    # New source/iterations/evidence invalidate the cached reasoning.
    for updates in ({"code_context": "changed"}, {"iteration_count": 1},
                    {"runtime_services": prepared["runtime_services"].model_copy(update={"session_id": "other"})}):
        assert model._cached({**prepared, **updates}) is None


def test_parallel_requests_have_private_clients_and_propagate_context(prepared, monkeypatch):
    context = ContextVar("prefetch-test", default=None)
    barrier, lock = Barrier(2), Lock()
    clients, seen = [], []
    turn = response(prepared)

    class ParallelClient(Client):
        def complete_model(self, **kwargs):
            with lock:
                seen.append(context.get())
            barrier.wait(timeout=3)
            return super().complete_model(**kwargs)

    def factory(cls, config):
        client = ParallelClient(turn)
        clients.append(client)
        return cls(client)

    monkeypatch.setattr(CompactRegisteredAgentModel, "from_settings", classmethod(factory))
    model = CompactRegisteredAgentModel(Client(turn))
    other = {**prepared, "finding": prepared["finding"].model_copy(update={"id": "another"})}
    token = context.set("run-context")
    try:
        model.prefetch([prepared, other], workers=2)
    finally:
        context.reset(token)
    assert len(clients) == 2 and clients[0] is not clients[1]
    assert seen == ["run-context", "run-context"]
    assert model._cached(prepared) and model._cached(other)
    assert model.analyse(prepared).summary == turn.analysis.summary
    assert model.client.calls == []
    monkeypatch.setattr(settings, "agent_mode", "llm")
    with reasoning_model_context(model):
        assert get_agent_model() is model
    assert get_agent_model() is not model


def test_coalescing_keeps_origins_and_does_not_choose_among_scanner_sinks(prepared):
    primary, profile = prepared["finding"], prepared["target_profile"]
    scout = normalize_finding(primary.model_copy(update={
        "id": "scout-search", "source": "model_scout", "rule_id": "sql-injection",
        "line_end": 6, "provenance": None,
    }), repository_root=profile.repository_path)
    findings, count = coalesce_bound_scout_findings([scout, primary], profile)
    assert count == 1 and len(findings) == 1
    assert findings[0].id == primary.id and findings[0].line_end == 7
    assert set(findings[0].provenance.aliases) == {primary.id, scout.id}
    assert len(findings[0].provenance.observations) == 2
    assert coalesce_bound_scout_findings(findings, profile) == (findings, 0)
    shifted = normalize_finding(scout.model_copy(update={
        "line_start": 5, "line_end": 6, "provenance": None,
    }), repository_root=profile.repository_path)
    assert coalesce_bound_scout_findings([primary, shifted], profile)[1] == 1
    disjoint = normalize_finding(scout.model_copy(update={
        "line_start": 8, "line_end": 8, "provenance": None,
    }), repository_root=profile.repository_path)
    assert coalesce_bound_scout_findings([primary, disjoint], profile)[1] == 0
    other_sink = primary.model_copy(update={"id": "scanner-other"})
    assert coalesce_bound_scout_findings([primary, other_sink, scout], profile)[1] == 0
    unmapped = normalize_finding(scout.model_copy(update={
        "file": "server.js", "line_start": 53, "line_end": 55, "provenance": None,
    }), repository_root=profile.repository_path)
    assert coalesce_bound_scout_findings([primary, unmapped], profile)[1] == 0


def test_unknown_model_candidate_is_not_cached_or_promoted(prepared):
    turn = response(prepared)
    turn.plan.steps[0].candidate_id = "invented:outside-scope"

    class InvalidClient(Client):
        def complete_model(self, **kwargs):
            self.calls.append(kwargs["operation"])
            if kwargs["operation"] == "analyse":
                return AnalysisResult(summary="Fallback analysis requires verification")
            return turn

    client = InvalidClient(turn)
    model = CompactRegisteredAgentModel(client)
    result = model.analyse(prepared)
    assert result.summary == "Fallback analysis requires verification"
    assert client.calls == ["registered_reasoning_turn", "analyse"]
    assert model._cached(prepared) is None


def test_no_registered_candidate_still_gets_analysis_without_a_fabricated_plan(prepared):
    turn = response(prepared)
    turn.plan = None
    unbound = {**prepared, "finding": prepared["finding"].model_copy(update={
        "id": "backup", "file": "server.js", "rule_id": "file-exposure",
        "line_start": 53, "line_end": 55, "provenance": None,
    })}
    assert verification_candidates(unbound) == []
    model = CompactRegisteredAgentModel(Client(turn))
    assert model.analyse(unbound) == turn.analysis
    assert model._cached(unbound).plan is None
