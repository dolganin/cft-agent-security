"""R07 queue recovery and R08 scope/transport boundaries, no live API required."""
import json
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from agent.llm import ProviderFailoverClient, parse_route_specs
from executor.research_browser import browser_bridge_request
from schemas.finding import Finding
from schemas.research import BrowserRequest, HttpServiceScope, ResearchFile, ResearchScope
from schemas.research_agent import ResearchProgress, ResearchTurn
from schemas.research_campaign import CampaignLimits
from schemas.target import TargetProfile
from security.research_scope import validate_research_action
from tools.research import research_proposal


def test_invalid_corrected_response_records_both_validation_failures(monkeypatch):
    from agent.llm import LLMUnavailableError
    replies = iter(['{"summary":"missing fields"}', '{"summary":"still missing"}'])
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:test"), credentials={"NSU_OPENWEBUI_KEY": "synthetic"})
    monkeypatch.setattr(client, "_request_route", lambda *_: next(replies))
    with pytest.raises(LLMUnavailableError):
        client.complete_model(output_model=ResearchTurn, system_prompt="test", user_payload={},
                              operation="test", schema_retries=1)
    assert sum(error["loc"] == ("hypothesis",) for error in client.last_schema_errors) == 2
    assert len(client.last_attempts) == 2


@pytest.mark.parametrize("category,failures,expected_runs,stop", [
    ("schema_validation_failed", 1, 3, "question_budget_exhausted"),
    ("schema_validation_failed", 3, 3, "consecutive_model_failures"),
    ("auth_or_access", 1, 1, "provider_unavailable"),
    ("rate_limited", 1, 1, "provider_unavailable"),
])
def test_campaign_preserves_failed_question_and_does_not_reset_budget(tmp_path, monkeypatch,
        category, failures, expected_runs, stop):
    from app import research_campaign as module
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.ts").write_text("const a = 1;\nconst b = 2;\nconst c = 3;\n")
    profile = TargetProfile(id="test", environment="sandbox", repository_path=source)
    sast = [Finding(id=f"q{i}", source="semgrep", rule_id=f"family-{i}", title=f"Question {i}",
        description="Unverified", file="app.ts", line_start=i+1) for i in range(3)]
    remaining = []
    http_budgets = []

    def run(**kwargs):
        index = len(remaining)
        remaining.append(kwargs["limits"].max_model_calls)
        http_budgets.append(kwargs["configuration"]["max_http_requests"])
        failed = index < failures
        progress = ResearchProgress(model_calls=2, provider_failure_status=category if failed else None)
        state = {"research_progress": progress, "research_scope": SimpleNamespace(),
                 "workflow_errors": ["synthetic"] if failed else [],
                 "stop_reason": "model_failure" if failed else "research_complete"}
        return state, {"model_calls": 2, "actions": 0, "cleanup_verified": True,
                       "http_requests": min(3, kwargs["configuration"]["max_http_requests"])}

    monkeypatch.setattr(module, "run_research", run)
    monkeypatch.setattr(module, "review_source_claims", lambda **_: [])
    monkeypatch.setattr(module, "attach_source_review", lambda state, *_: state)
    monkeypatch.setattr(module, "build_final_report", lambda _: SimpleNamespace(model_dump=lambda **_: {
        "finding_id": "no-confirmed", "status": "inconclusive"}))
    out = tmp_path / "out"
    result = module.campaign(profile=profile, configuration={"worker_image": "unused"}, client=None,
        output=out, sast=sast, limits=CampaignLimits(max_questions=3, max_model_calls=6, max_http_requests=4))
    assert len(remaining) == expected_runs
    assert remaining == [6, 4, 2][:expected_runs]
    assert http_budgets == [4, 1, 0][:expected_runs]
    assert result["http_requests"] <= 4
    assert result["stop_reason"] == stop
    assert result["degraded"]
    assert result["model_calls"] == expected_runs * 2
    questions = json.loads((out / "questions.json").read_text())
    assert sum(q["status"] == "failed" for q in questions) == min(failures, expected_runs)


def scope(browser=True):
    return ResearchScope(target_id="test", session_id="research-" + "a"*32,
        worker_image="sha256:"+"b"*64, worker_sha256="c"*64,
        source_files={"app.ts": ResearchFile(original_sha256="d"*64, visible_sha256="e"*64)},
        network_name="private-test", browser_image="sha256:"+"f"*64 if browser else None,
        browser_worker_sha256="a"*64 if browser else None,
        services={"app": HttpServiceScope(container_id="1"*64, image_id="sha256:"+"2"*64,
            address="http://app:8080", read_prefixes=["/ui", "/assets"], write_paths={"POST": ["/submit"]})})


def action(bound=None):
    return research_proposal(scope=bound or scope(), action_id="browser-test", tool="browser_interact",
        parameters={"path": "/ui"}, service="app", endpoint="/ui", purpose="Inspect UI",
        expected_evidence="Browser observation")


@pytest.mark.parametrize("parameters", [
    {"path":"http://external.example/"}, {"path":"/../private"},
    {"path":"/ui", "evaluate":"alert(1)"},
    {"path":"/ui", "storage_state":{}},
    {"path":"/ui", "steps":[{"operation":"evaluate", "value":"script"}]},
    {"path":"/ui", "steps":[{"operation":"press", "selector":"input", "value":"F12"}]},
])
def test_browser_rejects_arbitrary_origins_code_and_storage(parameters):
    with pytest.raises(ValidationError):
        BrowserRequest.model_validate(parameters)


def test_browser_requires_operator_image_and_scope():
    with pytest.raises(ValueError, match="provisioning"):
        action(scope(False))
    allowed = action()
    assert validate_research_action(scope(), allowed).path == "/ui"
    with pytest.raises(ValueError):
        validate_research_action(scope(), allowed.model_copy(update={"endpoint":"/private"}))


def test_every_browser_subrequest_uses_scope_and_shared_http_budget():
    runtime = SimpleNamespace(scope=scope(), requests=0)
    original = action()
    message = {"method":"GET", "path":"/assets/app.js", "body":"", "headers":{}}
    assert browser_bridge_request(runtime, original, message).path == "/assets/app.js"
    assert runtime.requests == 1
    for bad in [{**message, "path":"/private"}, {**message, "method":"POST"},
                {**message, "headers":{"Authorization":"not-allowed"}},
                {**message, "path":"http://app:8080/ui"}]:
        with pytest.raises(ValueError):
            browser_bridge_request(runtime, original, bad)
    runtime.requests = runtime.scope.max_http_requests
    with pytest.raises(ValueError, match="budget"):
        browser_bridge_request(runtime, original, message)


def test_reaped_browser_pipe_close_is_not_unknown_container_cleanup():
    from executor.research_browser import close_process
    calls = []

    def broken_pipe():
        raise BrokenPipeError("Child already exited")

    process = SimpleNamespace(kill=lambda:calls.append("kill"), wait=lambda **_:calls.append("wait"),
        stdin=SimpleNamespace(close=broken_pipe), stdout=SimpleNamespace(close=lambda:calls.append("close")))
    close_process(process)
    assert calls == ["kill", "wait", "close"]


@pytest.mark.parametrize("path", ["/ui/private", "/ui/private/child", "/ui/%70rivate", "/ui/%2570rivate"])
def test_operator_exclusions_override_read_grants_including_encoded_paths(path):
    original = scope()
    service = original.services["app"].model_copy(update={"denied_prefixes":["/ui/private"]})
    bound = original.model_copy(update={"services":{"app":service}})
    allowed = action(bound)
    request = {"method":"GET", "path":path, "body":"", "headers":{}}
    with pytest.raises(ValueError, match="excluded"):
        browser_bridge_request(SimpleNamespace(scope=bound, requests=0), allowed, request)
