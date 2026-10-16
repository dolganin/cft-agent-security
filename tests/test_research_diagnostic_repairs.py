"""Regressions for observed R09 failures, not benchmark performance claims."""
import os
from types import SimpleNamespace

import pytest

from agent.recovery import protected_node
from agent.research import ResearchAgentModel, research_context
from app.research_run import run_research
from discovery.service import ProjectDiscovery
from schemas.finding import Finding
from schemas.research import ResearchFile, ResearchScope
from schemas.research_agent import ResearchChoice, ResearchLimits, ResearchObservation, ResearchTurn
from schemas.target import TargetProfile
from tools.repository_source import RepositorySource


def scope():
    return ResearchScope(target_id="repair-test", session_id="research-" + "a" * 32,
        worker_image="sha256:" + "b" * 64, worker_sha256="c" * 64,
        source_files={"app.ts": ResearchFile(original_sha256="d" * 64, visible_sha256="e" * 64)})


def test_diagnostic_campaign_keeps_caps_and_enables_both_review_protocols():
    from app.research_diagnostic_run import FIXTURE_GRANTS, limits
    from pipeline.research_fixture_verification import PROTOCOLS

    required = sum(PROTOCOLS[grant.protocol][2] for grant in FIXTURE_GRANTS)
    assert required > limits().max_http_requests == 1024
    assert max(PROTOCOLS[grant.protocol][2] for grant in FIXTURE_GRANTS) <= 256
    assert {"b05.review-owner.v1", "b05.review-nosql.v1"} <= {g.protocol for g in FIXTURE_GRANTS}


def test_extended_campaign_quota_requires_explicit_bounded_operator_value():
    from pydantic import ValidationError

    from app.research_diagnostic_run import limits

    assert limits().max_http_requests == 1024
    assert limits(max_http_requests=1708).max_http_requests == 1708
    with pytest.raises(ValidationError):
        limits(max_http_requests=2049)


@pytest.mark.parametrize("http_budget", [1024, 1708])
@pytest.mark.parametrize("max_actions", [1, 4])
@pytest.mark.parametrize("settled", [False, True])
def test_preverification_separates_campaign_budget_from_per_scope_cap(tmp_path, monkeypatch, max_actions, settled,
                                                                    http_budget):
    import time

    from app import research_campaign as module
    from schemas.research_campaign import CampaignLimits

    captured_scopes, remaining = [], []

    class Runtime:
        def __init__(self, **kwargs):
            captured_scopes.append(kwargs["max_http_requests"])
            self.scope = scope()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    questions = [SimpleNamespace(id=str(n), finding=SimpleNamespace(id=str(n)),
                                 is_candidate=True) for n in range(4)]
    queue = SimpleNamespace(questions=questions, priority=lambda q: q.id,
                            work_key=lambda f: f.id, source_files=["app.ts"], complete=lambda q: None)
    monkeypatch.setattr(module, "ResearchRuntime", Runtime)
    monkeypatch.setattr(module, "verification_handoff", lambda *_args: {
        "checks": [{"status": "ready_for_canonical_verification"}]})

    def verify(**kwargs):
        remaining.append(kwargs["max_http_requests"])
        return {"status": "confirmed" if settled else "inconclusive", "executed": True, "actions": 1,
                "requests_reserved": 238, "requests_observed": 100,
                "request_accounting_complete": settled, "origin": "canonical_fixed_B05_verifier",
                "worker_cleanup_verified": True}

    monkeypatch.setattr(module, "verify_bound_candidate", verify)
    result = module._preverify_bound_findings(queue=queue,
        profile=TargetProfile(id="repair-test", environment="sandbox", repository_path=tmp_path),
        configuration={"worker_image": "sha256:" + "b" * 64}, output=tmp_path,
        limits=CampaignLimits(max_http_requests=http_budget, max_actions=max_actions), verification_profiles=(object(),),
        verification_worker_image="sha256:" + "b" * 64,
        fixture_grants=(), verification_grants=(), started=time.monotonic())
    assert captured_scopes == [256]
    charge = 100 if settled else 238
    assert remaining == [http_budget - charge * index for index in range(max_actions)]
    assert result[2:6] == (max_actions, 0, 238 * max_actions, 100 * max_actions)


def test_preverification_report_is_emitted_once_for_its_exact_group_representative():
    from app.research_campaign import _preverified_terminal_reports

    representative = SimpleNamespace(id="sql-primary", finding=SimpleNamespace(key="same-job"),
                                     is_candidate=True, status="researched")
    grouped = SimpleNamespace(id="sql-alias", finding=SimpleNamespace(key="same-job"),
                              is_candidate=True, status="grouped")
    queue = SimpleNamespace(questions=[representative, grouped],
                            work_key=lambda finding: finding.key)
    review = {"status": "confirmed", "report": {"finding_id": "sql-primary"}}

    reports = _preverified_terminal_reports(queue, {"same-job": review})

    assert len(reports) == 1
    assert reports[0]["question_id"] == "sql-primary"


def test_unknown_fixture_execution_keeps_full_possible_reservation(tmp_path, monkeypatch):
    import time

    from app import research_campaign as module
    from schemas.research_campaign import CampaignLimits

    class Runtime:
        def __init__(self, **kwargs):
            self.scope = scope()

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    question = SimpleNamespace(id="fixture", finding=SimpleNamespace(id="fixture"), is_candidate=True)
    queue = SimpleNamespace(questions=[question], priority=lambda q: q.id,
        work_key=lambda f: f.id, source_files=["app.ts"])
    monkeypatch.setattr(module, "ResearchRuntime", Runtime)
    monkeypatch.setattr(module, "verification_handoff", lambda *_args: {
        "checks": [{"status": "ready_for_canonical_verification"}]})

    def interrupted(**kwargs):
        raise RuntimeError("transport interrupted after possible execution")

    monkeypatch.setattr(module, "verify_bound_candidate", interrupted)
    result = module._preverify_bound_findings(queue=queue,
        profile=TargetProfile(id="repair-test", environment="sandbox", repository_path=tmp_path),
        configuration={"worker_image": "sha256:" + "b" * 64}, output=tmp_path,
        limits=CampaignLimits(max_http_requests=256), verification_profiles=(object(),),
        verification_worker_image="sha256:" + "b" * 64,
        fixture_grants=(SimpleNamespace(max_http_requests=250),), verification_grants=(),
        started=time.monotonic())
    assert result[2:] == (0, 1, 250, 0, True)


def test_preverification_report_with_unknown_finding_id_fails_closed():
    from app.research_campaign import _preverified_terminal_reports

    question = SimpleNamespace(id="sql-primary", finding=SimpleNamespace(key="same-job"),
                               is_candidate=True, status="researched")
    queue = SimpleNamespace(questions=[question], work_key=lambda finding: finding.key)
    review = {"status": "confirmed", "report": {"finding_id": "not-in-queue"}}

    with pytest.raises(ValueError, match="exact finding"):
        _preverified_terminal_reports(queue, {"same-job": review})


def finding():
    return Finding(id="repair", source="operator", rule_id="synthetic", title="Inspect source",
                   description="Not a vulnerability", file="app.ts", line_start=1)


def turn(tool=None, parameters=None, **kwargs):
    return ResearchTurn(summary="Investigate one missing fact", hypothesis="Observe source",
        finish=tool is None, action=None if tool is None else ResearchChoice(tool=tool,
            parameters=parameters, purpose="Inspect", expected_evidence="Observation", **kwargs))


class Client:
    max_output_tokens = 4096

    def __init__(self, turns):
        self.turns = iter(turns)
        self.payloads = []

    def complete_model(self, **kwargs):
        self.payloads.append(kwargs["user_payload"])
        return next(self.turns)


@pytest.mark.parametrize("invalid", [
    turn("read_source", {"path": "component.html"}),
    turn("search_source", {"paths": ["views/"], "literal": "layout"}),
    turn("target_http", {"method": "POST", "path": "/form"}, service="app", endpoint="/form"),
])
def test_scope_feedback_replans_without_provider_failure(invalid):
    client = Client([invalid, turn("read_source", {"path": "app.ts"})])
    model = ResearchAgentModel(client=client, scope=scope(), validator=None)
    state = {"finding": finding()}
    analysis = model.analyse(state)
    plan = model.build_plan(state, analysis, model.form_hypothesis(state, analysis))
    assert plan.steps[0].action.parameters["path"] == "app.ts"
    assert model.progress.model_calls == 2
    assert model.progress.provider_failure_status is None
    assert client.payloads[1]["proposal_feedback"][0]["executed"] is False
    assert client.payloads[1]["source_inventory"] == ["app.ts"]
    assert not model.progress.ledger  # Rejected proposals are not Evidence.


def test_repeated_operation_feedback_can_finish_honestly():
    client = Client([turn("read_source", {"path": "app.ts"}), turn()])
    model = ResearchAgentModel(client=client, scope=scope(), validator=None)
    model.turn = turn("read_source", {"path": "app.ts"})
    action = model._proposal({})
    model.progress.ledger.append(ResearchObservation(action_id=action.id, tool=action.tool,
        fingerprint=model.fingerprint(action), workspace_revision=0, evidence_ids=[], artifact_refs=[],
        execution_status="completed", exit_code=0, observation={"path": "app.ts", "content": "1: source"},
        bytes_observed=9, category="observation"))
    assert not model.analyse({"finding": finding()}).needs_verification
    assert model.progress.proposal_feedback[0]["reason"] == "repeated_operation"
    assert len(model.progress.ledger) == 1


@pytest.mark.parametrize("truncated,expected", [(False, True), (True, False)])
def test_increasing_limit_is_only_progress_after_truncated_search(truncated, expected):
    from tools.research import research_proposal

    model = ResearchAgentModel(client=None, scope=scope(), validator=None)
    action = research_proposal(scope=scope(), action_id="search", tool="search_source",
        parameters={"literal": "feedback", "max_matches": 20}, purpose="Search", expected_evidence="Matches")
    model.progress.ledger.append(ResearchObservation(action_id=action.id, tool=action.tool,
        fingerprint=model.fingerprint(action), request_summary=action.parameters,
        workspace_revision=0, evidence_ids=[], artifact_refs=[], execution_status="completed", exit_code=0,
        observation={"matches": [], "limit_reached": truncated}, bytes_observed=2, category="observation"))
    larger = action.model_copy(update={"parameters": {"literal": "feedback", "paths": ["app.ts"], "max_matches": 50}})
    assert model.repeated(larger) is expected


def test_local_exhaustion_is_not_model_failure():
    invalid = turn("read_source", {"path": "missing.ts"})
    model = ResearchAgentModel(client=Client([invalid] * 3), scope=scope(), validator=None,
                               limits=ResearchLimits(max_proposal_corrections=2))
    with research_context(model):
        result = protected_node("analyse", model.analyse)({"finding": finding()})
    assert result["stop_reason"] == "proposal_corrections_exhausted"
    assert "workflow_errors" not in result
    assert model.progress.model_calls == 3
    assert len(model.progress.proposal_feedback) == 3


def test_scope_mutation_still_rejected_after_preflight():
    from security.research_scope import validate_research_action
    from tools.research import research_proposal

    action = research_proposal(scope=scope(), action_id="a", tool="read_source", parameters={"path": "app.ts"},
                               purpose="Read", expected_evidence="Source")
    action = action.model_copy(update={"parameters": {"path": "missing.ts"}})
    with pytest.raises(ValueError):
        validate_research_action(scope(), action)


def test_proposal_repairs_consume_original_model_budget():
    from agent.research import ResearchBudgetExhausted

    invalid = turn("read_source", {"path": "missing.ts"})
    model = ResearchAgentModel(client=Client([invalid] * 4), scope=scope(), validator=None,
                               limits=ResearchLimits(max_model_calls=2, max_proposal_corrections=4))
    with pytest.raises(ResearchBudgetExhausted):
        model.analyse({"finding": finding()})
    assert model.progress.model_calls == 2
    assert not model.progress.ledger


def test_repair_exhaustion_does_not_trip_campaign_model_circuit(tmp_path, monkeypatch):
    from types import SimpleNamespace

    from app import research_campaign as module
    from schemas.research_agent import ResearchProgress
    from schemas.research_campaign import CampaignLimits

    root = tmp_path / "source"
    root.mkdir()
    (root / "app.ts").write_text("const a = 1;\nconst b = 2;\nconst c = 3;\nconst d = 4;\n")
    inputs = [finding().model_copy(update={"id": str(i), "rule_id": str(i), "line_start": i + 1}) for i in range(4)]
    contexts = []

    def run(**kwargs):
        contexts.append(kwargs["surface_context"])
        return {"research_progress": ResearchProgress(model_calls=1), "research_scope": SimpleNamespace(),
                "stop_reason": "proposal_corrections_exhausted"}, {
                "model_calls": 1, "actions": 0, "cleanup_verified": True,
                "stop_reason": "proposal_corrections_exhausted"}

    monkeypatch.setattr(module, "run_research", run)
    monkeypatch.setattr(module, "review_source_claims", lambda **_: [])
    monkeypatch.setattr(module, "attach_source_review", lambda state, *_: state)
    monkeypatch.setattr(module, "build_final_report", lambda _: SimpleNamespace(model_dump=lambda **_: {
        "finding_id": "not-confirmed", "status": "inconclusive"}))
    result = module.campaign(profile=TargetProfile(id="test", environment="sandbox", repository_path=root),
        configuration={"worker_image": "unused"}, client=None, output=tmp_path / "out", sast=inputs,
        limits=CampaignLimits(max_questions=4, max_model_calls=4))
    assert result["questions_researched"] == 4
    assert result["model_failures"] == []
    assert len(result["question_failures"]) == 4
    assert result["degraded"]
    assert contexts[1]["campaign_memory"]["previous_questions"]
    assert contexts[1]["verification_availability"]["legacy_b_verifiers_connected"] is False


def test_queue_prefers_reachable_server_handler_without_ground_truth(tmp_path):
    from pipeline.research_queue import ResearchQueue
    from schemas.source_map import ExpressRouteRegistration, ExpressSourceMap

    route = ExpressRouteRegistration(id="search", file="server.ts", receiver="app", method="get",
        path="/search", path_is_static=True, line_start=1, line_end=1, registration_order=0,
        handler_files=["routes/search.ts"])
    queue = ResearchQueue(profile=TargetProfile(id="test", environment="sandbox", repository_path=tmp_path),
        source_map=ExpressSourceMap(routes=[route]), source_files=["frontend/about.ts", "routes/search.ts"])
    queue.import_findings([finding().model_copy(update={"id": "frontend", "file": "frontend/about.ts"}),
                           finding().model_copy(update={"id": "backend", "file": "routes/search.ts"})], "sast")
    assert queue.next_question().finding.file == "routes/search.ts"


def test_verification_handoff_never_fabricates_execution(tmp_path):
    from pipeline.research_verification import verification_handoff

    bundle = verification_handoff([finding()], (), tmp_path)
    assert bundle["is_evidence"] is False
    assert bundle["checks"][0]["status"] == "missing_binding_or_capability"
    assert bundle["checks"][0]["security_verdict"] is None
    assert bundle["findings"][0]["id"] == finding().id
    with pytest.raises(ValueError, match="same sandbox"):
        verification_handoff([], [TargetProfile(id="other", environment="sandbox", repository_path=tmp_path / "other")], tmp_path)


def test_scanner_rule_alias_is_local_and_preserves_observation_identity():
    from pipeline.research_verification import verification_finding
    from sast.identity import rule_family

    rule = "javascript.express.security.injection.tainted-sql-string.tainted-sql-string"
    original = finding().model_copy(update={"rule_id": rule})
    mapped = verification_finding(original)
    assert mapped.rule_id == "sql-injection"
    assert mapped.id == original.id and mapped.file == original.file
    assert original.rule_id == rule
    assert rule_family(rule) == rule  # Historical normalization is intentionally unchanged.
    second_rule = "javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection"
    second = finding().model_copy(update={"rule_id": second_rule})
    assert verification_finding(second).rule_id == "sql-injection"
    assert second.rule_id == second_rule
    unknown = finding().model_copy(update={"rule_id": "unreviewed-tainted-sql-string"})
    assert verification_finding(unknown).rule_id == unknown.rule_id


@pytest.mark.parametrize("path", ["/search?q=hello%20world", "/search?q=%23fragment-as-data"])
def test_encoded_query_values_are_data_not_path(path):
    from schemas.research import TargetHttpRequest

    assert TargetHttpRequest(path=path).path == path


@pytest.mark.parametrize("path", ["/search?q=hello world", "/search?q=%0d%0aX:evil", "/search?q=%00",
                                  "/bad%20path?q=ok", "/search%3F/hidden", "/search%23/hidden"])
def test_query_support_keeps_control_and_path_boundaries(path):
    from schemas.research import TargetHttpRequest

    with pytest.raises(ValueError):
        TargetHttpRequest(path=path)


@pytest.mark.skipif(not os.getenv("CFT_RESEARCH_BRIDGE_TARGET"), reason="Opt-in pinned Juice Shop Docker bridge")
def test_existing_sql_verifier_accepts_research_candidate_without_llm(tmp_path):
    import json
    import subprocess
    import time
    from pathlib import Path
    from uuid import uuid4

    from executor.access_fixture import TARGET_IMAGE, WORKER_IMAGE
    from pipeline.research_verification import verify_bound_candidate
    from sast.identity import normalize_finding
    from schemas.research import HttpServiceScope
    from schemas.research_fixtures import ResearchVerificationGrant
    from security.verification_binding import source_snapshot

    def docker(*args):
        return subprocess.check_output(["docker", *args], text=True, stderr=subprocess.STDOUT, timeout=30).strip()

    repository = Path(os.environ["CFT_RESEARCH_BRIDGE_TARGET"]).resolve()
    profile = TargetProfile.from_yaml("targets/juice-verification.yaml", repository_path_override=repository)
    prefix = "research-bridge-test-" + uuid4().hex[:12]
    network, container = prefix + "-net", prefix + "-target"
    docker("network", "create", "--internal", network)
    try:
        cid = docker("run", "-d", "--pull=never", "--name", container, "--network", network,
            "--network-alias", "juice", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--memory=768m", "--cpus=2", "--pids-limit=128", TARGET_IMAGE)
        for _ in range(40):
            ready = subprocess.run(["docker", "exec", cid, "/nodejs/bin/node", "-e",
                "require('http').get('http://127.0.0.1:3000/',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"],
                capture_output=True, timeout=5, check=False)
            if ready.returncode == 0:
                break
            time.sleep(.25)
        else:
            pytest.fail("Pinned target readiness failed")
        file = "routes/search.ts"
        line = next(i for i, s in enumerate((repository / file).read_text().splitlines(), 1) if "models.sequelize.query(" in s)
        rule = "javascript.express.security.injection.tainted-sql-string.tainted-sql-string"
        candidate = normalize_finding(finding().model_copy(update={"id": "research-sql", "rule_id": rule,
            "file": file, "line_start": line, "line_end": line}), repository_root=repository)
        _, hashes = source_snapshot(profile)
        bound_scope = scope().model_copy(update={"source_files": {p: ResearchFile(original_sha256=h, visible_sha256=h)
            for p, h in hashes.items()}, "network_name": network, "services": {"juice": HttpServiceScope(
                container_id=cid, image_id=json.loads(docker("inspect", cid))[0]["Image"],
                address="http://juice:3000", read_prefixes=["/"])}})
        result = verify_bound_candidate(finding=candidate, profiles=(profile,), scope=bound_scope,
            repository=repository, output=tmp_path / "bridge", max_http_requests=4, worker_image=WORKER_IMAGE)
        assert result["status"] == "confirmed", result
        assert result["requests_reserved"] == 4
        assert result["worker_cleanup_verified"]
        assert result["evidence"]["verdict"] == "confirmed"
        assert result["report"]["status"] == "confirmed"
        assert result["report"]["finding"]["rule_id"] == rule
        denied = verify_bound_candidate(finding=candidate, profiles=(profile,), scope=bound_scope,
            repository=repository, output=tmp_path / "no-budget", max_http_requests=3, worker_image=WORKER_IMAGE)
        assert denied["status"] == "review_pending"
        assert not (tmp_path / "no-budget").exists()
        login_file = "routes/login.ts"
        login_line = next(i for i, s in enumerate((repository / login_file).read_text().splitlines(), 1)
                          if "models.sequelize.query(" in s)
        login = normalize_finding(candidate.model_copy(update={"id": "research-login", "provenance": None,
            "file": login_file, "line_start": login_line, "line_end": login_line}), repository_root=repository)
        blocked = verify_bound_candidate(finding=login, profiles=(profile,), scope=bound_scope,
            repository=repository, output=tmp_path / "no-post-grant", max_http_requests=4, worker_image=WORKER_IMAGE)
        assert blocked["status"] == "review_pending"
        assert "not granted" in blocked["reason"]
        assert not (tmp_path / "no-post-grant").exists()
        login_result = verify_bound_candidate(finding=login, profiles=(profile,), scope=bound_scope,
            repository=repository, output=tmp_path / "fixed-login-grant", max_http_requests=4,
            worker_image=WORKER_IMAGE,
            verification_grants=(ResearchVerificationGrant(protocol="b01.login-sql.v1", route_id="juice-login"),))
        assert login_result["status"] == "confirmed", login_result
        assert login_result["requests_reserved"] == 4
        assert login_result["evidence"]["verdict"] == "confirmed"
        assert login_result["worker_cleanup_verified"]
        if os.getenv("CFT_RESEARCH_IMAGE"):
            from app.research_campaign import campaign
            from schemas.research_campaign import CampaignLimits

            out = tmp_path / "integrated-campaign"
            summary = campaign(profile=TargetProfile(id="repair-test", environment="sandbox",
                repository_path=repository, services={"juice": {"internal_port": 3000}}),
                configuration={"worker_image": os.environ["CFT_RESEARCH_IMAGE"], "network_name": network,
                    "services": {"juice": bound_scope.services["juice"].model_dump(mode="json")}},
                client=Client([turn()]), output=out, sast=[candidate],
                limits=CampaignLimits(max_questions=1, max_actions=2, max_model_calls=2, max_http_requests=4),
                verification_profiles=(profile,), verification_worker_image=WORKER_IMAGE)
            assert summary["canonical_runtime_review_counts"]["confirmed"] == 1
            assert summary["http_requests"] == 0
            assert summary["canonical_verification_http_requests_reserved"] == 4
            assert summary["http_request_budget_used"] == 4
            assert summary["actions"] == 1
            assert summary["cleanup_verified"]
            reports = json.loads((out / "reports.json").read_text())
            candidate_report = next(row for row in reports if row["report"]["finding_id"] == candidate.id)
            assert candidate_report["report"]["status"] == "confirmed"
            assert candidate_report["canonical_runtime_review"]["origin"] == "canonical_fixed_verifier; not a model-generated proof"
            assert "research_report" not in candidate_report
            login_output = tmp_path / "integrated-login-campaign"
            login_summary = campaign(profile=TargetProfile(id="repair-login", environment="sandbox",
                repository_path=repository, services={"juice": {"internal_port": 3000}}),
                configuration={"worker_image": os.environ["CFT_RESEARCH_IMAGE"], "network_name": network,
                    "services": {"juice": bound_scope.services["juice"].model_dump(mode="json")}},
                client=Client([turn()]), output=login_output, sast=[login],
                limits=CampaignLimits(max_questions=1, max_actions=2, max_model_calls=2, max_http_requests=4),
                verification_profiles=(profile,), verification_worker_image=WORKER_IMAGE,
                verification_grants=(ResearchVerificationGrant(protocol="b01.login-sql.v1", route_id="juice-login"),))
            assert login_summary["canonical_runtime_review_counts"]["confirmed"] == 1
            login_reviews = json.loads((login_output / "canonical-runtime-reviews.json").read_text())
            assert login_reviews[0]["finding_id"] == login.id
            assert json.loads((login_output / "reports.json").read_text())[0]["canonical_runtime_review"]["status"] == "confirmed"
            assert login_reviews[0]["status"] == "confirmed"

        ftp_route = next(item for item in profile.verification_routes if item.id == "juice-directory-ftp")
        ftp_registration = ftp_route.registration
        ftp_lines = (repository / ftp_registration.file).read_text().splitlines()
        ftp_matches = [index for index, value in enumerate(ftp_lines, 1) if ftp_registration.anchor in value]
        assert len(ftp_matches) == 1
        ftp = normalize_finding(candidate.model_copy(update={"id": "research-ftp", "provenance": None,
            "rule_id": "file-exposure",
            "title": "Bounded FTP listing candidate", "description": "Source-bound directory listing observation",
            "file": ftp_registration.file, "line_start": ftp_matches[0], "line_end": ftp_matches[0]}),
            repository_root=repository)
        ftp_output = verify_bound_candidate(finding=ftp, profiles=(profile,), scope=bound_scope,
            repository=repository, output=tmp_path / "fixed-ftp-verifier", max_http_requests=1,
            worker_image=WORKER_IMAGE)
        assert ftp_output["executed"] is True
        assert ftp_output["requests_reserved"] == 1
        assert ftp_output["requests_observed"] == 1
        assert ftp_output["worker_cleanup_verified"] is True
        assert ftp_output["evidence"]["observation"]["facts"]["facts"]["file_contents_read"] is False
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, timeout=30, check=False)
        docker("network", "rm", network)


def test_research_templates_and_metadata_do_not_change_historical_inventory(tmp_path):
    for name, content in {"app.ts": "const a = 1;", "component.html": "<div>text</div>",
                          "view.pug": "p text", "package.json": '{"name":"test"}',
                          ".env": "SECRET=private", "solutions/answer.html": "oracle"}.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
    inventory = ProjectDiscovery().discover(tmp_path)
    old = RepositorySource(inventory)
    new = RepositorySource(inventory, research_mode=True)
    assert "component.html" not in old.files
    assert {"component.html", "view.pug", "package.json"} <= set(new.files)
    assert not any(".env" in p or "solutions" in p for p in new.files)


@pytest.mark.skipif(not os.getenv("CFT_RESEARCH_IMAGE"), reason="Opt-in immutable research image required")
def test_real_graph_scope_failure_then_html_read_then_repeat_repair(tmp_path):
    root = tmp_path / "target"
    root.mkdir()
    (root / "app.ts").write_text("export const a = 1;\n")
    (root / "component.html").write_text("<p>synthetic marker</p>\n")
    read = turn("read_source", {"path": "component.html"})
    client = Client([turn("search_source", {"paths": ["missing/"], "literal": "layout"}), read, read, turn()])
    state, summary = run_research(profile=TargetProfile(id="repair-test", environment="sandbox", repository_path=root),
        configuration={"worker_image": os.environ["CFT_RESEARCH_IMAGE"], "source_files": ["app.ts", "component.html"]},
        finding=finding(), output=tmp_path / "output", client=client)
    assert summary["stop_reason"] == "research_complete"
    assert summary["model_calls"] == 4
    assert summary["actions"] == 1
    assert summary["proposal_corrections"] == 2
    assert summary["cleanup_verified"]
    assert len(state["research_progress"].ledger) == 1
    assert "synthetic marker" in state["research_progress"].ledger[0].observation["content"]
    assert all(e.verdict == "inconclusive" for e in state["evidence"])
    assert not state.get("workflow_errors")
