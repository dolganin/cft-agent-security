"""B01 line movement, caller/helper ambiguity, approval and persisted provenance."""
import json
from hashlib import sha256
from types import SimpleNamespace

import pytest

from agent.model import DeterministicAgentModel
from agent.nodes import propose_action
from agent.verification import register_source_artifacts, verification_candidates
from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore, proposal_digest
from executor.executor import SafeExecutor
from executor.sandbox import RunLimiter, SandboxResult
from executor.sandbox_policy import SandboxPolicy
from executor.targets import TargetRegistry
from sast.identity import normalize_finding
from schemas.action import ActionProposal
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.target import TargetProfile
from security.verification_binding import resolve_binding, source_snapshot, validate_action_binding
from validator.validator import PolicyValidator


@pytest.fixture
def fixture(tmp_path):
    (tmp_path / "routes").mkdir()
    source = "export function search () {\n  return query(req.query.q)\n}\n"
    (tmp_path / "routes/search.ts").write_text(source, encoding="utf-8")
    (tmp_path / "server.ts").write_text("app.get('/search', search())\n", encoding="utf-8")
    profile = TargetProfile.model_validate({
        "id": "binding-test", "environment": "sandbox", "repository_path": tmp_path,
        "services": {"api": {"root": ".", "runtime_endpoints": ["/search", "/other"]}},
        "verification_routes": [{
            "id": "search", "handler_id": "api.search", "family": "sql-injection",
            "service": "api", "endpoint": "/search", "method": "GET",
            "tool": "verify_sql_injection", "mode": "search", "check": "sql_interpolation",
            "registration": {"file": "server.ts", "anchor": "app.get('/search', search())"},
            "sources": [{"file": "routes/search.ts", "anchor": "export function search () {",
                         "extent": "function"},
                        {"file": "server.ts", "anchor": "app.get('/search', search())"}],
        }],
    })
    from schemas.finding import Finding
    finding = normalize_finding(Finding(
        id="finding-1", source="semgrep", rule_id="sql-injection", title="SQL",
        description="fixture", file="routes/search.ts", line_start=2, line_end=2,
    ), repository_root=tmp_path)
    profile = register_source_artifacts(profile, [finding], tmp_path)
    _, hashes = source_snapshot(profile)
    runtime = RuntimeServiceMap(session_id="session", source_files_sha256=hashes, services={
        "api": RuntimeService(name="api", address="http://api:3000", ready=True,
                              readiness_source="http_probe", allowed_endpoints=["/search", "/other"]),
    })
    return profile, finding, runtime


def action_for(profile, finding, runtime):
    candidate, = verification_candidates({
        "target_profile": profile, "finding": finding, "runtime_services": runtime,
    })
    return ActionProposal(id="binding-action", tool=candidate["tool"], target=profile.id,
                          environment=profile.environment, parameters=candidate["parameters"],
                          purpose="Verify", expected_evidence="Controlled difference",
                          service=candidate["service"], endpoint=candidate["endpoint"],
                          verification_binding=candidate["verification_binding"])


def test_inserted_lines_relocate_exact_anchor_and_keep_route_id(fixture):
    profile, finding, runtime = fixture
    before = resolve_binding(profile, finding).binding
    path = profile.repository_path / "routes/search.ts"
    path.write_text("// added header\n\n" + path.read_text(), encoding="utf-8")
    after = resolve_binding(profile, finding).binding
    assert before.route_id == after.route_id == "search"
    assert after.line_start == before.line_start + 2
    assert after.anchor_sha256 == before.anchor_sha256
    assert after.source_snapshot != before.source_snapshot
    _, runtime.source_files_sha256 = source_snapshot(profile)
    action = action_for(profile, finding, runtime)
    assert action.parameters["line"] == 4
    assert PolicyValidator.from_yaml("policies/default.yaml", target_profile=profile).validate(action).approved


def test_fresh_scan_after_line_shift_needs_no_operator_line_edit(fixture):
    profile, finding, _ = fixture
    path = profile.repository_path / "routes/search.ts"
    path.write_text("\n\n" + path.read_text(), encoding="utf-8")
    fresh = finding.model_copy(update={"provenance": None, "line_start": 4, "line_end": 4})
    fresh = normalize_finding(fresh, repository_root=profile.repository_path)
    result = resolve_binding(profile, fresh)
    assert result.status == "bound" and result.binding.route_id == "search"


def test_caller_is_an_explicit_source_edge(fixture):
    profile, finding, _ = fixture
    caller = finding.model_copy(update={"file": "server.ts", "line_start": 1, "line_end": 1,
                                        "provenance": None})
    result = resolve_binding(profile, caller)
    assert result.status == "bound" and result.binding.handler_id == "api.search"


def test_shared_helper_is_inconclusive_and_does_not_call_model(fixture, monkeypatch):
    profile, finding, _ = fixture
    path = profile.repository_path / "server.ts"
    path.write_text(path.read_text() + "app.get('/other', search())\n", encoding="utf-8")
    route = profile.verification_routes[0].model_copy(update={
        "id": "other", "endpoint": "/other",
        "registration": profile.verification_routes[0].registration.model_copy(
            update={"anchor": "app.get('/other', search())"}),
    })
    profile = profile.model_copy(update={"verification_routes": [*profile.verification_routes, route]})
    resolution = resolve_binding(profile, finding)
    assert resolution.status == "inconclusive" and resolution.candidates == ["other", "search"]
    monkeypatch.setattr("agent.nodes.get_agent_model", lambda: pytest.fail("Ambiguity must stop before model"))
    state = {"target_profile": profile, "finding": finding}
    result = propose_action(state)
    assert result["status"] == "inconclusive"
    assert result["binding_resolution"].candidates == ["other", "search"]
    assert verification_candidates(state) == []


@pytest.mark.parametrize("mutation", ["duplicate", "deleted", "changed", "registration"])
def test_changed_or_ambiguous_source_never_uses_old_line(fixture, mutation):
    profile, finding, _ = fixture
    path = profile.repository_path / "routes/search.ts"
    text = path.read_text()
    if mutation == "duplicate":
        path.write_text("// shifted\n" + text + "\n  return query(req.query.q)\n", encoding="utf-8")
    elif mutation == "deleted":
        path.unlink()
    elif mutation == "changed":
        path.write_text(text.replace("query(req.query.q)", "safeQuery()"), encoding="utf-8")
    else:
        (profile.repository_path / "server.ts").write_text("app.get('/other', search())", encoding="utf-8")
    assert resolve_binding(profile, finding).status == "inconclusive"


@pytest.mark.parametrize("field,value", [("endpoint", "/other"), ("service", "unknown"),
                                        ("tool", "verify_sensitive_directory")])
def test_model_cannot_retarget_binding(fixture, field, value):
    profile, finding, runtime = fixture
    action = action_for(profile, finding, runtime).model_copy(update={field: value})
    with pytest.raises(ValueError):
        validate_action_binding(profile, action)
    assert not PolicyValidator.from_yaml("policies/default.yaml", target_profile=profile).validate(action).approved


def executor_for(tmp_path, profile, action, runtime, sandbox):
    validation = PolicyValidator.from_yaml("policies/default.yaml", target_profile=profile).validate(action)
    assert validation.approved
    approvals = InMemoryApprovalStore()
    approvals.record(action, validation)
    store = JsonExecutionEvidenceStore(tmp_path / "evidence")
    executor = SafeExecutor(approvals=approvals, targets=TargetRegistry([profile]),
                            evidence_store=store, audit_log=JsonlAuditLog(tmp_path / "audit.jsonl"),
                            sandbox=sandbox, run_limiter=RunLimiter(1, 1),
                            policy=SandboxPolicy(backend="process"))
    executor._active_runtime_services = runtime
    return executor, store


def test_source_change_after_approval_cannot_execute(fixture, tmp_path):
    profile, finding, runtime = fixture
    action = action_for(profile, finding, runtime)
    sandbox = SimpleNamespace(run=lambda request: pytest.fail("No execution after source mutation"))
    executor, _ = executor_for(tmp_path, profile, action, runtime, sandbox)
    path = profile.repository_path / "routes/search.ts"
    path.write_text("// shift\n" + path.read_text(), encoding="utf-8")
    result = executor._execute_one(action, "unit-run", runtime.session_id)
    assert result.status == "denied"


def test_runtime_snapshot_mismatch_cannot_execute(fixture, tmp_path):
    profile, finding, runtime = fixture
    action = action_for(profile, finding, runtime)
    sandbox = SimpleNamespace(run=lambda request: pytest.fail("No mismatched runtime execution"))
    executor, _ = executor_for(tmp_path, profile, action, runtime, sandbox)
    runtime.source_files_sha256 = {}
    assert executor._execute_one(action, "unit-run", runtime.session_id).status == "denied"


def test_execution_record_binds_snapshot_endpoint_and_approved_action(fixture, tmp_path):
    profile, finding, runtime = fixture
    action = action_for(profile, finding, runtime)
    facts = dict(action.parameters, mode="search", endpoint="/search", requests=4,
                 response_values_redacted=True, control_repeated=True, probe_repeated=True,
                 observations=[{"status": 200, "valid_json": True, "result_count": n,
                                "authenticated": False} for n in [0, 1, 0, 1]])
    payload = {"schema": "cft.bounded_verification.v1", "scope": "runtime_sql_differential",
               "verdict": "confirmed", "explanation": "Synthetic controlled difference", "facts": facts}
    sandbox = SimpleNamespace(run=lambda request: SandboxResult(
        run_id=request.run_id, exit_code=0, stdout=json.dumps(payload), stderr="",
        timed_out=False, workspace_id="unit", runtime_backend="process"))
    executor, store = executor_for(tmp_path, profile, action, runtime, sandbox)
    result = executor._execute_one(action, "unit-run", runtime.session_id)
    assert result.status == "completed"
    record = store.get_execution(result.evidence_ref)
    assert record["verification_binding"] == action.verification_binding.model_dump(mode="json")
    assert record["action_digest"] == proposal_digest(action)
    evidence = build_evidence(action=action, execution=result, record=record, evidence_loaded=True,
                              artifact_refs=result.artifacts, hypothesis_id="hypothesis",
                              sandbox_session_id=runtime.session_id)
    assert evidence.verdict == "confirmed"
    assert evidence.observation.facts["verification_binding"]["source_snapshot"]
    record["verification_binding"]["source_snapshot"] = "0" * 64
    evidence = build_evidence(action=action, execution=result, record=record, evidence_loaded=True,
                              artifact_refs=result.artifacts, hypothesis_id="hypothesis",
                              sandbox_session_id=runtime.session_id)
    assert evidence.verdict == "inconclusive"


def test_new_operator_profile_resolves_real_juice_sources():
    from pathlib import Path
    root = Path("artifacts/benchmark-target/juice-shop")
    if not root.is_dir():
        pytest.skip("Pinned Juice Shop checkout is an operator prerequisite")
    profile = TargetProfile.from_yaml("targets/juice-verification.yaml", repository_path_override=root)
    from schemas.finding import Finding
    for file, marker, family, expected in [
        ("routes/search.ts", "models.sequelize.query(", "sql-injection", "juice-search"),
        ("routes/login.ts", "models.sequelize.query(", "sql-injection", "juice-login"),
        ("server.ts", "app.use('/ftp', serveIndexMiddleware", "file-exposure", "juice-directory-ftp"),
    ]:
        lines = (root / file).read_text(encoding="utf-8").splitlines()
        line = next(i for i, text in enumerate(lines, 1) if marker in text)
        finding = Finding(id="real-source", source="fixture", rule_id=family, title="Read source",
                          description="Binding acceptance only, not runtime Evidence", file=file,
                          line_start=line, line_end=line)
        result = resolve_binding(profile, finding)
        assert result.status == "bound", result.reason
        assert result.binding.route_id == expected
        assert result.binding.source_files[file] == sha256((root / file).read_bytes()).hexdigest()


def test_deterministic_mode_uses_real_bound_candidate_not_confirming_stub(fixture):
    from schemas.hypothesis import Hypothesis
    profile, finding, runtime = fixture
    model = DeterministicAgentModel()
    state = {"target_profile": profile, "finding": finding, "runtime_services": runtime}
    hypothesis = Hypothesis(id="h", statement="SQL", expected_evidence="Runtime", confidence=0.5)
    plan = model.build_plan(state, model.analyse(state), hypothesis)
    assert plan.steps[0].action.tool == "verify_sql_injection"
    assert plan.steps[0].action.verification_binding.route_id == "search"


def test_provider_plan_receives_only_application_owned_binding(fixture, monkeypatch):
    from schemas.hypothesis import Hypothesis
    profile, finding, runtime = fixture
    model = DeterministicAgentModel()
    state = {"target_profile": profile, "finding": finding, "runtime_services": runtime,
             "max_steps": 2, "iteration_count": 0}
    state["hypothesis"] = Hypothesis(statement="SQL", expected_evidence="Runtime", confidence=0.5)
    state["analysis"] = model.analyse(state)
    plan = model.build_plan(state, state["analysis"], state["hypothesis"])
    plan.steps[0].action.verification_binding = None
    monkeypatch.setattr("agent.nodes.get_agent_model", lambda: SimpleNamespace(build_plan=lambda *a: plan))
    result = propose_action(state)
    assert result["plan_validation"].approved
    assert result["proposed_action"].verification_binding == resolve_binding(profile, finding).binding


def test_source_mutation_during_execution_never_yields_confirmation(fixture, tmp_path):
    profile, finding, runtime = fixture
    action = action_for(profile, finding, runtime)

    def mutate(request):
        path = profile.repository_path / "routes/search.ts"
        path.write_text("// concurrent change\n" + path.read_text(), encoding="utf-8")
        return SandboxResult(run_id=request.run_id, exit_code=0, stdout="{}", stderr="",
                             timed_out=False, workspace_id="unit")

    executor, store = executor_for(tmp_path, profile, action, runtime, SimpleNamespace(run=mutate))
    result = executor._execute_one(action, "unit-run", runtime.session_id)
    assert result.status == "failed"
    assert store.get_execution(result.evidence_ref)["status"] == "failed"


def test_braces_in_regex_templates_and_comments_do_not_change_function_scope(fixture):
    profile, finding, _ = fixture
    path = profile.repository_path / "routes/search.ts"
    path.write_text("export function search () {\n"
                    "  const regexp = /['{}]/; const text = `} ${'{'}`; /* } */\n"
                    "  return query(req.query.q)\n}\n", encoding="utf-8")
    result = resolve_binding(profile, finding)
    assert result.status == "bound" and result.binding.line_start == 3


def test_multiline_registration_and_function_header_do_not_need_line_metadata(fixture):
    profile, finding, _ = fixture
    path = profile.repository_path / "routes/search.ts"
    path.write_text(path.read_text().replace("function search () {", "function\n search (\n) {"), encoding="utf-8")
    (profile.repository_path / "server.ts").write_text("app.get(\n '/search',\n search()\n)\n", encoding="utf-8")
    result = resolve_binding(profile, finding)
    assert result.status == "bound" and result.binding.line_start == 4


def test_malformed_source_is_visible_inconclusive(fixture):
    profile, finding, _ = fixture
    path = profile.repository_path / "server.ts"
    path.write_text("app.get('/search', search(\n", encoding="utf-8")
    result = resolve_binding(profile, finding)
    assert result.status == "inconclusive" and "malformed" in result.reason


def test_ambiguous_artifact_ids_do_not_choose_first(fixture):
    profile, finding, runtime = fixture
    artifact = next(iter(profile.artifacts.values()))
    profile.artifacts["duplicate"] = artifact.model_copy(update={"id": "duplicate"})
    assert verification_candidates({"target_profile": profile, "finding": finding,
                                    "runtime_services": runtime}) == []


def test_runtime_builder_records_operator_source_inventory(fixture):
    from executor.runtime_service_map import RuntimeServiceMapBuilder
    profile, _, _ = fixture
    session = SimpleNamespace(session_id="test", status="ready", collect_state=lambda: {
        "compose_project": "b01-test", "services": [{"Service": "api", "State": "running", "Health": "healthy"}],
    })
    runtime = RuntimeServiceMapBuilder().build(profile, session)
    _, hashes = source_snapshot(profile)
    assert runtime.source_files_sha256 == hashes


@pytest.mark.parametrize("path", ["../outside.ts", "C:/outside.ts", "/outside.ts"])
def test_operator_selector_cannot_name_host_paths(path):
    from schemas.verification_binding import SourceSelector
    with pytest.raises(ValueError):
        SourceSelector(file=path, anchor="function sample () {")


def test_binding_mutation_invalidates_existing_approval(fixture):
    profile, finding, runtime = fixture
    action = action_for(profile, finding, runtime)
    validation = PolicyValidator.from_yaml("policies/default.yaml", target_profile=profile).validate(action)
    approvals = InMemoryApprovalStore()
    approvals.record(action, validation)
    action.verification_binding.source_files["routes/search.ts"] = "0" * 64
    assert approvals.check(action)[0] is False
    assert not PolicyValidator.from_yaml("policies/default.yaml", target_profile=profile).validate(action).approved


def test_missing_source_diagnostic_does_not_expose_host_paths(fixture):
    profile, finding, _ = fixture
    (profile.repository_path / "routes/search.ts").unlink()
    resolution = resolve_binding(profile, finding)
    assert resolution.status == "inconclusive"
    assert str(profile.repository_path) not in resolution.reason


def test_alias_spelling_retains_canonical_route_and_artifact_id(fixture):
    profile, finding, runtime = fixture
    canonical = action_for(profile, finding, runtime)
    alias = finding.model_copy(update={"file": ".\\routes\\search.ts"})
    action = action_for(profile, alias, runtime)
    assert action.parameters["artifact_id"] == canonical.parameters["artifact_id"]
    assert action.verification_binding == canonical.verification_binding


def test_operator_can_bind_shared_helper_outside_service_root(fixture):
    from schemas.verification_binding import SourceSelector
    profile, finding, _ = fixture
    profile.services["api"].root = "routes"
    (profile.repository_path / "lib").mkdir()
    helper = profile.repository_path / "lib/helper.ts"
    helper.write_text("export function shared () {\n  return query(req.query.q)\n}\n", encoding="utf-8")
    route = profile.verification_routes[0].model_copy(update={"sources": [
        *profile.verification_routes[0].sources,
        SourceSelector(file="lib/helper.ts", anchor="export function shared () {", extent="function"),
    ]})
    profile.verification_routes = [route]
    finding = finding.model_copy(update={"file": "lib/helper.ts", "provenance": None})
    assert profile.resolve_service(finding.file) is None
    resolution = resolve_binding(profile, finding)
    assert resolution.status == "bound" and resolution.binding.service == "api"


def test_revoked_endpoint_does_not_keep_its_old_approval(fixture):
    profile, finding, runtime = fixture
    action = action_for(profile, finding, runtime)
    profile.services["api"].runtime_endpoints.remove("/search")
    with pytest.raises(ValueError):
        validate_action_binding(profile, action)
