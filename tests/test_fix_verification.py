"""Integration at the Validator/Executor/persistence boundary with a fake Docker transport."""
import difflib
import json
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from agent.verification import register_source_artifacts
from evidence.interpreter import build_evidence
from executor import worker
from executor.fix_runtime import DockerFixRuntime
from executor.sandbox import DockerSandbox, SandboxResult
from fix_verification.review import prepare_patch_review
from fix_verification.service import FixVerificationService, original_binding
from fix_verification.workspace import apply_patch, digest, snapshot
from schemas.action import ActionProposal
from schemas.execution import ExecutionResult
from schemas.fix import ProposedPatch
from schemas.report import FinalReport, ReportFinding, VerificationSummary
from schemas.target import TargetFixConfig, TargetProfile, TargetService

SOURCE = "prefix\nunsafe()\nsuffix\n"
PATCHED = SOURCE.replace("unsafe()", "safe()")
COMMIT = "1" * 40
IMAGE = "example.invalid/fix@sha256:" + "a" * 64


def sql_output(action, verdict):
    control = {"status": 200, "valid_json": True, "result_count": 0, "authenticated": False}
    positive = dict(control, result_count=1 if verdict == "confirmed" else 0)
    observations = [control, positive, control, positive]
    if verdict == "inconclusive":
        observations[1] = dict(control, status=500, valid_json=False)
    return json.dumps({"schema": "cft.bounded_verification.v1", "scope": "runtime_sql_differential",
                       "verdict": verdict, "explanation": "Observed repeated SQL probe",
                       "facts": dict(action.parameters, endpoint=action.endpoint, observations=observations)})


def fixture(root):
    (root / "routes").mkdir()
    (root / "routes/search.ts").write_text(SOURCE, encoding="utf-8", newline="\n")
    profile = TargetProfile(id="fixture", repository_path=root, environment="sandbox",
        services={"juice": TargetService(id="juice", type="node", internal_port=3000,
                                        runtime_endpoints=["/rest/products/search"])},
        metadata={"verification.routes/search.ts:2.endpoint": "/rest/products/search",
                  "verification.routes/search.ts:2.check": "sql_interpolation",
                  "verification.routes/search.ts:2.mode": "search"},
        fix_verification=TargetFixConfig(image=IMAGE, service="juice", source_commit=COMMIT))
    finding = ReportFinding(id="f1", source="semgrep", rule_id="sql-injection", title="SQL",
                            file="routes/search.ts", line_start=2)
    profile = register_source_artifacts(profile, [finding], root)
    action = ActionProposal(id="original", tool="verify_sql_injection", target=profile.id,
        environment="sandbox", service="juice", endpoint="/rest/products/search",
        parameters={"artifact_id": profile.artifact_id_for_path(finding.file), "line": 2,
                    "check": "sql_interpolation", "mode": "search"},
        purpose="Verify", expected_evidence="Repeated SQL differential")
    execution = ExecutionResult(run_id="original-run", action_id=action.id, status="completed",
                               exit_code=0, evidence_ref="execution-original", audit_ref="audit:original")
    evidence = build_evidence(action=action, execution=execution,
        record={"status": "completed", "exit_code": 0, "stdout": sql_output(action, "confirmed")},
        evidence_loaded=True, artifact_refs=[], hypothesis_id="h1", sandbox_session_id="s1")
    report = FinalReport(finding_id="f1", finding=finding, status="confirmed", evidence=[evidence],
        verification=VerificationSummary(action_id=action.id, capability=action.tool, target=profile.id,
                                         environment="sandbox", validator_decision="approved"),
        code_context="1: prefix\n2: unsafe()\n3: suffix", explanation="Confirmed", next_step="Fix")
    diff = "".join(difflib.unified_diff(SOURCE.splitlines(True), PATCHED.splitlines(True),
                                      fromfile="a/routes/search.ts", tofile="b/routes/search.ts"))
    proposal = ProposedPatch(finding_id="f1", rationale="Fix", unified_diff=diff)
    client = SimpleNamespace(complete_model=lambda **kwargs: proposal)
    review = prepare_patch_review(client=client, report=report, repository=root, run_id="r1",
                                  editable_start=2, editable_end=2)
    return profile, report, review, action


@pytest.fixture
def harness(tmp_path, monkeypatch):
    root = tmp_path / "target"
    root.mkdir()
    profile, report, review, original = fixture(root)
    state = {"before": "confirmed", "after": "rejected", "failure": None,
             "opened": [], "closed": [], "actions": []}
    monkeypatch.setenv("CFT_SANDBOX_IMAGE", IMAGE)
    monkeypatch.setattr("fix_verification.service.original_commit", lambda _: COMMIT)
    monkeypatch.setattr(DockerFixRuntime, "open", lambda self: state["opened"].append(self.profile.repository_path) or self)
    monkeypatch.setattr(DockerFixRuntime, "close", lambda self: state["closed"].append(self.id) or True)

    def stage(self, request):
        phase = "after" if "\nsafe()\n" in (self.profile.repository_path / review.file).read_text() else "before"
        failed = state["failure"] == (phase, request.parameters["stage"])
        state["actions"].append((phase, request.tool, request.parameters.copy()))
        return SandboxResult(request.run_id, 1 if failed else 0, "stage passed" if not failed else "",
                             "test failure" if failed else "", False, self.id, 1, "docker")
    monkeypatch.setattr(DockerFixRuntime, "run", stage)

    @contextmanager
    def sequence(self, **kwargs):
        # Security checks still go through SafeExecutor, persisted output, interpreter and guard.
        def run(request):
            phase = "after" if any(a[0] == "after" for a in state["actions"]) else "before"
            action = original.model_copy(update={"parameters": request.parameters, "endpoint": request.endpoint})
            state["actions"].append((phase, request.tool, request.parameters.copy()))
            return SandboxResult(request.run_id, 0, sql_output(action, state[phase]), "", False, "fake-docker", 1, "docker")
        yield SimpleNamespace(run=run, runtime_instance_id="fake-docker")
    monkeypatch.setattr(DockerSandbox, "open_sequence", sequence)
    def verify():
        return FixVerificationService().verify(report=report, review=review, profile=profile,
                                               artifact_directory=tmp_path / "artifacts")
    return SimpleNamespace(profile=profile, report=report, review=review, state=state, verify=verify,
                           directory=tmp_path / "artifacts", original=original)


def test_full_chain_preserves_source_and_cleans_workspace(harness):
    before = snapshot(harness.profile.repository_path)
    result = harness.verify()
    assert result.status == "FIXED", (result.explanation, result.stages, result.new_evidence)
    assert result.security_verified and result.applied and result.original_unchanged
    assert result.before_evidence.verdict == "confirmed" and result.after_evidence.verdict == "rejected"
    assert result.before_evidence_sha256 and result.after_evidence_sha256
    assert len(result.stages) == 10 and len(result.new_evidence) == 12
    assert snapshot(harness.profile.repository_path) == before
    assert all(not path.exists() for path in harness.state["opened"])
    assert len(harness.state["closed"]) == 2 and result.cleanup_complete
    checks = [p for _, tool, p in harness.state["actions"] if tool == "verify_sql_injection"]
    assert checks == [harness.original.parameters, harness.original.parameters]
    assert list(harness.directory.rglob("audit.jsonl"))


@pytest.mark.parametrize("before,after,status", [
    ("rejected", "rejected", "INCONCLUSIVE"),
    ("inconclusive", "rejected", "INCONCLUSIVE"),
    ("confirmed", "confirmed", "NOT_FIXED"),
    ("confirmed", "inconclusive", "INCONCLUSIVE"),
])
def test_security_verdicts(harness, before, after, status):
    harness.state.update(before=before, after=after)
    result = harness.verify()
    assert result.status == status and not result.security_verified
    if before != "confirmed":
        assert not result.applied


@pytest.mark.parametrize("stage", ["build", "tests", "start", "smoke"])
def test_required_regression_failure_never_verifies(harness, stage):
    harness.state["failure"] = ("after", stage)
    result = harness.verify()
    assert result.status == "REGRESSION" and not result.security_verified
    assert result.after_evidence is None
    assert result.cleanup_complete


def test_proposal_mutation_after_review_is_rejected(harness):
    harness.review.proposal.unified_diff += "--- a/other.ts\n+++ b/other.ts\n"
    result = harness.verify()
    assert result.status == "REJECTED" and "digest" in result.explanation
    assert not harness.state["opened"]


def test_proposal_replacement_during_before_cannot_change_applied_patch(harness, monkeypatch):
    original = FixVerificationService._phase
    def phase(self, profile, action, stage, artifact, directory, policy_file):
        result = original(self, profile, action, stage, artifact, directory, policy_file)
        if stage == "before":
            harness.review.proposal.unified_diff = "malicious replacement"
        return result
    monkeypatch.setattr(FixVerificationService, "_phase", phase)
    result = harness.verify()
    assert result.status == "FIXED"
    assert result.proposed_patch.unified_diff != "malicious replacement"
    assert result.patch_sha256 == digest(result.proposed_patch.unified_diff.encode())


def test_source_change_after_review_is_rejected(harness):
    (harness.profile.repository_path / harness.review.file).write_text("stale\n")
    result = harness.verify()
    assert result.status == "REJECTED" and "digest" in result.explanation


@pytest.mark.parametrize("mutation", ["second", "traversal", "mode", "command"])
def test_rehashed_malicious_patch_is_still_rejected(harness, mutation):
    proposal = harness.review.proposal
    if mutation == "second":
        proposal.unified_diff += "--- a/other.ts\n+++ b/other.ts\n@@ -1 +1 @@\n-old\n+new\n"
    elif mutation == "traversal":
        proposal.unified_diff = proposal.unified_diff.replace("routes/search.ts", "../search.ts")
    elif mutation == "mode":
        proposal.unified_diff = "old mode 100644\nnew mode 100755\n" + proposal.unified_diff
    else:
        proposal.unified_diff = proposal.unified_diff.replace("+safe()", "+safe()\n+process.exec('curl evil')")
    harness.review.proposal_sha256 = digest(proposal.model_dump_json().encode())
    assert harness.verify().status == "REJECTED"
    assert not harness.state["opened"]


def test_symlink_source_is_rejected(harness, tmp_path):
    path = harness.profile.repository_path / harness.review.file
    path.unlink()
    outside = tmp_path / "outside.ts"
    outside.write_text(SOURCE)
    try:
        path.symlink_to(outside)
    except OSError:
        pytest.skip("Windows symlink creation requires developer mode or privilege")
    assert harness.verify().status == "REJECTED"
    assert outside.read_text() == SOURCE


@pytest.mark.parametrize("field,value", [("endpoint", "/other"), ("mode", "authentication"), ("service", "other")])
def test_original_binding_cannot_change(harness, field, value):
    if field == "service":
        evidence = harness.report.evidence[0]
        harness.report.evidence[0] = evidence.model_copy(update={"scope": evidence.scope.model_copy(update={"service": value})})
    else:
        key = "verification.routes/search.ts:2." + field
        harness.profile.metadata[key] = value
    assert harness.verify().status == "REJECTED"
    assert not harness.state["opened"]


def test_executor_record_tampering_cannot_prove_fix(harness, monkeypatch):
    from evidence.store import JsonExecutionEvidenceStore
    original = JsonExecutionEvidenceStore.get_execution
    def tampered(self, ref):
        record = original(self, ref)
        record["action_id"] = "different"
        return record
    monkeypatch.setattr(JsonExecutionEvidenceStore, "get_execution", tampered)
    result = harness.verify()
    assert result.status == "INCONCLUSIVE" and not result.security_verified
    assert "mismatch" in result.explanation and harness.state["closed"]


def test_unknown_host_command_interface_is_removed(harness):
    with pytest.raises(TypeError):
        FixVerificationService().verify(report=harness.report, proposal=harness.review.proposal,
                                        target=harness.profile.repository_path, checks=[])


def test_patch_apply_is_data_only_and_exact(tmp_path):
    _profile, _report, review, _ = fixture(tmp_path)
    before = snapshot(tmp_path)
    result = apply_patch(tmp_path, review.proposal.unified_diff, review.file)
    assert result == digest(PATCHED.encode())
    assert snapshot(tmp_path).keys() == before.keys()
    assert (tmp_path / review.file).read_text() == PATCHED


def test_original_evidence_requires_exact_binding(harness):
    action = original_binding(harness.report, harness.profile)
    assert action.parameters == harness.original.parameters


def test_no_configuration_is_inconclusive(harness):
    harness.profile.fix_verification = None
    result = harness.verify()
    assert result.status == "INCONCLUSIVE" and not result.security_verified


def test_commit_mismatch_rejected(harness, monkeypatch):
    monkeypatch.setattr("fix_verification.service.original_commit", lambda _: "2" * 40)
    assert harness.verify().status == "REJECTED"


def test_unstructured_confirmed_output_is_not_evidence(harness, monkeypatch):
    monkeypatch.setattr(DockerFixRuntime, "run", lambda self, req: SandboxResult(
        req.run_id, 0, "confirmed", "", False, self.id, 1, "docker"))
    harness.state["before"] = "inconclusive"
    assert not harness.verify().security_verified


def test_runtime_stage_contract_rejects_arbitrary_commands(harness):
    from validator.validator import PolicyValidator
    validator = PolicyValidator.from_yaml("policies/default.yaml", target_profile=harness.profile)
    action = harness.original.model_copy(update={"tool": "fix_target_stage", "service": None,
        "endpoint": None, "parameters": {"adapter": "juice_node_v1", "stage": "tests", "argv": ["python", "-c", "evil"]}})
    assert not validator.validate(action).approved


def test_demo_fix_api_requires_review_and_persists_separate_result(harness):
    from fastapi.testclient import TestClient

    from app.demo import PATCH_REVIEW_POLICY, create_demo_app
    result = harness.verify()
    directory = harness.directory
    calls = []
    def verify(**kwargs):
        calls.append(kwargs)
        return result
    service = SimpleNamespace(
        close=lambda: None,
        get_run=lambda _: SimpleNamespace(target_id="juice-presentation", status="completed"),
        get_report=lambda *args: harness.report,
        store=SimpleNamespace(artifact_dir=lambda _: directory),
        registry=SimpleNamespace(get=lambda _: SimpleNamespace(profile=harness.profile)),
    )
    with TestClient(create_demo_app(service, fix_service=SimpleNamespace(verify=verify))) as api:
        assert api.get("/demo/runs/r1/fix-verification").json() is None
        assert api.post("/demo/runs/r1/fix-verification").status_code == 409
        review = harness.review.model_copy(update={"validation_policy": PATCH_REVIEW_POLICY})
        (directory / "patch-review.json").write_text(review.model_dump_json(), encoding="utf-8")
        response = api.post("/demo/runs/r1/fix-verification", json={"argv": ["evil"], "endpoint": "/other"})
        assert response.status_code == 200 and response.json()["security_verified"] is True
        assert api.get("/demo/runs/r1/fix-verification").json() == response.json()
        assert "argv" not in calls[0] and "endpoint" not in calls[0]
        assert harness.report.status == "confirmed"
        assert (directory / "fix-verification.json").is_file()


def test_sql_rejection_requires_healthy_repeated_answers(monkeypatch):
    from evidence.interpreter import _bounded_result_matches_action
    action = ActionProposal(id="sql", tool="verify_sql_injection", target="test", environment="sandbox",
        service="juice", endpoint="/search", parameters={"artifact_id": "source", "line": 1,
        "check": "sql_interpolation", "mode": "search"}, purpose="check", expected_evidence="structured")
    for status, verdict in [(200, "rejected"), (500, "inconclusive")]:
        monkeypatch.setattr(worker, "_json_probe", lambda *a, status=status: {"status": status, "valid_json": status == 200,
                            "result_count": 0, "authenticated": False})
        code, out, _ = worker._verify_sql_injection("http://juice:3000/search", action.parameters, 2, None)
        from schemas.security_tools import BoundedVerificationResult
        payload = BoundedVerificationResult.model_validate_json(out)
        assert code == 0 and payload.verdict == verdict
        assert _bounded_result_matches_action(payload, action)
