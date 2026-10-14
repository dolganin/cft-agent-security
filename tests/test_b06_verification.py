"""Insufficient facts and provenance must not become terminal B06 verdicts."""
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent.verification import register_source_artifacts, verification_candidates
from evidence.audit import JsonlAuditLog
from evidence.interpreter import build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore, proposal_digest
from executor.b06_verdicts import AUTH_OPERATIONS, evaluate
from executor.sandbox_audit import AuditRecord
from schemas.action import ActionProposal
from schemas.b06_verification import (
    B06PreparationProof,
    B06TrialResult,
    B06VerificationResult,
    FixtureExecutionBinding,
    VerificationExchange,
    profile_digest,
)
from schemas.execution import ExecutionResult
from schemas.finding import Finding
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.target import TargetProfile
from security.verification_binding import digest, resolve_binding, source_snapshot
from validator.validator import PolicyValidator

ROOT = Path(__file__).resolve().parents[1]


def result(tool="verify_redirect_destination", verdict="confirmed"):
    fixture = FixtureExecutionBinding(fixture_id="b06-" + "a" * 20, session_id="b06-" + "a" * 20,
        target="juice-b06-verification", tool=tool, generations=("a" * 16, "b" * 16),
        source_snapshot="c" * 64, profile_sha256="d" * 64)
    trials = []
    for generation in fixture.generations:
        if tool == "verify_redirect_destination":
            exchanges = [VerificationExchange(sequence=i, operation=operation,
                status_code=status, response_bytes=0, location=location,
                location_sha256="e" * 64 if location != "none" else None)
                for i, (operation, status, location) in enumerate((
                    ("positive_redirect", 302, "approved"), ("negative_redirect", 406, "none"),
                    ("probe_redirect", 302 if verdict == "confirmed" else 406,
                     "probe" if verdict == "confirmed" else "none")), 1)]
        else:
            exchanges = []
            for i, operation in enumerate(AUTH_OPERATIONS, 1):
                facts = {"sequence": i, "operation": operation, "status_code": 200, "response_bytes": 0}
                if "identity" in operation or operation == "positive_readback":
                    actor = 2 if operation.startswith(("positive", "other")) else 1
                    facts.update(identity_id=actor, expected_identity_id=actor,
                        identity_sha256=str(actor) * 64, expected_identity_sha256=str(actor) * 64)
                if "login" in operation:
                    facts["login_accepted"] = True
                if operation == "anonymous_change":
                    facts.update(status_code=500, denial="auth_required")
                if operation == "wrong_password_change":
                    facts.update(status_code=401, denial="wrong_current")
                if operation == "old_credential_login":
                    facts.update(status_code=401, login_accepted=False)
                if operation == "other_owner_read":
                    facts.update(owner_id=2, object_sha256="3" * 64, expected_object_sha256="3" * 64)
                exchanges.append(VerificationExchange(**facts))
        preparation = None
        if tool == "verify_auth_reauthentication":
            preparation = B06PreparationProof(fixture_id=fixture.fixture_id, generation=generation,
                source_snapshot=fixture.source_snapshot, context_sha256="7" * 64,
                roles=[{"id": role, "server_user_id": i, "identity_sha256": str(i) * 64,
                        "identity_verified": True, "server_role": "customer"}
                       for i, role in enumerate(("role-a", "role-b"), 1)],
                controls=("availability", "negative-control", "anonymous-identity"),
                owner_id=2, object_sha256="3" * 64, http_exchanges=39)
        trials.append(B06TrialResult(generation=generation, exchanges=exchanges, preparation=preparation,
            http_exchanges=len(exchanges), setup_http_exchanges=39 if tool == "verify_auth_reauthentication" else 0,
            sink_requests=0, redirect_followed=False, destination_dns=False, cleanup_complete=True))
    return B06VerificationResult(binding=fixture, action_digest="f" * 64, trials=trials,
        original_unchanged=True, verdict=verdict, explanation="unit protocol",
        scope="runtime_password_reauthentication" if tool == "verify_auth_reauthentication" else "runtime_redirect_destination")


@pytest.mark.parametrize("tool", ["verify_redirect_destination", "verify_auth_reauthentication"])
def test_complete_controls_and_two_trials(tool):
    assert evaluate(result(tool))[0] == "confirmed"


def test_redirect_rejected_requires_working_controls():
    assert evaluate(result(verdict="rejected"))[0] == "rejected"


def test_auth_rejected_requires_original_credentials_and_preparation():
    value = result("verify_auth_reauthentication")
    for trial in value.trials:
        trial.exchanges[:] = [e.model_copy(update={"status_code": 401}) if e.operation == "omission_change"
            else e.model_copy(update={"status_code": 401, "login_accepted": False}) if e.operation == "new_credential_login"
            else e.model_copy(update={"status_code": 200, "login_accepted": True}) if e.operation == "old_credential_login"
            else e for e in trial.exchanges]
    assert evaluate(value)[0] == "rejected"
    value.trials[0] = value.trials[0].model_copy(update={"preparation": None})
    assert evaluate(value)[0] == "inconclusive"


@pytest.mark.parametrize("change", [
    {"cleanup_complete": False}, {"error": "timeout"}, {"sink_requests": 1},
    {"redirect_followed": True}, {"destination_dns": True},
])
def test_incomplete_trial_cannot_confirm(change):
    value = result()
    value.trials[0] = value.trials[0].model_copy(update=change)
    assert evaluate(value)[0] == "inconclusive"


@pytest.mark.parametrize("tool,operation,change", [
    ("verify_redirect_destination", "positive_redirect", {"status_code": 500}),
    ("verify_redirect_destination", "negative_redirect", {"location": "probe"}),
    ("verify_redirect_destination", "probe_redirect", {"location": "ambiguous"}),
    ("verify_auth_reauthentication", "effect_identity", {"identity_id": 999}),
    ("verify_auth_reauthentication", "old_credential_login", {"login_accepted": True}),
    ("verify_auth_reauthentication", "anonymous_change", {"denial": "none"}),
    ("verify_auth_reauthentication", "other_owner_read", {"object_sha256": "f" * 64}),
])
def test_missing_control_or_effect_cannot_confirm(tool, operation, change):
    value = result(tool)
    trial = value.trials[0]
    trial.exchanges[:] = [e.model_copy(update=change) if e.operation == operation else e for e in trial.exchanges]
    assert evaluate(value)[0] == "inconclusive"


def test_contract_rejects_duplicate_ledger_and_secret_fields():
    value = result().model_dump(mode="json")
    value["trials"][0]["exchanges"][1]["sequence"] = 1
    with pytest.raises(ValidationError):
        B06VerificationResult.model_validate(value)
    value = result().model_dump(mode="json")
    value["password"] = "forbidden-secret"
    with pytest.raises(ValidationError):
        B06VerificationResult.model_validate(value)


@pytest.fixture
def mapped(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "server.ts").write_text("app.get('/redirect', performRedirect())\n")
    (tmp_path / "routes/redirect.ts").write_text("export function performRedirect () { return true }\n")
    profile = TargetProfile.model_validate({"id": "juice-b06-verification", "repository_path": tmp_path,
        "environment": "sandbox", "b06_verification": {}, "runtime": {"type": "operator_b06_fixture"},
        "services": {"juice": {"root": ".", "runtime_endpoints": ["/redirect"]}},
        "verification_routes": [{"id": "redirect", "handler_id": "juice.redirect", "family": "open-redirect",
            "service": "juice", "endpoint": "/redirect", "method": "GET", "tool": "verify_redirect_destination",
            "check": "redirect_destination", "registration": {"file": "server.ts", "anchor": "app.get('/redirect', performRedirect())"},
            "sources": [{"file": "routes/redirect.ts", "anchor": "export function performRedirect () {", "extent": "function"}]}]})
    finding = Finding(id="redirect", source="unit", rule_id="open-redirect", title="redirect",
        description="unit", file="routes/redirect.ts", line_start=1, line_end=1)
    profile = register_source_artifacts(profile, [finding], tmp_path)
    _, hashes = source_snapshot(profile)
    binding = result().binding.model_copy(update={"source_snapshot": digest(hashes), "profile_sha256": profile_digest(profile)})
    runtime = RuntimeServiceMap(session_id=binding.session_id, source_files_sha256=hashes,
        verification_fixtures={binding.tool: binding}, services={"juice": RuntimeService(
            name="juice", address="http://juice:3000", ready=True, readiness_source="http_probe", allowed_endpoints=["/redirect"])})
    candidate, = verification_candidates({"target_profile": profile, "finding": finding, "runtime_services": runtime})
    action = ActionProposal(id="action", target=profile.id, environment="sandbox", tool=binding.tool,
        parameters=candidate["parameters"], verification_binding=candidate["verification_binding"],
        fixture_binding=binding, service="juice", endpoint="/redirect", purpose="unit", expected_evidence="unit")
    validator = PolicyValidator.from_yaml(ROOT / "policies/b06.yaml", target_profile=profile)
    return profile, action, validator


def test_fixture_registry_and_mutation_are_enforced(mapped):
    profile, action, validator = mapped
    assert not validator.validate(action).approved
    validator.fixture_bindings[profile.id] = action.fixture_binding
    validation = validator.validate(action)
    assert validation.approved
    approvals = InMemoryApprovalStore()
    approvals.record(action, validation)
    forged = action.model_copy(update={"fixture_binding": action.fixture_binding.model_copy(update={"generations": ("c" * 16, "d" * 16)})})
    assert not validator.validate(forged).approved
    assert not approvals.check(forged)[0]
    forged = action.model_copy(update={"parameters": {**action.parameters, "url": "http://outside.invalid"}})
    assert not validator.validate(forged).approved
    (profile.repository_path / "routes/redirect.ts").write_text("export function other () {}\n")
    assert not validator.validate(action).approved


def test_evidence_requires_matching_persistent_audit(mapped, tmp_path):
    _, action, _ = mapped
    value = result().model_copy(update={"binding": action.fixture_binding, "action_digest": proposal_digest(action)})
    record = {"run_id": "run", "action_id": action.id, "session_id": action.fixture_binding.session_id,
        "tool": action.tool, "target": action.target, "status": "completed", "exit_code": 0,
        "endpoint": action.endpoint, "action_digest": proposal_digest(action), "policy": {},
        "verification_binding": action.verification_binding.model_dump(mode="json"),
        "fixture_binding": action.fixture_binding.model_dump(mode="json"), "stdout": value.model_dump_json()}
    store = JsonExecutionEvidenceStore(tmp_path / "execution")
    ref, path = store.put_execution(record)
    audit = JsonlAuditLog(tmp_path / "audit.jsonl")
    audit.append(AuditRecord.create(run_id="run", session_id=action.fixture_binding.session_id,
        action_id=action.id, tool=action.tool, target=action.target, status="completed", exit_code=0,
        duration_ms=1, evidence_ref=ref, action_proposal_dict=action.model_dump(mode="json"),
        evidence_dict=record, policy_dict={}, runtime_backend="docker", network_mode="target").to_dict())
    execution = ExecutionResult(run_id="run", action_id=action.id, status="completed", exit_code=0,
        stdout=value.model_dump_json(), evidence_ref=ref, audit_ref="audit:run", artifacts=[path, str(audit.path)])
    kwargs = {"action": action, "execution": execution, "record": store.get_execution(ref),
        "evidence_loaded": True, "artifact_refs": execution.artifacts, "hypothesis_id": "hypothesis",
        "sandbox_session_id": action.fixture_binding.session_id}
    assert build_evidence(**kwargs).verdict == "confirmed"
    audit.path.unlink()
    assert build_evidence(**kwargs).verdict == "inconclusive"


def test_missing_source_route_stays_inconclusive(mapped):
    profile, action, _ = mapped
    finding = Finding(id="other", source="unit", rule_id="code-injection", title="other",
        description="unit", file="routes/redirect.ts", line_start=1)
    assert resolve_binding(profile, finding).status == "inconclusive"
    assert action.fixture_binding.tool == "verify_redirect_destination"


def test_worker_stops_before_probe_after_failed_baseline(monkeypatch):
    from executor.b06_worker import Failure, Protocol
    protocol = Protocol()
    operations = []

    def response(operation, *args, **kwargs):
        operations.append(operation)
        return {"status_code": 401}, b'{}'

    monkeypatch.setattr(protocol, "request", response)
    with pytest.raises(Failure, match="control_failed"):
        protocol.login("baseline_login", {"email": "fixture@example.invalid"}, "disposable")
    assert operations == ["baseline_login"]


def test_worker_rejects_http_200_with_wrong_server_identity(monkeypatch):
    from executor.b06_worker import Failure, Protocol
    protocol = Protocol()
    monkeypatch.setattr(protocol, "request", lambda *args, **kwargs: (
        {"status_code": 200}, b'{"user":{"id":999,"email":"other@example.invalid","role":"customer"}}'))
    with pytest.raises(Failure, match="control_failed"):
        protocol.identity("baseline_identity", {"user_id": 1, "email": "fixture@example.invalid"}, "private")
