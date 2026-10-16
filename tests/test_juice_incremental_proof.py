import os
from types import SimpleNamespace
from urllib.parse import parse_qs, urlsplit

import pytest

from executor import juice_incremental_worker as worker
from executor.juice_incremental_fixture import JuiceIncrementalFixture, _canonical_digest
from schemas.action import ActionProposal
from schemas.finding import Finding
from schemas.juice_incremental_proof import (
    JuiceProofBinding,
    JuiceProofProfile,
    JuiceProofRoute,
    ProductPutTrial,
    RoleRegistrationTrial,
    product_put_disposition,
    role_registration_disposition,
)
from schemas.target import TargetProfile
from security.juice_incremental_binding import bind_finding
from validator.validator import PolicyValidator


def digest(value):
    return worker._digest(value)


def test_generation_binding_uses_same_canonical_digest_in_host_and_worker():
    generation = "7f3a1bc9d2e640a1"
    assert _canonical_digest(generation) == worker._digest(generation)


def _incremental_profile(tmp_path):
    for relative in (
        "server.ts", "routes/login.ts", "routes/currentUser.ts", "models/user.ts",
        "lib/insecurity.ts", "models/product.ts",
    ):
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("// fixed test source\n", encoding="utf-8")
    return TargetProfile(
        id="juice-incremental-proof", environment="sandbox", repository_path=tmp_path,
        juice_incremental_proofs=JuiceProofProfile(
            target_commit="5658473cf8814459bf89000ce373b20ed0b4eb37",
            target_image="bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b",
            worker_image="python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4",
            routes=[
                JuiceProofRoute(check_id="role-registration",
                               rule_id="juice.authorization.client-role-setter",
                               source_file="models/user.ts"),
                JuiceProofRoute(check_id="anonymous-product-put",
                               rule_id="juice.authorization.generated-product-put",
                               source_file="server.ts"),
            ],
        ),
    )


def test_juice_proof_candidate_is_source_and_rule_bound(tmp_path):
    from agent.verification import verification_candidates

    profile = _incremental_profile(tmp_path)
    finding = Finding(id="case-1", source="juice_source_detector",
                      rule_id="juice.authorization.client-role-setter",
                      title="role setter", description="role setter", file="models/user.ts")
    binding = bind_finding(profile, finding)
    assert binding is not None
    assert binding.finding_id == finding.id
    assert binding.check_id == "role-registration"
    candidates = verification_candidates({
        "target_profile": profile, "finding": finding, "action_history": [],
    })
    assert len(candidates) == 1
    assert candidates[0]["tool"] == "verify_juice_proof"
    assert candidates[0]["juice_proof_binding"] == binding
    assert bind_finding(profile, finding.model_copy(update={"file": "server.ts"})) is None
    assert bind_finding(profile, finding.model_copy(update={"rule_id": "other-rule"})) is None


def test_registered_juice_profile_pins_the_two_supported_routes():
    profile = TargetProfile.from_yaml("targets/juice-incremental-proof.yaml")
    assert profile.juice_incremental_proofs is not None
    assert {route.check_id for route in profile.juice_incremental_proofs.routes} == {
        "role-registration", "anonymous-product-put",
    }
    assert profile.environment == "sandbox"


def test_juice_proof_validator_requires_fresh_registered_binding(tmp_path):
    profile = _incremental_profile(tmp_path)
    finding = Finding(id="case-2", source="juice_source_detector",
                      rule_id="juice.authorization.generated-product-put",
                      title="product PUT", description="product PUT", file="server.ts")
    binding = bind_finding(profile, finding)
    action = ActionProposal(
        id="juice-proof-action", tool="verify_juice_proof", target=profile.id,
        environment="sandbox", parameters={"check_id": "anonymous-product-put"},
        purpose="Check the registered fixed protocol", expected_evidence="Typed runtime proof",
        juice_proof_binding=binding,
    )
    validator = PolicyValidator.from_yaml(
        "policies/b06.yaml", target_profile=profile,
        capability_policy_file="policies/juice-incremental-proof.yaml",
    )
    assert validator.validate(action).approved
    default_validator = PolicyValidator.from_yaml(
        "policies/b06.yaml", target_profile=profile,
    )
    assert not default_validator.validate(action).approved
    assert not validator.validate(action.model_copy(update={"juice_proof_binding": None})).approved
    tampered = action.model_copy(update={"parameters": {"check_id": "role-registration"}})
    assert not validator.validate(tampered).approved
    (tmp_path / "server.ts").write_text("// changed source\n", encoding="utf-8")
    assert not validator.validate(action).approved


def test_action_proposal_keeps_historical_wire_shape_without_juice_binding():
    action = ActionProposal(
        id="legacy-shape", tool="safe_noop", target="demo", purpose="test",
        expected_evidence="test",
    )
    assert "juice_proof_binding" not in action.model_dump(mode="json")


def test_runtime_evidence_recomputes_verdict_from_persisted_bound_trial():
    import json

    from evidence.interpreter import _juice_proof_evidence
    from executor.approvals import proposal_digest
    from schemas.execution import ExecutionResult

    trial = role_trial(generation_sha256=digest("generation-1"))
    binding = JuiceProofBinding(
        target="juice-incremental-proof", finding_id="JS-AUTHZ-002",
        rule_id="juice.authorization.client-role-setter", source_file="models/user.ts",
        check_id="role-registration", route_sha256="e" * 64,
        source_snapshot_sha256=trial.source_snapshot_sha256,
    )
    action = ActionProposal(
        id="runtime-proof", tool="verify_juice_proof", target=binding.target,
        environment="sandbox", parameters={"check_id": "role-registration"},
        purpose="Run the fixed registration proof", expected_evidence="Server-side role readback",
        juice_proof_binding=binding,
    )
    output = {
        "protocol": "role-registration", "generation": "generation-1",
        "result": {"trial": trial.model_dump(mode="json"), "disposition": "confirmed"},
        "failure_type": None, "cleanup_complete": True,
        "target_source_unchanged": True,
    }
    execution = ExecutionResult(
        run_id="run-1", action_id=action.id, status="completed", exit_code=0,
        stdout=json.dumps(output), evidence_ref="execution-" + "a" * 32,
        audit_ref="audit:run-1",
    )
    record = {
        "stdout": execution.stdout, "action_digest": proposal_digest(action),
        "juice_proof_binding": binding.model_dump(mode="json"),
        "status": "completed", "exit_code": 0, "session_id": "generation-1",
    }
    evidence = _juice_proof_evidence(
        action=action, execution=execution, record=record, evidence_loaded=True,
        artifact_refs=[execution.evidence_ref], hypothesis_id="hypothesis-1",
    )
    assert evidence.verdict == "confirmed"
    assert evidence.observation.facts["proof_binding_valid"] is True

    output["cleanup_complete"] = False
    record["stdout"] = json.dumps(output)
    execution = execution.model_copy(update={"stdout": record["stdout"]})
    evidence = _juice_proof_evidence(
        action=action, execution=execution, record=record, evidence_loaded=True,
        artifact_refs=[execution.evidence_ref], hypothesis_id="hypothesis-1",
    )
    assert evidence.verdict == "inconclusive"


def test_juice_proof_execution_requires_exact_matching_audit(tmp_path):
    from executor.approvals import proposal_digest
    from executor.executor import SafeExecutor
    from executor.sandbox_audit import calculate_sha256_digest
    from schemas.execution import ExecutionResult

    profile = _incremental_profile(tmp_path)
    finding = Finding(id="audit-case", source="juice_source_detector",
                      rule_id="juice.authorization.client-role-setter",
                      title="role setter", description="role setter", file="models/user.ts")
    binding = bind_finding(profile, finding)
    action = ActionProposal(
        id="audit-proof", tool="verify_juice_proof", target=profile.id,
        environment="sandbox", parameters={"check_id": "role-registration"},
        purpose="Run the fixed registration proof", expected_evidence="Independent identity readback",
        juice_proof_binding=binding,
    )
    record = {
        "id": "execution-" + "a" * 32, "type": "executor_result", "created_at": "ignored",
        "run_id": "audit-run", "action_id": action.id, "action_digest": proposal_digest(action),
        "juice_proof_binding": binding.model_dump(mode="json"), "session_id": "generation-1",
        "status": "completed", "exit_code": 0, "stdout": "{}", "stderr": "",
    }
    execution = ExecutionResult(
        run_id="audit-run", action_id=action.id, status="completed", exit_code=0,
        stdout="{}", evidence_ref=record["id"], audit_ref="audit:audit-run",
    )
    audit = {
        "run_id": execution.run_id, "action_id": action.id,
        "proposal_digest": calculate_sha256_digest(action.model_dump()),
        "evidence_digest": calculate_sha256_digest(
            {key: value for key, value in record.items() if key not in {"id", "type", "created_at"}}
        ),
        "session_id": record["session_id"], "status": record["status"],
        "exit_code": record["exit_code"], "tool": action.tool, "target": action.target,
        "runtime_backend": "docker", "network_mode": "internal",
        "evidence_ref": execution.evidence_ref,
    }
    executor_stub = SimpleNamespace(
        read_execution=lambda _ref: record,
        _audit_log=SimpleNamespace(records=lambda: [audit]),
    )
    assert SafeExecutor.read_juice_proof_execution(executor_stub, action, execution) == record

    audit["network_mode"] = "target"
    with pytest.raises(ValueError, match="do not match"):
        SafeExecutor.read_juice_proof_execution(executor_stub, action, execution)


def test_campaign_handoff_and_budget_require_registered_proof_and_complete_reservation(tmp_path):
    from hashlib import sha256

    from pipeline.research_verification import verification_handoff, verify_bound_candidate

    profile = _incremental_profile(tmp_path)
    finding = Finding(id="campaign-proof", source="juice_source_detector",
        rule_id="juice.authorization.generated-product-put", title="product PUT",
        description="product PUT", file="server.ts")
    row, = verification_handoff([finding], (profile,), tmp_path)["checks"]
    assert row["status"] == "ready_for_canonical_verification"
    scope = SimpleNamespace(source_files={relative: SimpleNamespace(
        original_sha256=sha256((tmp_path / relative).read_bytes()).hexdigest())
        for relative in ("server.ts", "models/product.ts", "models/user.ts", "lib/insecurity.ts")})
    for http, wall in ((113, 900), (114, 899)):
        result = verify_bound_candidate(finding=finding, profiles=(profile,), scope=scope,
            repository=tmp_path, output=tmp_path.parent / "not-created", max_http_requests=http,
            worker_image=profile.juice_incremental_proofs.worker_image, remaining_wall_seconds=wall)
        assert result["status"] == "review_pending" and result["requests_reserved"] == 0
        assert not (tmp_path.parent / "not-created").exists()
    unrelated = finding.model_copy(update={"rule_id": "other-rule"})
    assert verification_handoff([unrelated], (profile,), tmp_path)["checks"][0]["status"] == "missing_binding_or_capability"


@pytest.mark.skipif(not os.getenv("CFT_JUICE_PROOF_ACCEPTANCE_CHECKOUT"),
                    reason="Opt-in canonical proof integration on pinned Juice Shop in Docker")
def test_incremental_proofs_through_real_campaign_and_offline_replay(tmp_path):
    from pathlib import Path

    from app.research_campaign import campaign
    from app.research_score import replay_runtime
    from discovery.service import ProjectDiscovery
    from executor.access_fixture import WORKER_IMAGE
    from pipeline.juice_source_detectors import detect_juice_source_candidates
    from schemas.research_campaign import CampaignLimits
    from tools.repository_source import RepositorySource

    checkout = Path(os.environ["CFT_JUICE_PROOF_ACCEPTANCE_CHECKOUT"]).resolve(strict=True)
    profile = TargetProfile.from_yaml("targets/juice-incremental-proof.yaml", repository_path_override=checkout)
    source = RepositorySource(ProjectDiscovery().discover(checkout), research_mode=True)
    findings = [finding for finding in detect_juice_source_candidates(profile, source)
                if bind_finding(profile, finding) is not None]
    assert len(findings) == 2
    root = Path(os.environ.get("CFT_JUICE_PROOF_ACCEPTANCE_OUTPUT", str(tmp_path / "acceptance"))).resolve()
    research_profile = TargetProfile(id="incremental-campaign-acceptance", environment="sandbox",
                                    repository_path=checkout)
    result = campaign(profile=research_profile, configuration={"worker_image": WORKER_IMAGE},
        client=None, output=root / "campaign", source_detector_findings=findings,
        verification_profiles=(profile,), verification_worker_image=WORKER_IMAGE, verification_only=True,
        limits=CampaignLimits(max_questions=1, max_model_calls=1, max_actions=2,
                              wall_seconds=1800, max_http_requests=228))
    assert result["model_calls"] == 0
    assert result["canonical_runtime_review_counts"]["confirmed"] == 2
    assert result["cleanup_verified"] and result["source_unchanged"]
    assert result["http_request_budget_used"] == 228
    replayed = replay_runtime(root)
    assert len(replayed) == 2 and all(row["status"] == "confirmed" for row in replayed)
    assert {row["route_id"] for row in replayed} == {"role-registration", "anonymous-product-put"}


def role_trial(**updates):
    data = {
        "schema_version": "juice.role_registration.trial.v1",
        "generation_sha256": "a" * 64,
        "source_snapshot_sha256": "b" * 64,
        "profile_sha256": "c" * 64,
        "worker_sha256": "d" * 64,
        "baseline_registration_status": 201,
        "baseline_login_status": 200,
        "baseline_identity_status": 200,
        "baseline_identity_sha256": "1" * 64,
        "baseline_role": "customer",
        "candidate_registration_status": 201,
        "candidate_login_status": 200,
        "candidate_identity_status": 200,
        "candidate_identity_present": True,
        "candidate_identity_sha256": "2" * 64,
        "candidate_role": "admin",
        "identities_distinct": True,
        "request_order": [
            "baseline-register", "baseline-login", "baseline-identity",
            "candidate-register", "candidate-login", "candidate-identity",
        ],
        "http_exchanges": 6,
    }
    data.update(updates)
    return RoleRegistrationTrial.model_validate(data)


class RegistrationClient:
    def __init__(self, *, honors_requested_role=True, reject_candidate=False):
        self.requests = 0
        self.next_id = 100
        self.users = {}
        self.sessions = {}
        self.honors_requested_role = honors_requested_role
        self.reject_candidate = reject_candidate

    def request(self, method, path, data=None, token=None):
        self.requests += 1
        if method == "POST" and path == "/api/Users":
            if self.reject_candidate and data["email"].startswith("cft-candidate-"):
                return 403, None
            self.next_id += 1
            role = data.get("role", "customer") if self.honors_requested_role else "customer"
            self.users[data["email"]] = {"id": self.next_id, "email": data["email"], "role": role,
                                          "password": data["password"]}
            return 201, {"data": {"id": self.next_id}}
        if method == "POST" and path == "/rest/user/login":
            user = self.users.get(data["email"])
            if user is None or user["password"] != data["password"]:
                return 401, None
            session = "synthetic-token-" + str(user["id"])
            self.sessions[session] = user
            return 200, {"authentication": {"token": session, "umail": user["email"]}}
        if method == "GET" and path == "/rest/user/whoami?fields=id,email,role":
            user = self.sessions.get(token)
            return 200, {"user": ({key: user[key] for key in ("id", "email", "role")}
                                   if user else {})}
        raise AssertionError((method, path))


def product_trial(**updates):
    data = {
        "schema_version": "juice.product_put.trial.v1",
        "generation_sha256": "a" * 64,
        "source_snapshot_sha256": "b" * 64,
        "profile_sha256": "c" * 64,
        "worker_sha256": "d" * 64,
        "account_registration_status": 201,
        "account_login_status": 200,
        "identity_status": 200,
        "identity_sha256": "1" * 64,
        "identity_role": "customer",
        "positive_create_status": 201,
        "positive_product_id_sha256": "2" * 64,
        "positive_authenticated_put_status": 200,
        "positive_readback_status": 200,
        "positive_mutation_persisted": True,
        "positive_untouched_fields_stable": True,
        "candidate_create_status": 201,
        "candidate_product_id_sha256": "3" * 64,
        "candidate_before_sha256": "4" * 64,
        "anonymous_put_status": 200,
        "candidate_readback_status": 200,
        "candidate_after_sha256": "5" * 64,
        "anonymous_mutation_persisted": True,
        "candidate_untouched_fields_stable": True,
        "anonymous_create_control_status": 401,
        "anonymous_create_control_readback_status": 200,
        "anonymous_create_control_absent": True,
        "request_order": [
            "register", "login", "identity", "positive-create", "positive-read-before",
            "positive-authenticated-put", "positive-read-after", "candidate-create",
            "candidate-read-before", "candidate-anonymous-put", "candidate-read-after",
            "anonymous-create-control", "anonymous-create-control-readback",
        ],
        "http_exchanges": 13,
    }
    data.update(updates)
    return ProductPutTrial.model_validate(data)


class ProductClient(RegistrationClient):
    def __init__(self, *, allows_anonymous_put=True, auth_put_status=200,
                 anonymous_put_status=None, anonymous_put_noop=False):
        super().__init__()
        self.products = {}
        self.next_product_id = 700
        self.allows_anonymous_put = allows_anonymous_put
        self.auth_put_status = auth_put_status
        self.anonymous_put_status = anonymous_put_status
        self.anonymous_put_noop = anonymous_put_noop

    def request(self, method, path, data=None, token=None):
        if path == "/api/Users" or path == "/rest/user/login" or path.startswith("/rest/user/whoami"):
            return super().request(method, path, data, token)
        self.requests += 1
        if method == "POST" and path == "/api/Products":
            if token is None:
                return 401, None
            self.next_product_id += 1
            record = {"id": self.next_product_id, **data}
            self.products[record["id"]] = record
            return 201, {"data": record}
        if method == "GET" and path.startswith("/api/Products?"):
            query = parse_qs(urlsplit(path).query)
            requested_name = query.get("filter", [""])[0]
            from urllib.parse import unquote

            decoded = unquote(requested_name)
            matches = [record.copy() for record in self.products.values()
                       if record["name"] in decoded]
            return 200, {"data": matches}
        parts = path.rstrip("/").split("/")
        if len(parts) == 4 and parts[:3] == ["", "api", "Products"]:
            product_id = int(parts[3])
            record = self.products[product_id]
            if method == "GET":
                return 200, {"data": record.copy()}
            if method == "PUT":
                if token is not None and self.auth_put_status != 200:
                    return self.auth_put_status, None
                if token is None and not self.allows_anonymous_put:
                    return self.anonymous_put_status or 401, None
                if not (token is None and self.anonymous_put_noop):
                    record.update(data)
                return (self.anonymous_put_status or 200 if token is None else self.auth_put_status), {
                    "data": record.copy(),
                }
        raise AssertionError((method, path))


def proof_config(protocol):
    return {
        "protocol_id": protocol,
        "generation": "a" * 16,
        "source_snapshot_sha256": "b" * 64,
        "profile_sha256": "c" * 64,
        "worker_sha256": "d" * 64,
    }


def test_role_registration_trial_confirms_only_persisted_admin_readback():
    client = RegistrationClient()
    envelope = worker.run_role_registration(
        client, proof_config(worker.ROLE_PROTOCOL),
    )
    trial = RoleRegistrationTrial.model_validate(envelope["trial"])
    assert role_registration_disposition(trial) == "confirmed"
    serialized = str(trial.model_dump(mode="json"))
    assert "synthetic-token" not in serialized
    assert all(user["password"] not in serialized for user in client.users.values())


def test_role_registration_ignored_or_rejected_role_is_not_confirmed():
    ignored = RegistrationClient(honors_requested_role=False)
    ignored_trial = RoleRegistrationTrial.model_validate(
        worker.run_role_registration(ignored, proof_config(worker.ROLE_PROTOCOL))["trial"],
    )
    assert role_registration_disposition(ignored_trial) == "rejected"

    blocked = RegistrationClient(reject_candidate=True)
    blocked_trial = RoleRegistrationTrial.model_validate(
        worker.run_role_registration(blocked, proof_config(worker.ROLE_PROTOCOL))["trial"],
    )
    assert role_registration_disposition(blocked_trial) == "rejected"


def test_role_registration_requires_healthy_baseline_and_distinct_identity():
    assert role_registration_disposition(
        role_trial(baseline_role="admin"),
    ) == "inconclusive"
    assert role_registration_disposition(
        role_trial(identities_distinct=False),
    ) == "inconclusive"
    assert role_registration_disposition(
        role_trial(candidate_identity_present=False, candidate_identity_sha256=None),
    ) == "inconclusive"


def test_product_put_requires_separate_readback_and_controls():
    client = ProductClient(allows_anonymous_put=True)
    envelope = worker.run_product_put(client, proof_config(worker.PRODUCT_PROTOCOL))
    trial = ProductPutTrial.model_validate(envelope["trial"])
    assert trial.http_exchanges == 13
    assert product_put_disposition(trial) == "confirmed"
    assert "CFT-J01" not in str(trial.model_dump(mode="json"))
    assert "synthetic-token" not in str(trial.model_dump(mode="json"))


def test_product_put_denial_and_ignored_success_are_distinguished_from_confirmation():
    blocked = ProductClient(allows_anonymous_put=False, anonymous_put_status=403)
    blocked_trial = ProductPutTrial.model_validate(
        worker.run_product_put(blocked, proof_config(worker.PRODUCT_PROTOCOL))["trial"],
    )
    assert product_put_disposition(blocked_trial) == "rejected"

    ignored = ProductClient(allows_anonymous_put=True, anonymous_put_noop=True)
    ignored_trial = ProductPutTrial.model_validate(
        worker.run_product_put(ignored, proof_config(worker.PRODUCT_PROTOCOL))["trial"],
    )
    assert product_put_disposition(ignored_trial) == "rejected"


def test_product_put_control_failure_or_http_200_without_change_is_inconclusive():
    bad_control = ProductClient()
    bad_control.anonymous_create_absent = False
    trial = ProductPutTrial.model_validate(
        worker.run_product_put(bad_control, proof_config(worker.PRODUCT_PROTOCOL))["trial"],
    )
    altered = trial.model_copy(update={
        "anonymous_create_control_status": 201,
        "anonymous_create_control_absent": False,
    })
    assert product_put_disposition(altered) == "inconclusive"

    incomplete = product_trial(positive_mutation_persisted=False)
    assert product_put_disposition(incomplete) == "inconclusive"


def test_protocol_status_mutation_does_not_change_frozen_input_trial():
    frozen = role_trial()
    updated = frozen.model_copy(update={"candidate_role": "customer"})
    assert role_registration_disposition(frozen) == "confirmed"
    assert role_registration_disposition(updated) == "rejected"


@pytest.mark.parametrize("cleanup_complete,source_unchanged", [(False, True), (True, False)])
def test_lab_never_returns_confirmed_when_cleanup_or_source_integrity_fails(
    tmp_path, cleanup_complete, source_unchanged,
):
    class FakeLab(JuiceIncrementalFixture):
        def _prepare(self):
            self.source_files = {"server.ts": "a" * 64}
            self.snapshot_calls = 0

        def _execute_worker(self):
            return {"trial": {"http_exchanges": 6}, "disposition": "confirmed"}

        def _cleanup(self):
            return cleanup_complete

        def _snapshot(self):
            self.snapshot_calls += 1
            if source_unchanged or self.snapshot_calls == 1:
                return self.source_files
            return {"server.ts": "b" * 64}

    target = tmp_path / "target"
    target.mkdir()
    lab = FakeLab(repository=target, output=tmp_path / "out",
                  protocol="role-registration")
    result = lab.run()

    assert result["result"]["pre_cleanup_disposition"] == "confirmed"
    assert result["result"]["disposition"] == "inconclusive"
    assert result["cleanup_complete"] is cleanup_complete
    assert result["target_source_unchanged"] is source_unchanged
