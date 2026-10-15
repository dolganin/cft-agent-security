import json
import os
from hashlib import sha256
from pathlib import Path

import pytest

from evaluation.b05_offline import verify_artifacts
from evidence.access_control import evaluate_access_check
from schemas.access_verification import (
    AccessCheckTrace,
    AccessExchange,
    AccessGenerationEvidence,
    DatabaseOwnershipProof,
)
from schemas.action import ActionProposal
from schemas.finding import Finding
from schemas.target import TargetProfile
from schemas.verification_binding import VerificationBinding
from security.access_verification import (
    ACCESS_CHECKS,
    binding_id,
    is_access_check_supported,
    validate_access_action,
)
from security.verification_binding import resolve_binding
from validator.validator import PolicyValidator

PROFILE_FILE = Path(__file__).resolve().parents[1] / "targets/juice-b05-access-fixture.yaml"
TARGET_ROOT = Path(os.environ.get(
    "CFT_B05_TARGET_REPOSITORY",
    Path(__file__).resolve().parents[1] / "artifacts/benchmark-target/juice-shop",
))


def _b05_validator(profile):
    return PolicyValidator.from_yaml(
        "policies/default.yaml", target_profile=profile,
        capability_policy_file="policies/b05-access.yaml",
    )


@pytest.fixture
def bound_action(tmp_path):
    repository = TARGET_ROOT
    if not repository.is_dir():
        pytest.skip("Pinned Juice Shop checkout is an operator prerequisite; set CFT_B05_TARGET_REPOSITORY")
    profile = TargetProfile.from_yaml(PROFILE_FILE, repository_path_override=repository)
    actions = {}
    for check_id, registration in ACCESS_CHECKS.items():
        route = next(item for item in profile.verification_routes if item.id == registration.route_id)
        source_selector = next(
            (item for item in route.sources if item.file != route.registration.file),
            route.registration,
        )
        lines = (repository / source_selector.file).read_text(encoding="utf-8").splitlines()
        line = next(index for index, text in enumerate(lines, 1) if source_selector.anchor in text)
        finding = Finding(id="finding-" + check_id, source="operator", rule_id="idor",
                          title="Access control", description="B05 binding fixture",
                          file=source_selector.file, line_start=line, line_end=line)
        resolution = resolve_binding(profile, finding)
        assert resolution.status == "bound", resolution.reason
        action = ActionProposal(
            id="action-" + check_id, tool="verify_access_control", target=profile.id,
            environment=profile.environment, parameters={"check_id": check_id},
            purpose="Run the one registered access check.", expected_evidence="Bound controls and repeat.",
            service="juice", endpoint=registration.endpoint,
            verification_binding=resolution.binding,
        )
        actions[check_id] = (profile, action)
    return actions


def _generation(index: int) -> AccessGenerationEvidence:
    value = lambda x: sha256(x.encode()).hexdigest()
    return AccessGenerationEvidence(
        generation_sha256=value(f"generation-{index}"),
        role_a_identity_sha256=value(f"role-a-{index}"),
        role_b_identity_sha256=value(f"role-b-{index}"),
        role_a_identity_verified=True, role_b_identity_verified=True,
        ownership_verified=True, permission_relation_verified=True,
        b04_fixture_ready=True, reset_from_previous_verified=True,
    )


def _read_trace(action, probe_status=200):
    rows = [
        ("oc-r-read", "GET", "role-b", "basket-b", "basket-read", 200, True, True),
        ("nc-r-deny", "GET", "role-a", "negative-control-b", "address-read", 400, False, False),
        ("sc-r-self", "GET", "role-a", "basket-a", "basket-read", 200, True, True),
        ("baseline-r-digest", "GET", "role-b", "basket-b", "basket-read", 200, True, True),
        ("probe-r-t1", "GET", "role-a", "basket-b", "basket-read", probe_status, probe_status == 200, probe_status == 200),
        ("probe-r-t2", "GET", "role-a", "basket-b", "basket-read", probe_status, probe_status == 200, probe_status == 200),
        ("cleanup-r-verify", "GET", "role-b", "basket-b", "basket-read", 200, True, True),
    ]
    exchanges = [AccessExchange(exchange_id=name, index=i, method=method, role_id=role,
                                object_ref=obj, endpoint_id=endpoint, status=status,
                                private_marker_match=marker, owner_data_present=owner)
                for i, (name, method, role, obj, endpoint, status, marker, owner) in enumerate(rows, 1)]
    controls = {key: True for key in (
        "owner_availability", "negative_control", "attacker_self", "ownership",
        "permission_relation", "cleanup_baseline",
    )}
    return AccessCheckTrace(
        check_id="juice-basket-own-read-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment, operation="own_read",
        endpoint_id="basket-read", method="GET", object_ref="basket-b", controls=controls,
        generations=[_generation(1), _generation(2)], exchanges=exchanges,
        exchange_count=7, request_budget=7, reset_complete=True, cleanup_complete=True,
        integrity_verified=True,
    )


def _write_trace(action, effect="changed", readback_status=200):
    marker = "CFT-B05-FIXED-CITY-MARKER"
    baseline = "Fixture"
    rows = [
        ("oc-w-update", "PUT", "role-b", "address-b", "address-write", 200, "unknown", False, digest_value(marker)),
        ("oc-w-readback", "GET", "role-b", "address-b", "address-read", 200, "unknown", True, digest_value(marker)),
        ("sc-w-self", "PUT", "role-a", "address-a", "address-write", 200, "unknown", False, digest_value(marker)),
        ("nc-w-deny", "PUT", "role-a", "negative-control-b", "address-write", 400, "unknown", False, None),
        ("nc-w-readback", "GET", "role-b", "negative-control-b", "address-read", 200, "unchanged", True, digest_value(baseline)),
        ("baseline-w-digest", "GET", "role-b", "write-candidate-b", "address-read", 200, "unknown", False, digest_value(baseline)),
        ("probe-w-t1", "PUT", "role-a", "write-candidate-b", "address-write", 200, effect, False, digest_value(marker) if effect == "changed" else None),
        ("probe-w-t1-readback", "GET", "role-b", "write-candidate-b", "address-read", readback_status, effect, True, digest_value(marker) if effect == "changed" else digest_value(baseline)),
        ("probe-w-t2", "PUT", "role-a", "write-candidate-b", "address-write", 200, effect, False, digest_value(marker) if effect == "changed" else None),
        ("probe-w-t2-readback", "GET", "role-b", "write-candidate-b", "address-read", readback_status, effect, True, digest_value(marker) if effect == "changed" else digest_value(baseline)),
        ("cleanup-w-verify", "GET", "role-b", "write-candidate-b", "address-read", 200, "unknown", False, digest_value(baseline)),
    ]
    exchanges = [AccessExchange(exchange_id=name, index=i, method=method, role_id=role,
                                object_ref=obj, endpoint_id=endpoint, status=status,
                                mutation_effect=mutation, independent_readback=independent,
                                owner_data_present=(True if method == "GET" and status == 200 else None),
                                value_sha256=value,
                                private_marker_match=name in {"baseline-w-digest", "cleanup-w-verify"})
                for i, (name, method, role, obj, endpoint, status, mutation, independent, value)
                in enumerate(rows, 1)]
    controls = {key: True for key in (
        "owner_write_control", "attacker_self", "negative_control", "ownership",
        "permission_relation", "cleanup_baseline",
    )}
    return AccessCheckTrace(
        check_id="juice-address-own-write-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment, operation="own_write",
        endpoint_id="address-write", method="PUT", object_ref="write-candidate-b",
        mutation_field="city", mutation_value_sha256=digest_value(marker), controls=controls,
        generations=[_generation(1), _generation(2), _generation(3)], exchanges=exchanges,
        exchange_count=11, request_budget=12, reset_complete=True, cleanup_complete=True,
        integrity_verified=True,
    )


def digest_value(value):
    import json
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _basket_write_v2_trace(action):
    rows = [
        ("oc-b-update", "PUT", "role-b", "basket-write-control-b", "basket-write"),
        ("oc-b-readback", "GET", "role-b", "basket-write-control-b", "basket-read"),
        ("sc-a-update", "PUT", "role-a", "basket-write-self-a", "basket-write"),
        ("sc-a-readback", "GET", "role-a", "basket-write-self-a", "basket-read"),
        ("nc-a-update", "PUT", "role-a", "basket-write-negative-b", "basket-write"),
        ("nc-b-readback", "GET", "role-b", "basket-write-negative-b", "basket-read"),
        ("baseline-b-state", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
        ("probe-b-t1", "PUT", "role-a", "basket-write-candidate-b", "basket-write"),
        ("probe-b-t1-readback", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
        ("probe-b-t2", "PUT", "role-a", "basket-write-candidate-b", "basket-write"),
        ("probe-b-t2-readback", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
        ("cleanup-b-baseline", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
    ]
    exchanges = [AccessExchange(
        exchange_id=name, index=index, method=method, role_id=role, object_ref=obj,
        endpoint_id=endpoint, status=403 if name == "nc-a-update" else 200,
        owner_data_present=method == "GET", independent_readback=method == "GET",
    ) for index, (name, method, role, obj, endpoint) in enumerate(rows, 1)]
    exact = [1, 3, 8, 10]
    for index in exact:
        exchanges[index] = exchanges[index].model_copy(update={
            "changed_fields": ["quantity", "updatedAt"], "timestamp_update_proven": True,
            "created_at_unchanged": True, "relationships_unchanged": True,
            "other_items_unchanged": True, "mutation_effect": "changed",
            "value_sha256": digest_value(2),
        })
    for index in (0, 2, 7, 9):
        exchanges[index] = exchanges[index].model_copy(update={"mutation_effect": "changed"})
    exchanges[5] = exchanges[5].model_copy(update={
        "changed_fields": [], "relationships_unchanged": True,
        "other_items_unchanged": True, "mutation_effect": "unchanged",
    })
    exchanges[6] = exchanges[6].model_copy(update={"changed_fields": []})
    exchanges[11] = exchanges[11].model_copy(update={
        "changed_fields": [], "relationships_unchanged": True, "other_items_unchanged": True,
    })
    return AccessCheckTrace(
        check_id="juice-basket-own-write-v2", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment, operation="own_write",
        endpoint_id="basket-write", method="PUT", object_ref="basket-write-candidate-b",
        mutation_field="quantity", mutation_value_sha256=digest_value(2),
        allowed_technical_fields=["updatedAt"],
        controls={key: True for key in (
            "owner_write_control", "attacker_self", "negative_control", "ownership",
            "permission_relation", "cleanup_baseline",
        )},
        generations=[_generation(i) for i in range(1, 4)], exchanges=exchanges,
        exchange_count=12, request_budget=12, reset_complete=True, cleanup_complete=True,
        integrity_verified=True,
    )


def _ownership_transfer_trace(action):
    rows = [
        ("oc-t-owner", "GET", "role-b", "address-b", "address-read"),
        ("nc-t-deny", "GET", "role-a", "negative-control-b", "address-read"),
        ("nc-t-owner", "GET", "role-b", "negative-control-b", "address-read"),
        ("probe-t-transfer", "PUT", "role-a", "address-b", "address-write"),
        ("probe-t-attacker-read", "GET", "role-a", "address-b", "address-read"),
        ("probe-t-owner-read", "GET", "role-b", "address-b", "address-read"),
        ("oc-t-owner-t2", "GET", "role-b", "address-b", "address-read"),
        ("nc-t-deny-t2", "GET", "role-a", "negative-control-b", "address-read"),
        ("nc-t-owner-t2", "GET", "role-b", "negative-control-b", "address-read"),
        ("probe-t-transfer-t2", "PUT", "role-a", "address-b", "address-write"),
        ("probe-t-attacker-read-t2", "GET", "role-a", "address-b", "address-read"),
        ("probe-t-owner-read-t2", "GET", "role-b", "address-b", "address-read"),
    ]
    exchanges = [AccessExchange(
        exchange_id=name, index=index, method=method, role_id=role, object_ref=obj,
        endpoint_id=endpoint, status=403 if name.startswith("nc-t-deny") else 200,
        owner_data_present=True, independent_readback=method == "GET",
        observed_owner_role=("role-b" if name.startswith(("oc-t-owner", "nc-t-owner")) else
                             "role-a" if name.startswith("probe-t-attacker") else None),
    ) for index, (name, method, role, obj, endpoint) in enumerate(rows, 1)]
    for index in (3, 9):
        exchanges[index] = exchanges[index].model_copy(update={"mutation_effect": "changed"})
    generations = [_generation(1), _generation(2)]
    proofs = []
    for generation in generations:
        for phase, owner, user_id in (("before", "role-b", 26), ("after", "role-a", 25)):
            proofs.append(DatabaseOwnershipProof(
                generation_sha256=generation.generation_sha256, object_ref="address-b",
                phase=phase, object_id=808, owner_user_id=user_id, owner_role=owner, row_found=True,
            ))
    return AccessCheckTrace(
        check_id="juice-address-ownership-transfer-v1", binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment,
        operation="ownership_transfer", endpoint_id="address-write", method="PUT",
        object_ref="address-b", controls={key: True for key in (
            "owner_availability", "negative_control", "attacker_identity", "ownership",
            "permission_relation",
        )}, generations=generations, exchanges=exchanges,
        ownership_proofs=proofs, exchange_count=12, request_budget=12,
        reset_complete=True, cleanup_complete=True, integrity_verified=True,
    )


@pytest.mark.parametrize("parameters", [
    {"check_id": "unknown"},
    {"check_id": "juice-basket-own-read-v1", "url": "http://example.invalid"},
    {"check_id": "juice-basket-own-read-v1", "object_id": "other"},
    {"check_id": "juice-basket-own-read-v1", "actor": "role-b"},
    {"check_id": "juice-basket-own-read-v1", "session": "secret"},
    {"check_id": "juice-address-own-write-v1", "field": "UserId"},
    {"check_id": "juice-address-own-write-v1", "value": "arbitrary"},
])
def test_validator_denies_unregistered_b05_parameters(bound_action, parameters):
    profile, action = bound_action["juice-basket-own-read-v1"]
    if parameters["check_id"] == "juice-address-own-write-v1":
        profile, action = bound_action["juice-address-own-write-v1"]
    result = _b05_validator(profile).validate(
        action.model_copy(update={"parameters": parameters}),
    )
    assert not result.approved


def test_validator_denies_endpoint_method_route_mutation_and_stale_or_ambiguous_binding(bound_action):
    profile, action = bound_action["juice-basket-own-read-v1"]
    validator = _b05_validator(profile)
    assert not validator.validate(action.model_copy(update={"endpoint": "/rest/basket/999"})).approved
    stale = action.verification_binding.model_copy(update={"source_snapshot": "0" * 64})
    assert not validator.validate(action.model_copy(update={"verification_binding": stale})).approved
    duplicate = profile.verification_routes[0].model_copy(update={"id": "ambiguous-duplicate"})
    profile.verification_routes.append(duplicate)
    assert not _b05_validator(profile).validate(action).approved


def test_binding_rejects_method_and_check_substitution(bound_action):
    profile, action = bound_action["juice-basket-own-read-v1"]
    binding = action.verification_binding.model_copy(update={"method": "PUT"})
    with pytest.raises(ValueError):
        validate_access_action(profile, action.model_copy(update={"verification_binding": binding}))


def test_candidate_checks_are_not_model_offered_and_have_fixed_validator_bindings(bound_action):
    for check_id in ("juice-basket-own-write-v2", "juice-basket-own-write-v3",
                     "juice-address-ownership-transfer-v1"):
        profile, action = bound_action[check_id]
        assert not is_access_check_supported(check_id)
        assert _b05_validator(profile).validate(action).approved
        with pytest.raises(ValueError):
            validate_access_action(profile, action.model_copy(update={
                "parameters": {"check_id": check_id, "url": "http://example.invalid"},
            }))


def test_basket_write_v2_requires_exact_delta_and_all_independent_controls(bound_action):
    action = bound_action["juice-basket-own-write-v2"][1]
    trace = _basket_write_v2_trace(action)
    assert evaluate_access_check(trace, action).verdict == "confirmed"
    unexpected = list(trace.exchanges)
    unexpected[8] = unexpected[8].model_copy(update={"changed_fields": ["quantity", "updatedAt", "ProductId"]})
    assert evaluate_access_check(trace.model_copy(update={"exchanges": unexpected}), action).verdict == "inconclusive"
    failed_control = dict(trace.controls, negative_control=False)
    assert evaluate_access_check(trace.model_copy(update={"controls": failed_control}), action).verdict == "inconclusive"
    missing_readback = [item for item in trace.exchanges if item.exchange_id != "probe-b-t2-readback"]
    assert evaluate_access_check(trace.model_copy(update={
        "exchanges": missing_readback, "exchange_count": len(missing_readback),
    }), action).verdict == "inconclusive"



def _basket_write_v3_trace(verdict="confirmed"):
    from schemas.access_verification import AccessBasketItemState, AccessBasketSnapshot
    h = lambda value: sha256(value.encode()).hexdigest()
    schedule = [
        ("oc-b-update", "PUT", "role-b", "basket-write-control-b", "basket-write", 0),
        ("oc-b-readback", "GET", "role-b", "basket-write-control-b", "basket-read", 0),
        ("authn-anon-put", "PUT", None, "basket-write-candidate-b", "basket-write", 0),
        ("authn-b-readback", "GET", "role-b", "basket-write-candidate-b", "basket-read", 0),
        ("sc-a-update", "PUT", "role-a", "basket-write-self-a", "basket-write", 0),
        ("sc-a-readback", "GET", "role-a", "basket-write-self-a", "basket-read", 0),
        ("probe-b-t1", "PUT", "role-a", "basket-write-candidate-b", "basket-write", 0),
        ("probe-b-t1-readback", "GET", "role-b", "basket-write-candidate-b", "basket-read", 0),
        ("baseline-b-t2", "GET", "role-b", "basket-write-candidate-b", "basket-read", 1),
        ("probe-b-t2", "PUT", "role-a", "basket-write-candidate-b", "basket-write", 1),
        ("probe-b-t2-readback", "GET", "role-b", "basket-write-candidate-b", "basket-read", 1),
        ("cleanup-b-baseline", "GET", "role-b", "basket-write-candidate-b", "basket-read", 2),
    ]
    generations = []
    for i in range(3):
        generations.append(AccessGenerationEvidence(
            generation_sha256=h(f"gen{i}"), role_a_identity_sha256=h(f"a{i}"),
            role_b_identity_sha256=h(f"b{i}"), role_a_identity_verified=True,
            role_b_identity_verified=True, role_a_user_id=100 + i * 2,
            role_b_user_id=101 + i * 2, permission_profile_sha256=h(f"permissions{i}"),
            ownership_verified=True, permission_relation_verified=True, b04_fixture_ready=True,
            reset_from_previous_verified=True, role_a_session_binding_sha256=h(f"as{i}"),
            role_b_session_binding_sha256=h(f"bs{i}"),
        ))
    ref_product = {
        "basket-write-candidate-b": 2, "basket-write-control-b": 3,
        "basket-write-negative-b": 4, "basket-write-default-b": 1,
    }
    snapshots = []
    phases = [
        ("baseline-t1", "oc-b-readback", 0, False),
        ("after-authn", "authn-b-readback", 0, False),
        ("probe-t1-readback", "probe-b-t1-readback", 0, verdict == "confirmed"),
        ("baseline-t2", "baseline-b-t2", 1, False),
        ("probe-t2-readback", "probe-b-t2-readback", 1, verdict == "confirmed"),
        ("cleanup", "cleanup-b-baseline", 2, False),
    ]
    for phase, exchange_id, gi, changed in phases:
        gen = generations[gi]
        basket_identity = h(f"basket{gi}")
        items = []
        for ref, product in ref_product.items():
            candidate = ref == "basket-write-candidate-b"
            quantity = (2 if (changed and candidate) or ref == "basket-write-default-b"
                        or (ref == "basket-write-control-b" and gi == 0)
                        else 1)
            updated = "2026-10-14T00:00:02+00:00" if changed and candidate else "2026-10-14T00:00:00+00:00"
            state = {
                "object_ref": ref, "object_identity_sha256": h(f"{gi}:{ref}"),
                "parent_basket_identity_sha256": basket_identity, "product_id": product,
                "owner_role_id": "role-b", "owner_identity_sha256": gen.role_b_identity_sha256,
                "quantity": quantity, "created_at": "2026-10-13T00:00:00+00:00",
                "updated_at": updated, "membership_verified": True,
            }
            items.append(AccessBasketItemState(**state, state_sha256=digest_value(state)))
        snapshot = {
            "phase": phase, "generation_sha256": gen.generation_sha256,
            "exchange_id": exchange_id, "reader_identity_sha256": gen.role_b_identity_sha256,
            "reader_session_binding_sha256": gen.role_b_session_binding_sha256,
            "basket_identity_sha256": basket_identity, "basket_owner_user_id": gen.role_b_user_id,
            "basket_owner_identity_sha256": gen.role_b_identity_sha256,
            "items": [item.model_dump(mode="json") for item in items],
        }
        snapshots.append(AccessBasketSnapshot(**snapshot, snapshot_sha256=digest_value(snapshot)))
    events = []
    for index, (name, method, role, obj, endpoint, gi) in enumerate(schedule, 1):
        gen = generations[gi]
        item_identity = h(f"{gi}:{obj}")
        parent = h(f"basket{gi}") if obj != "basket-write-self-a" else h(f"basket-a{gi}")
        actor_kind = "anonymous" if role is None else "authenticated"
        identity = None if role is None else (gen.role_a_identity_sha256 if role == "role-a" else gen.role_b_identity_sha256)
        session = None if role is None else (gen.role_a_session_binding_sha256 if role == "role-a" else gen.role_b_session_binding_sha256)
        request = digest_value({
            "method": method, "endpoint_id": endpoint, "object_ref": obj,
            "object_identity_sha256": item_identity,
            "parent_basket_identity_sha256": parent,
            "body": {"quantity": 2} if method == "PUT" else None,
        })
        status = 401 if name == "authn-anon-put" else 200
        fields = []
        changed_read = name in {"oc-b-readback", "sc-a-readback"} or (
            verdict == "confirmed" and name in {"probe-b-t1-readback", "probe-b-t2-readback"})
        if changed_read:
            fields = ["quantity", "updatedAt"]
        events.append(AccessExchange(
            exchange_id=name, index=index, role_id=role, actor_kind=actor_kind,
            object_ref=obj, method=method, endpoint_id=endpoint, status=status,
            owner_data_present=(True if method == "GET" else None),
            mutation_effect=("changed" if verdict == "confirmed" and name.startswith("probe-b-t") else "unknown"),
            independent_readback=method == "GET", changed_fields=fields,
            timestamp_update_proven=(True if changed_read else None),
            created_at_unchanged=(True if changed_read else None),
            relationships_unchanged=(True if method == "GET" else None),
            other_items_unchanged=(True if method == "GET" else None),
            generation_sha256=gen.generation_sha256, actor_identity_sha256=identity,
            actor_session_binding_sha256=session, request_sha256=request,
            object_identity_sha256=item_identity, parent_basket_identity_sha256=parent,
        ))
    return AccessCheckTrace(
        check_id="juice-basket-own-write-v3", binding_id=h("binding"),
        source_snapshot_digest=h("source"), target="juice-access-fixture", environment="sandbox",
        operation="own_write", endpoint_id="basket-write", method="PUT",
        object_ref="basket-write-candidate-b", mutation_field="quantity",
        mutation_value_sha256=digest_value(2), allowed_technical_fields=["updatedAt"],
        controls={key: True for key in ("owner_write_control", "attacker_self",
            "authentication_control", "ownership", "permission_relation", "non_interference",
            "repeat_reset", "cleanup_baseline")}, generations=generations, exchanges=events,
        basket_snapshots=snapshots, exchange_count=12, request_budget=12,
        reset_complete=True, cleanup_complete=True, integrity_verified=True,
    )


def test_basket_write_v3_requires_identity_bound_exact_repeated_state_deltas():
    trace = _basket_write_v3_trace("confirmed")
    assert evaluate_access_check(trace).verdict == "confirmed"
    rejected = _basket_write_v3_trace("rejected")
    assert evaluate_access_check(rejected).verdict == "rejected"
    events = list(trace.exchanges)
    events[6] = events[6].model_copy(update={"actor_session_binding_sha256": "0" * 64})
    assert evaluate_access_check(trace.model_copy(update={"exchanges": events})).verdict == "inconclusive"
    snapshots = list(trace.basket_snapshots)
    snapshots[2] = snapshots[2].model_copy(update={"snapshot_sha256": "0" * 64})
    assert evaluate_access_check(trace.model_copy(update={"basket_snapshots": snapshots})).verdict == "inconclusive"
    controls = dict(trace.controls, authentication_control=False)
    assert evaluate_access_check(trace.model_copy(update={"controls": controls})).verdict == "inconclusive"


def _rehashed_v3_snapshots(snapshots):
    from schemas.access_verification import AccessBasketItemState, AccessBasketSnapshot
    result = []
    for snapshot in snapshots:
        items = []
        for item in snapshot.items:
            values = item.model_dump(mode="json", exclude={"state_sha256"})
            items.append(AccessBasketItemState(**values, state_sha256=digest_value(values)))
        values = snapshot.model_dump(mode="json", exclude={"snapshot_sha256", "items"})
        values["items"] = [item.model_dump(mode="json") for item in items]
        result.append(AccessBasketSnapshot(**values, snapshot_sha256=digest_value(values)))
    return result


def _bound_v3_action(trace):
    binding = VerificationBinding(
        route_id="juice-basket-own-write-v2", handler_id="juice.basketItem.update",
        target="juice-access-fixture", finding_id="finding-v3", family="idor",
        source_file="routes/basket.ts", line_start=1, line_end=1,
        anchor_sha256=digest_value("anchor"), source_snapshot=trace.source_snapshot_digest,
        source_files={"routes/basket.ts": digest_value("file")}, map_sha256=digest_value("map"),
        service="juice", endpoint="/api/BasketItems/:id", method="PUT",
        tool="verify_access_control", check="own_write",
    )
    return ActionProposal(
        id="action-v3", tool="verify_access_control", target=trace.target,
        environment=trace.environment, parameters={"check_id": trace.check_id},
        purpose="fixed check", expected_evidence="owner readback", service="juice",
        endpoint="/api/BasketItems/:id", verification_binding=binding,
    )


@pytest.mark.parametrize("case", [
    "equivalent-vulnerable-writes", "protected-http-200-unchanged", "wrong-role",
    "wrong-object-basket", "missing-ownership", "missing-permission", "ambiguous-business-field",
    "sibling-side-effect", "owner-change", "authentication-failure", "damaged-reset",
    "source-binding-mismatch", "missing-readback", "session-generation-discontinuity",
    "budget-exhausted", "mixed-repeat",
])
def test_basket_write_v3_regression_matrix(case):
    trace = _basket_write_v3_trace("confirmed")
    action = None
    if case == "protected-http-200-unchanged":
        trace = _basket_write_v3_trace("rejected")
        assert evaluate_access_check(trace).verdict == "rejected"
        return
    if case == "equivalent-vulnerable-writes":
        assert evaluate_access_check(trace).verdict == "confirmed"
        return
    if case == "wrong-role":
        events = list(trace.exchanges)
        events[6] = events[6].model_copy(update={"role_id": "role-b"})
        trace = trace.model_copy(update={"exchanges": events})
    elif case == "wrong-object-basket":
        snapshots = list(trace.basket_snapshots)
        first = snapshots[0]
        items = [item.model_copy(update={"parent_basket_identity_sha256": "0" * 64})
                 if item.object_ref == "basket-write-candidate-b" else item for item in first.items]
        snapshots[0] = first.model_copy(update={"items": items})
        trace = trace.model_copy(update={"basket_snapshots": _rehashed_v3_snapshots(snapshots)})
    elif case == "missing-ownership":
        snapshots = list(trace.basket_snapshots)
        first = snapshots[0]
        items = [item.model_copy(update={"membership_verified": False})
                 if item.object_ref == "basket-write-candidate-b" else item for item in first.items]
        snapshots[0] = first.model_copy(update={"items": items})
        trace = trace.model_copy(update={"basket_snapshots": _rehashed_v3_snapshots(snapshots)})
    elif case == "missing-permission":
        generations = list(trace.generations)
        generations[0] = generations[0].model_copy(update={"permission_profile_sha256": None})
        trace = trace.model_copy(update={"generations": generations})
    elif case == "ambiguous-business-field":
        events = list(trace.exchanges)
        events[7] = events[7].model_copy(update={"changed_fields": ["quantity", "updatedAt", "ProductId"]})
        trace = trace.model_copy(update={"exchanges": events})
    elif case == "sibling-side-effect":
        snapshots = list(trace.basket_snapshots)
        first = snapshots[2]
        items = [item.model_copy(update={"quantity": 9})
                 if item.object_ref == "basket-write-negative-b" else item for item in first.items]
        snapshots[2] = first.model_copy(update={"items": items})
        trace = trace.model_copy(update={"basket_snapshots": _rehashed_v3_snapshots(snapshots)})
    elif case == "owner-change":
        snapshots = list(trace.basket_snapshots)
        first = snapshots[2]
        snapshots[2] = first.model_copy(update={"basket_owner_user_id": 777})
        trace = trace.model_copy(update={"basket_snapshots": _rehashed_v3_snapshots(snapshots)})
    elif case == "authentication-failure":
        events = list(trace.exchanges)
        events[2] = events[2].model_copy(update={"status": 200})
        trace = trace.model_copy(update={"exchanges": events})
    elif case == "damaged-reset":
        trace = trace.model_copy(update={"reset_complete": False})
    elif case == "source-binding-mismatch":
        action = _bound_v3_action(trace)
        trace = trace.model_copy(update={"source_snapshot_digest": "0" * 64})
    elif case == "missing-readback":
        events = list(trace.exchanges)
        events[7] = events[7].model_copy(update={"independent_readback": False})
        trace = trace.model_copy(update={"exchanges": events})
    elif case == "session-generation-discontinuity":
        events = list(trace.exchanges)
        events[6] = events[6].model_copy(update={"generation_sha256": trace.generations[1].generation_sha256})
        trace = trace.model_copy(update={"exchanges": events})
    elif case == "budget-exhausted":
        trace = trace.model_copy(update={"request_budget": 7})
    elif case == "mixed-repeat":
        snapshots = list(trace.basket_snapshots)
        second = snapshots[4]
        items = [item.model_copy(update={"quantity": 1, "updated_at": "2026-10-14T00:00:00+00:00"})
                 if item.object_ref == "basket-write-candidate-b" else item for item in second.items]
        snapshots[4] = second.model_copy(update={"items": items})
        trace = trace.model_copy(update={"basket_snapshots": _rehashed_v3_snapshots(snapshots)})
    assert evaluate_access_check(trace, action).verdict == "inconclusive"

def test_ownership_transfer_requires_independent_persisted_owner_proofs(bound_action):
    action = bound_action["juice-address-ownership-transfer-v1"][1]
    trace = _ownership_transfer_trace(action)
    assert evaluate_access_check(trace, action).verdict == "confirmed"
    assert evaluate_access_check(trace.model_copy(update={"ownership_proofs": []}), action).verdict == "inconclusive"
    controls = dict(trace.controls, negative_control=False)
    assert evaluate_access_check(trace.model_copy(update={"controls": controls}), action).verdict == "inconclusive"
    proofs = list(trace.ownership_proofs)
    proofs[1] = proofs[1].model_copy(update={"owner_role": "role-b", "owner_user_id": 26})
    assert evaluate_access_check(trace.model_copy(update={"ownership_proofs": proofs}), action).verdict == "inconclusive"


def test_unsafe_juice_address_update_is_not_offered_or_approved(bound_action):
    profile, action = bound_action["juice-address-own-write-v1"]
    assert len(ACCESS_CHECKS) == 6
    assert is_access_check_supported("juice-basket-own-read-v1")
    assert not is_access_check_supported("juice-address-own-write-v1")
    result = _b05_validator(profile).validate(action)
    assert not result.approved
    assert "rewrites object ownership" in result.reason


def _basket_insert_trace(action, *, vulnerable):
    check_id = "juice-basket-insert-owner-check-v1"
    rows = []
    generations = []
    for index in (1, 2):
        generation = _generation(index).model_copy(update={
            "role_a_user_id": 100 + index * 2,
            "role_b_user_id": 101 + index * 2,
            "permission_profile_sha256": digest_value("owner-only-permissions"),
            "role_a_session_binding_sha256": digest_value(f"session-a-{index}"),
            "role_b_session_binding_sha256": digest_value(f"session-b-{index}"),
        })
        generations.append(generation)
        base_hash = digest_value(f"basket-b-baseline-{index}")
        after_hash = digest_value(f"basket-b-after-{index}" if vulnerable else f"basket-b-baseline-{index}")
        item_hash = digest_value(f"inserted-item-{index}") if vulnerable else None
        suffix = f"t{index}"
        specifications = [
            (f"baseline-b-{suffix}", "GET", "role-b", "basket-b", None, 200,
             "unknown", base_hash, False, None, 0, True),
            (f"owner-a-insert-{suffix}", "POST", "role-a", "basket-a", "owned-basket-insert", 201,
             "changed", None, False, digest_value(f"owner-item-{index}"), 1, True),
            (f"owner-a-readback-{suffix}", "GET", "role-a", "basket-a", None, 200,
             "changed", digest_value(f"owner-basket-{index}"), True, digest_value(f"owner-item-{index}"), 1, True),
            (f"denied-b-insert-{suffix}", "POST", "role-a", "basket-b", "single-foreign-basket-insert", 401,
             "unchanged", None, False, None, 0, False),
            (f"denied-b-readback-{suffix}", "GET", "role-b", "basket-b", None, 200,
             "unchanged", base_hash, False, None, 0, True),
            (f"probe-duplicate-basket-{suffix}", "POST", "role-a", "basket-b",
             "duplicate-own-first-foreign-last-insert", 201 if vulnerable else 401,
             "changed" if vulnerable else "unchanged", None, False, item_hash, 1 if vulnerable else 0, vulnerable),
            (f"probe-b-readback-{suffix}", "GET", "role-b", "basket-b", None, 200,
             "changed" if vulnerable else "unchanged", after_hash, vulnerable, item_hash,
             1 if vulnerable else 0, True),
        ]
        for (exchange_id, method, role_id, object_ref, request_shape, status, effect,
             object_hash, marker, value_hash, added_count, owner_ok) in specifications:
            basket_identity = digest_value(f"basket:{object_ref}:{index}")
            expected_request = digest_value({
                "method": method, "endpoint_id": "basket-write" if method == "POST" else "basket-read",
                "object_ref": object_ref, "basket_identity_sha256": basket_identity,
                "request_shape": request_shape,
                "product_id": 5 if method == "POST" else None,
                "quantity": 1 if method == "POST" else None,
            })
            rows.append(AccessExchange(
                exchange_id=exchange_id, index=len(rows) + 1, role_id=role_id,
                object_ref=object_ref, method=method,
                endpoint_id="basket-write" if method == "POST" else "basket-read",
                status=status, object_sha256=object_hash, value_sha256=value_hash,
                private_marker_match=marker, owner_data_present=owner_ok,
                mutation_effect=effect, independent_readback=method == "GET",
                request_shape=request_shape, product_id=5 if method == "POST" else None,
                added_item_count=added_count,
                generation_sha256=generation.generation_sha256,
                actor_identity_sha256=(generation.role_a_identity_sha256 if role_id == "role-a"
                                       else generation.role_b_identity_sha256),
                actor_session_binding_sha256=(generation.role_a_session_binding_sha256 if role_id == "role-a"
                                              else generation.role_b_session_binding_sha256),
                request_sha256=expected_request, object_identity_sha256=basket_identity,
                parent_basket_identity_sha256=basket_identity,
            ))
    return AccessCheckTrace(
        check_id=check_id, binding_id=binding_id(action),
        source_snapshot_digest=action.verification_binding.source_snapshot,
        target=action.target, environment=action.environment, operation="basket_insert",
        endpoint_id="basket-write", method="POST", object_ref="basket-b", mutation_field="BasketId",
        controls={key: True for key in ("owner_write_control", "attacker_self", "negative_control",
            "ownership", "permission_relation", "cleanup_baseline")},
        generations=generations, exchanges=rows, exchange_count=14, request_budget=14,
        reset_complete=True, cleanup_complete=True, integrity_verified=True,
    )


def test_duplicate_basket_id_insert_requires_two_owner_readbacks(bound_action):
    action = bound_action["juice-basket-insert-owner-check-v1"][1]
    assert evaluate_access_check(_basket_insert_trace(action, vulnerable=True), action).verdict == "confirmed"
    assert evaluate_access_check(_basket_insert_trace(action, vulnerable=False), action).verdict == "rejected"
    trace = _basket_insert_trace(action, vulnerable=True)
    exchanges = list(trace.exchanges)
    exchanges[6] = exchanges[6].model_copy(update={"private_marker_match": False})
    assert evaluate_access_check(trace.model_copy(update={"exchanges": exchanges}), action).verdict == "inconclusive"


def test_partial_basket_insert_trace_is_inconclusive(bound_action):
    action = bound_action["juice-basket-insert-owner-check-v1"][1]
    partial = _basket_insert_trace(action, vulnerable=True).model_copy(update={
        "controls": {}, "generations": [], "exchanges": [], "exchange_count": 0,
        "reset_complete": False, "cleanup_complete": False,
        "integrity_verified": False, "technical_error": "docker_runtime_or_fixture_failure",
    })
    assert evaluate_access_check(partial, action).verdict == "inconclusive"


def test_http_status_alone_never_decides_access_verdict(bound_action):
    read_action = bound_action["juice-basket-own-read-v1"][1]
    trace = _read_trace(read_action)
    probe = trace.exchanges[4].model_copy(update={"private_marker_match": False, "owner_data_present": None})
    trace = trace.model_copy(update={"exchanges": [*trace.exchanges[:4], probe, trace.exchanges[5]]})
    assert evaluate_access_check(trace, read_action).verdict == "inconclusive"
    trace = _read_trace(read_action, probe_status=403)
    trace = trace.model_copy(update={"controls": {"negative_control": True}})
    assert evaluate_access_check(trace, read_action).verdict == "inconclusive"


def test_proven_own_read_confirmed_and_denied_rejected(bound_action):
    action = bound_action["juice-basket-own-read-v1"][1]
    assert evaluate_access_check(_read_trace(action), action).verdict == "confirmed"
    assert evaluate_access_check(_read_trace(action, probe_status=403), action).verdict == "rejected"
    leaked_denial = _read_trace(action, probe_status=403)
    exchanges = list(leaked_denial.exchanges)
    exchanges[4] = exchanges[4].model_copy(update={"owner_data_present": True,
                                                   "private_marker_match": True})
    assert evaluate_access_check(leaked_denial.model_copy(update={"exchanges": exchanges}), action).verdict == "inconclusive"


def test_own_write_requires_two_independent_owner_readbacks(bound_action):
    action = bound_action["juice-address-own-write-v1"][1]
    assert evaluate_access_check(_write_trace(action), action).verdict == "confirmed"
    assert evaluate_access_check(_write_trace(action, effect="unchanged"), action).verdict == "rejected"
    technical = _write_trace(action, effect="unchanged")
    exchanges = list(technical.exchanges)
    exchanges[6] = exchanges[6].model_copy(update={"status": 500})
    assert evaluate_access_check(technical.model_copy(update={"exchanges": exchanges}), action).verdict == "inconclusive"
    failed = _write_trace(action, readback_status=500)
    assert evaluate_access_check(failed, action).verdict == "inconclusive"


def test_inconsistent_repeat_binding_reset_and_cleanup_are_inconclusive(bound_action):
    action = bound_action["juice-basket-own-read-v1"][1]
    trace = _read_trace(action)
    exchanges = list(trace.exchanges)
    exchanges[5] = exchanges[5].model_copy(update={"private_marker_match": False})
    assert evaluate_access_check(trace.model_copy(update={"exchanges": exchanges}), action).verdict == "inconclusive"
    assert evaluate_access_check(trace.model_copy(update={"reset_complete": False}), action).verdict == "inconclusive"
    assert evaluate_access_check(trace.model_copy(update={"cleanup_complete": False,
        "technical_error": "cleanup_unverified"}), action).verdict == "inconclusive"
    assert evaluate_access_check(trace.model_copy(update={"binding_id": "0" * 64}), action).verdict == "inconclusive"


def test_partial_technical_trace_is_persistable_and_inconclusive(bound_action):
    action = bound_action["juice-basket-own-read-v1"][1]
    partial = _read_trace(action).model_copy(update={
        "controls": {}, "generations": [], "exchanges": [], "exchange_count": 0,
        "reset_complete": False, "cleanup_complete": False,
        "integrity_verified": False, "technical_error": "docker_runtime_or_fixture_failure",
    })
    assert evaluate_access_check(partial, action).verdict == "inconclusive"


def test_access_contract_rejects_secret_fields_and_schema_unknowns():
    with pytest.raises(ValueError):
        AccessCheckTrace.model_validate({"check_id": "juice-basket-own-read-v1", "token": "secret"})


def test_offline_verifier_rejects_tampered_sealed_file(tmp_path):
    (tmp_path / "seal.json").write_text(json.dumps({"manifest.json": "0" * 64}))
    (tmp_path / "manifest.json").write_text("{}")
    with pytest.raises(ValueError, match="seal"):
        verify_artifacts(tmp_path)


def test_offline_rescore_is_deterministic(bound_action):
    action = bound_action["juice-basket-own-read-v1"][1]
    trace = _read_trace(action)
    first = evaluate_access_check(trace, action).model_dump(mode="json")
    second = evaluate_access_check(AccessCheckTrace.model_validate(trace.model_dump()), action).model_dump(mode="json")
    assert first == second and first["verdict"] == "confirmed"
