"""Deterministic offline verdicts for persisted B05 traces."""
from schemas.access_verification import AccessCheckEvidence, AccessCheckTrace
from schemas.action import ActionProposal
from security.access_verification import binding_id, registered_check

READ_SCHEDULE = ["oc-r-read", "nc-r-deny", "sc-r-self", "baseline-r-digest",
                "probe-r-t1", "probe-r-t2", "cleanup-r-verify"]
ADDRESS_WRITE_SCHEDULE = [
    "oc-w-update", "oc-w-readback", "sc-w-self", "nc-w-deny", "nc-w-readback",
    "baseline-w-digest", "probe-w-t1", "probe-w-t1-readback", "probe-w-t2",
    "probe-w-t2-readback", "cleanup-w-verify",
]
BASKET_WRITE_SCHEDULE = [
    "oc-b-update", "oc-b-readback", "sc-a-update", "sc-a-readback", "nc-a-update",
    "nc-b-readback", "baseline-b-state", "probe-b-t1", "probe-b-t1-readback",
    "probe-b-t2", "probe-b-t2-readback", "cleanup-b-baseline",
]
BASKET_WRITE_V3_SCHEDULE = [
    "oc-b-update", "oc-b-readback", "authn-anon-put", "authn-b-readback",
    "sc-a-update", "sc-a-readback", "probe-b-t1", "probe-b-t1-readback",
    "baseline-b-t2", "probe-b-t2", "probe-b-t2-readback", "cleanup-b-baseline",
]
BASKET_INSERT_SCHEDULE = [
    "baseline-b-t1", "owner-a-insert-t1", "owner-a-readback-t1",
    "denied-b-insert-t1", "denied-b-readback-t1", "probe-duplicate-basket-t1",
    "probe-b-readback-t1", "baseline-b-t2", "owner-a-insert-t2",
    "owner-a-readback-t2", "denied-b-insert-t2", "denied-b-readback-t2",
    "probe-duplicate-basket-t2", "probe-b-readback-t2",
]
TRANSFER_SCHEDULE = [
    "oc-t-owner", "nc-t-deny", "nc-t-owner", "probe-t-transfer",
    "probe-t-attacker-read", "probe-t-owner-read", "oc-t-owner-t2", "nc-t-deny-t2",
    "nc-t-owner-t2", "probe-t-transfer-t2", "probe-t-attacker-read-t2",
    "probe-t-owner-read-t2",
]


def evaluate_access_check(trace: AccessCheckTrace, action: ActionProposal | None = None) -> AccessCheckEvidence:
    if trace.check_id == "juice-review-own-write-v1":
        from evidence.review_ownership import evaluate_review_ownership
        return evaluate_review_ownership(trace, action)
    if trace.check_id == "juice-review-nosql-selector-v1":
        from evidence.review_nosql import evaluate_review_nosql
        return evaluate_review_nosql(trace, action)
    if trace.check_id == "juice-user-private-fields-v1":
        from evidence.user_fields import evaluate_user_fields
        return evaluate_user_fields(trace, action)
    if trace.check_id == "juice-feedback-owner-v1":
        from evidence.feedback_owner import evaluate_feedback_owner
        return evaluate_feedback_owner(trace, action)
    registration = registered_check({"check_id": trace.check_id})
    controls = dict(trace.controls)
    by_id = {item.exchange_id: item for item in trace.exchanges}
    if registration.operation == "own_read":
        required_controls = {"owner_availability", "negative_control", "attacker_self", "ownership",
                             "permission_relation", "cleanup_baseline"}
        expected_schedule = READ_SCHEDULE
        generation_count = 2
    elif trace.check_id == "juice-basket-own-write-v2":
        required_controls = {"owner_write_control", "attacker_self", "negative_control", "ownership",
                             "permission_relation", "cleanup_baseline"}
        expected_schedule = BASKET_WRITE_SCHEDULE
        generation_count = 3
    elif trace.check_id == "juice-basket-own-write-v3":
        required_controls = {"owner_write_control", "attacker_self", "authentication_control",
                             "ownership", "permission_relation", "non_interference",
                             "repeat_reset", "cleanup_baseline"}
        expected_schedule = BASKET_WRITE_V3_SCHEDULE
        generation_count = 3
    elif trace.check_id == "juice-basket-insert-owner-check-v1":
        required_controls = {"owner_write_control", "attacker_self", "negative_control", "ownership",
                             "permission_relation", "cleanup_baseline"}
        expected_schedule = BASKET_INSERT_SCHEDULE
        generation_count = 2
    elif registration.operation == "ownership_transfer":
        required_controls = {"owner_availability", "negative_control", "attacker_identity", "ownership",
                             "permission_relation"}
        expected_schedule = TRANSFER_SCHEDULE
        generation_count = 2
    else:
        required_controls = {"owner_write_control", "attacker_self", "negative_control", "ownership",
                             "permission_relation", "cleanup_baseline"}
        expected_schedule = ADDRESS_WRITE_SCHEDULE
        generation_count = 3
    controls_valid = set(controls) == required_controls and all(controls.values())
    binding_valid = action is None or (
        action.verification_binding is not None
        and trace.binding_id == binding_id(action)
        and trace.source_snapshot_digest == action.verification_binding.source_snapshot
        and trace.target == action.target and trace.environment == action.environment
        and action.tool == "verify_access_control"
    )
    generations_valid = (
        len(trace.generations) == generation_count
        and len({item.generation_sha256 for item in trace.generations}) == generation_count
        and all(item.b04_fixture_ready and item.role_a_identity_verified and item.role_b_identity_verified
                and item.ownership_verified and item.permission_relation_verified
                and item.reset_from_previous_verified for item in trace.generations)
    )
    if trace.check_id in {"juice-basket-own-write-v3", "juice-basket-insert-owner-check-v1"}:
        generations_valid = generations_valid and all(
            item.role_a_user_id is not None and item.role_b_user_id is not None
            and item.role_a_user_id != item.role_b_user_id
            and item.role_a_identity_sha256 != item.role_b_identity_sha256
            and item.permission_profile_sha256 is not None
            and item.role_a_session_binding_sha256 is not None
            and item.role_b_session_binding_sha256 is not None
            and item.role_a_session_binding_sha256 != item.role_b_session_binding_sha256
            for item in trace.generations
        )
    lifecycle_valid = (trace.reset_complete and trace.cleanup_complete and trace.integrity_verified
                       and trace.technical_error is None)
    schedule = [item.exchange_id for item in trace.exchanges]
    schedule_valid = (
        trace.exchange_count == len(trace.exchanges)
        and trace.exchange_count == len(expected_schedule)
        and trace.exchange_count <= trace.request_budget
        and trace.request_budget == registration.request_budget
        and schedule == expected_schedule
        and [item.index for item in trace.exchanges] == list(range(1, len(trace.exchanges) + 1))
    )
    exchange_bindings_valid = _exchange_bindings_valid(trace)
    technical_fields_valid = (
        trace.allowed_technical_fields == (["updatedAt"] if trace.check_id in {
            "juice-basket-own-write-v2", "juice-basket-own-write-v3",
        } else [])
    )
    registration_valid = (
        trace.operation == registration.operation
        and trace.endpoint_id == registration.endpoint_id
        and trace.method == registration.method
        and trace.object_ref == registration.object_ref
        and trace.mutation_field == registration.mutation_field
        and trace.mutation_value_sha256 == (
            canonical_value_digest(registration.mutation_value) if registration.mutation_value is not None else None
        )
    )
    controls_observed = _controls_match_exchanges(trace)
    if trace.check_id == "juice-basket-own-write-v3":
        controls_observed = controls_observed and _v3_snapshots_valid(trace)
    proofs_valid = _ownership_proofs_valid(trace)

    verdict = "inconclusive"
    reason = "Required controls, binding, state proof, repetition, reset, cleanup, or integrity evidence is incomplete."
    base_valid = (binding_valid and registration_valid and technical_fields_valid and controls_valid
                  and generations_valid and lifecycle_valid and schedule_valid
                  and exchange_bindings_valid and controls_observed)
    if base_valid and registration.operation == "own_read":
        trials = [item for item in trace.exchanges if item.exchange_id in {"probe-r-t1", "probe-r-t2"}]
        if all(item.status == 200 and item.owner_data_present is True and item.private_marker_match for item in trials):
            verdict, reason = "confirmed", "Both repeated cross-user reads returned the owner-bound private object."
        elif all((item.status in {400, 401, 403, 404}
                  or (item.status == 200 and item.owner_data_present is False))
                 and item.owner_data_present is not True and not item.private_marker_match for item in trials):
            verdict, reason = "rejected", "Both cross-user reads were denied or exposed no owner-only object data."
    elif base_valid and trace.check_id == "juice-basket-own-write-v3":
        verdict, reason = _v3_write_verdict(trace)
    elif base_valid and trace.check_id == "juice-basket-insert-owner-check-v1":
        trials = [(by_id[f"probe-duplicate-basket-{suffix}"], by_id[f"probe-b-readback-{suffix}"],
                   by_id[f"baseline-b-{suffix}"]) for suffix in ("t1", "t2")]
        confirmed = all(
            request.status in {200, 201} and request.mutation_effect == "changed"
            and request.added_item_count == 1 and request.owner_data_present is True
            and read.status == 200 and read.role_id == "role-b" and read.independent_readback
            and read.private_marker_match and read.mutation_effect == "changed"
            and read.added_item_count == 1 and read.value_sha256 == request.value_sha256
            and baseline.object_sha256 != read.object_sha256
            for request, read, baseline in trials
        )
        rejected = all(
            request.status in {200, 201, 400, 401, 403, 404}
            and request.mutation_effect == "unchanged" and request.added_item_count == 0
            and read.status == 200 and read.role_id == "role-b" and read.independent_readback
            and not read.private_marker_match and read.mutation_effect == "unchanged"
            and read.added_item_count == 0 and read.object_sha256 == baseline.object_sha256
            for request, read, baseline in trials
        )
        if confirmed:
            verdict, reason = "confirmed", "Both reset-separated duplicate-key insertions added exactly one owner-bound BasketItem, independently read back by the basket owner."
        elif rejected:
            verdict, reason = "rejected", "Both duplicate-key probes left the owner-bound basket unchanged while authorized insertion and denial controls passed."
    elif base_valid and trace.check_id == "juice-basket-own-write-v2":
        puts = [item for item in trace.exchanges if item.exchange_id in {"probe-b-t1", "probe-b-t2"}]
        reads = [item for item in trace.exchanges
                 if item.exchange_id in {"probe-b-t1-readback", "probe-b-t2-readback"}]
        allowed = {"quantity", "updatedAt"}
        confirmed = len(puts) == len(reads) == 2 and all(
            put.status in {200, 201} and put.mutation_effect == "changed"
            and read.status == 200 and read.role_id == "role-b" and read.independent_readback
            and read.owner_data_present is True and read.mutation_effect == "changed"
            and set(read.changed_fields) == allowed and read.timestamp_update_proven is True
            and read.created_at_unchanged is True and read.relationships_unchanged is True
            and read.other_items_unchanged is True
            and read.value_sha256 == canonical_value_digest(2)
            for put, read in zip(puts, reads, strict=True)
        )
        rejected = len(puts) == len(reads) == 2 and all(
            put.status in {200, 201, 400, 401, 403, 404} and put.mutation_effect == "unchanged"
            and read.status == 200 and read.role_id == "role-b" and read.independent_readback
            and read.owner_data_present is True and read.mutation_effect == "unchanged"
            and read.changed_fields == [] and read.relationships_unchanged is True
            and read.other_items_unchanged is True
            for put, read in zip(puts, reads, strict=True)
        )
        if confirmed:
            verdict, reason = "confirmed", "Both unauthorized BasketItem quantity changes were independently read back; only quantity and server-generated updatedAt changed."
        elif rejected:
            verdict, reason = "rejected", "Both BasketItem updates left the registered item and related state unchanged under owner readback."
    elif base_valid and registration.operation == "ownership_transfer" and proofs_valid:
        pairs = [(trace.ownership_proofs[index], trace.ownership_proofs[index + 1]) for index in (0, 2)]
        confirmed = all(before.owner_role == "role-b" and after.owner_role == "role-a"
                        and before.object_id == after.object_id for before, after in pairs)
        rejected = all(before.owner_role == after.owner_role == "role-b"
                       and before.object_id == after.object_id for before, after in pairs)
        if confirmed:
            verdict, reason = "confirmed", "Read-only SQLite proofs show the unauthorized Address owner changed from B to A in both reset-separated trials."
        elif rejected:
            verdict, reason = "rejected", "Read-only SQLite proofs show the Address remained owned by B in both trials."
    elif base_valid and trace.check_id == "juice-address-own-write-v1":
        # Preserve offline replay semantics for historical synthetic traces.
        # Validator still denies this unsafe legacy Address candidate at runtime.
        puts = [item for item in trace.exchanges
                if item.exchange_id in {"probe-w-t1", "probe-w-t2"}]
        reads = [item for item in trace.exchanges
                 if item.exchange_id in {"probe-w-t1-readback", "probe-w-t2-readback"}]
        confirmed = len(puts) == len(reads) == 2 and all(
            put.status in {200, 201} and put.mutation_effect == "changed"
            and read.status == 200 and read.role_id == "role-b" and read.independent_readback
            and read.owner_data_present is True and read.mutation_effect == "changed"
            for put, read in zip(puts, reads, strict=True)
        )
        rejected = len(puts) == len(reads) == 2 and all(
            put.status in {200, 201, 400, 401, 403, 404} and put.mutation_effect == "unchanged"
            and read.status == 200 and read.role_id == "role-b" and read.independent_readback
            and read.owner_data_present is True and read.mutation_effect == "unchanged"
            for put, read in zip(puts, reads, strict=True)
        )
        if confirmed:
            verdict, reason = "confirmed", "Historical synthetic trace: both Address changes were independently read back."
        elif rejected:
            verdict, reason = "rejected", "Historical synthetic trace: both Address updates left owner state unchanged."

    return AccessCheckEvidence(
        check_id=trace.check_id, verdict=verdict, reason=reason,
        binding_id=trace.binding_id, source_snapshot_digest=trace.source_snapshot_digest,
        control_results=controls, repeated_trials=(2 if generations_valid and schedule_valid else 0),
        exchange_count=trace.exchange_count, reset_complete=trace.reset_complete,
        cleanup_complete=trace.cleanup_complete, integrity_verified=trace.integrity_verified,
    )


def canonical_value_digest(value: object) -> str:
    from executor.access_fixture import digest
    return digest(value)


def _exchange_bindings_valid(trace: AccessCheckTrace) -> bool:
    by_check = {
        "juice-basket-own-read-v1": [
            ("oc-r-read", "GET", "role-b", "basket-b", "basket-read"),
            ("nc-r-deny", "GET", "role-a", "negative-control-b", "address-read"),
            ("sc-r-self", "GET", "role-a", "basket-a", "basket-read"),
            ("baseline-r-digest", "GET", "role-b", "basket-b", "basket-read"),
            ("probe-r-t1", "GET", "role-a", "basket-b", "basket-read"),
            ("probe-r-t2", "GET", "role-a", "basket-b", "basket-read"),
            ("cleanup-r-verify", "GET", "role-b", "basket-b", "basket-read"),
        ],
        "juice-address-own-write-v1": [
            ("oc-w-update", "PUT", "role-b", "address-b", "address-write"),
            ("oc-w-readback", "GET", "role-b", "address-b", "address-read"),
            ("sc-w-self", "PUT", "role-a", "address-a", "address-write"),
            ("nc-w-deny", "PUT", "role-a", "negative-control-b", "address-write"),
            ("nc-w-readback", "GET", "role-b", "negative-control-b", "address-read"),
            ("baseline-w-digest", "GET", "role-b", "write-candidate-b", "address-read"),
            ("probe-w-t1", "PUT", "role-a", "write-candidate-b", "address-write"),
            ("probe-w-t1-readback", "GET", "role-b", "write-candidate-b", "address-read"),
            ("probe-w-t2", "PUT", "role-a", "write-candidate-b", "address-write"),
            ("probe-w-t2-readback", "GET", "role-b", "write-candidate-b", "address-read"),
            ("cleanup-w-verify", "GET", "role-b", "write-candidate-b", "address-read"),
        ],
        "juice-basket-own-write-v3": [
            ("oc-b-update", "PUT", "role-b", "basket-write-control-b", "basket-write"),
            ("oc-b-readback", "GET", "role-b", "basket-write-control-b", "basket-read"),
            ("authn-anon-put", "PUT", None, "basket-write-candidate-b", "basket-write"),
            ("authn-b-readback", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
            ("sc-a-update", "PUT", "role-a", "basket-write-self-a", "basket-write"),
            ("sc-a-readback", "GET", "role-a", "basket-write-self-a", "basket-read"),
            ("probe-b-t1", "PUT", "role-a", "basket-write-candidate-b", "basket-write"),
            ("probe-b-t1-readback", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
            ("baseline-b-t2", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
            ("probe-b-t2", "PUT", "role-a", "basket-write-candidate-b", "basket-write"),
            ("probe-b-t2-readback", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
            ("cleanup-b-baseline", "GET", "role-b", "basket-write-candidate-b", "basket-read"),
        ],
        "juice-basket-insert-owner-check-v1": [
            ("baseline-b-t1", "GET", "role-b", "basket-b", "basket-read"),
            ("owner-a-insert-t1", "POST", "role-a", "basket-a", "basket-write"),
            ("owner-a-readback-t1", "GET", "role-a", "basket-a", "basket-read"),
            ("denied-b-insert-t1", "POST", "role-a", "basket-b", "basket-write"),
            ("denied-b-readback-t1", "GET", "role-b", "basket-b", "basket-read"),
            ("probe-duplicate-basket-t1", "POST", "role-a", "basket-b", "basket-write"),
            ("probe-b-readback-t1", "GET", "role-b", "basket-b", "basket-read"),
            ("baseline-b-t2", "GET", "role-b", "basket-b", "basket-read"),
            ("owner-a-insert-t2", "POST", "role-a", "basket-a", "basket-write"),
            ("owner-a-readback-t2", "GET", "role-a", "basket-a", "basket-read"),
            ("denied-b-insert-t2", "POST", "role-a", "basket-b", "basket-write"),
            ("denied-b-readback-t2", "GET", "role-b", "basket-b", "basket-read"),
            ("probe-duplicate-basket-t2", "POST", "role-a", "basket-b", "basket-write"),
            ("probe-b-readback-t2", "GET", "role-b", "basket-b", "basket-read"),
        ],
        "juice-basket-own-write-v2": [
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
        ],
        "juice-address-ownership-transfer-v1": [
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
        ],
    }
    expected = by_check[trace.check_id]
    if len(trace.exchanges) != len(expected):
        return False
    if not all(
        (item.exchange_id, item.method, item.role_id, item.object_ref, item.endpoint_id) == row
        for item, row in zip(trace.exchanges, expected, strict=True)
    ):
        return False
    if trace.check_id == "juice-basket-insert-owner-check-v1":
        generations = {item.generation_sha256: item for item in trace.generations}
        for event in trace.exchanges:
            generation = generations.get(event.generation_sha256)
            if (generation is None or event.request_sha256 is None
                    or event.object_identity_sha256 is None
                    or event.parent_basket_identity_sha256 != event.object_identity_sha256):
                return False
            identity = (generation.role_a_identity_sha256 if event.role_id == "role-a"
                        else generation.role_b_identity_sha256)
            session = (generation.role_a_session_binding_sha256 if event.role_id == "role-a"
                       else generation.role_b_session_binding_sha256)
            if (event.actor_kind != "authenticated" or event.actor_identity_sha256 != identity
                    or event.actor_session_binding_sha256 != session):
                return False
            expected_request = canonical_value_digest({
                "method": event.method, "endpoint_id": event.endpoint_id,
                "object_ref": event.object_ref,
                "basket_identity_sha256": event.object_identity_sha256,
                "request_shape": event.request_shape,
                "product_id": event.product_id,
                "quantity": 1 if event.method == "POST" else None,
            })
            if (event.product_id != (5 if event.method == "POST" else None)
                    or expected_request != event.request_sha256):
                return False
            expected_shape = {
                "owner-a-insert-t1": "owned-basket-insert",
                "owner-a-insert-t2": "owned-basket-insert",
                "denied-b-insert-t1": "single-foreign-basket-insert",
                "denied-b-insert-t2": "single-foreign-basket-insert",
                "probe-duplicate-basket-t1": "duplicate-own-first-foreign-last-insert",
                "probe-duplicate-basket-t2": "duplicate-own-first-foreign-last-insert",
            }.get(event.exchange_id)
            if event.request_shape != expected_shape:
                return False
        return True
    if trace.check_id != "juice-basket-own-write-v3":
        return True
    generations = {item.generation_sha256: item for item in trace.generations}
    for event in trace.exchanges:
        generation = generations.get(event.generation_sha256)
        if generation is None or event.request_sha256 is None or event.object_identity_sha256 is None:
            return False
        if event.parent_basket_identity_sha256 is None:
            return False
        if event.actor_kind == "anonymous":
            if (event.role_id is not None or event.actor_identity_sha256 is not None
                    or event.actor_session_binding_sha256 is not None
                    or event.exchange_id != "authn-anon-put"):
                return False
        else:
            if event.role_id not in {"role-a", "role-b"}:
                return False
            identity = (generation.role_a_identity_sha256 if event.role_id == "role-a"
                        else generation.role_b_identity_sha256)
            session = (generation.role_a_session_binding_sha256 if event.role_id == "role-a"
                       else generation.role_b_session_binding_sha256)
            if event.actor_identity_sha256 != identity or event.actor_session_binding_sha256 != session:
                return False
        expected_request = canonical_value_digest({
            "method": event.method, "endpoint_id": event.endpoint_id,
            "object_ref": event.object_ref,
            "object_identity_sha256": event.object_identity_sha256,
            "parent_basket_identity_sha256": event.parent_basket_identity_sha256,
            "body": {"quantity": 2} if event.method == "PUT" else None,
        })
        if expected_request != event.request_sha256:
            return False
    return True


def _controls_match_exchanges(trace: AccessCheckTrace) -> bool:
    by_id = {item.exchange_id: item for item in trace.exchanges}
    if trace.check_id == "juice-basket-own-read-v1":
        if not set(READ_SCHEDULE) <= by_id.keys():
            return False
        return (
            by_id["oc-r-read"].status == 200 and by_id["oc-r-read"].private_marker_match
            and by_id["nc-r-deny"].status in {400, 401, 403, 404}
            and by_id["sc-r-self"].status == 200 and by_id["sc-r-self"].private_marker_match
            and by_id["baseline-r-digest"].status == 200 and by_id["baseline-r-digest"].private_marker_match
            and by_id["cleanup-r-verify"].status == 200 and by_id["cleanup-r-verify"].private_marker_match
        )
    if trace.check_id == "juice-basket-insert-owner-check-v1":
        required = {
            f"{prefix}-{suffix}"
            for suffix in ("t1", "t2")
            for prefix in (
                "baseline-b", "owner-a-insert", "owner-a-readback", "denied-b-insert",
                "denied-b-readback", "probe-duplicate-basket", "probe-b-readback",
            )
        }
        if not required <= by_id.keys():
            return False
        for suffix in ("t1", "t2"):
            baseline = by_id[f"baseline-b-{suffix}"]
            owner_write = by_id[f"owner-a-insert-{suffix}"]
            owner_read = by_id[f"owner-a-readback-{suffix}"]
            denied = by_id[f"denied-b-insert-{suffix}"]
            denied_read = by_id[f"denied-b-readback-{suffix}"]
            probe = by_id[f"probe-duplicate-basket-{suffix}"]
            probe_read = by_id[f"probe-b-readback-{suffix}"]
            if not (baseline.status == 200 and baseline.role_id == "role-b"
                    and baseline.owner_data_present is True and baseline.independent_readback
                    and owner_write.status in {200, 201} and owner_write.added_item_count == 1
                    and owner_read.status == 200 and owner_read.role_id == "role-a"
                    and owner_read.owner_data_present is True and owner_read.private_marker_match
                    and owner_read.independent_readback and owner_read.value_sha256 == owner_write.value_sha256
                    and denied.status in {400, 401, 403, 404}
                    and denied.mutation_effect == "unchanged"
                    and denied_read.status == 200 and denied_read.role_id == "role-b"
                    and denied_read.owner_data_present is True and denied_read.independent_readback
                    and denied_read.object_sha256 == baseline.object_sha256
                    and denied_read.added_item_count == 0 and denied_read.mutation_effect == "unchanged"
                    and probe_read.status == 200 and probe_read.role_id == "role-b"
                    and probe_read.owner_data_present is True and probe_read.independent_readback):
                return False
            if probe.mutation_effect == "changed":
                if not (probe.status in {200, 201} and probe.added_item_count == 1
                        and probe_read.private_marker_match and probe_read.added_item_count == 1
                        and probe_read.value_sha256 == probe.value_sha256
                        and probe_read.mutation_effect == "changed"):
                    return False
            elif probe.mutation_effect == "unchanged":
                if not (probe.status in {200, 201, 400, 401, 403, 404}
                        and probe.added_item_count == 0 and not probe_read.private_marker_match
                        and probe_read.added_item_count == 0
                        and probe_read.object_sha256 == baseline.object_sha256
                        and probe_read.mutation_effect == "unchanged"):
                    return False
            else:
                return False
        return True
    if trace.check_id == "juice-basket-own-write-v2":
        if not set(BASKET_WRITE_SCHEDULE) <= by_id.keys():
            return False
        exact = {"quantity", "updatedAt"}
        for put_id, read_id in (("oc-b-update", "oc-b-readback"), ("sc-a-update", "sc-a-readback")):
            put, read = by_id[put_id], by_id[read_id]
            if not (put.status in {200, 201} and read.status == 200
                    and set(read.changed_fields) == exact and read.timestamp_update_proven is True
                    and read.created_at_unchanged is True and read.relationships_unchanged is True
                    and read.other_items_unchanged is True):
                return False
        negative, negative_read = by_id["nc-a-update"], by_id["nc-b-readback"]
        baseline, cleanup = by_id["baseline-b-state"], by_id["cleanup-b-baseline"]
        return (
            negative.status in {400, 401, 403, 404} and negative_read.status == 200
            and negative_read.changed_fields == [] and negative_read.relationships_unchanged is True
            and negative_read.other_items_unchanged is True
            and baseline.status == 200 and baseline.owner_data_present is True
            and cleanup.status == 200 and cleanup.changed_fields == []
            and cleanup.relationships_unchanged is True and cleanup.other_items_unchanged is True
        )
    if trace.check_id == "juice-basket-own-write-v3":
        if not set(BASKET_WRITE_V3_SCHEDULE) <= by_id.keys():
            return False
        exact = {"quantity", "updatedAt"}
        for put_id, read_id in (("oc-b-update", "oc-b-readback"),
                                ("sc-a-update", "sc-a-readback")):
            put, read = by_id[put_id], by_id[read_id]
            if not (put.status in {200, 201} and read.status == 200
                    and read.owner_data_present is True and read.independent_readback
                    and set(read.changed_fields) == exact
                    and read.timestamp_update_proven is True
                    and read.created_at_unchanged is True
                    and read.relationships_unchanged is True
                    and read.other_items_unchanged is True):
                return False
        anon, auth_read = by_id["authn-anon-put"], by_id["authn-b-readback"]
        if not (anon.actor_kind == "anonymous" and anon.status in {401, 403}
                and auth_read.status == 200 and auth_read.owner_data_present is True
                and auth_read.independent_readback):
            return False
        for put_id, read_id in (("probe-b-t1", "probe-b-t1-readback"),
                                ("probe-b-t2", "probe-b-t2-readback")):
            put, read = by_id[put_id], by_id[read_id]
            if not (put.status in {200, 201, 400, 401, 403, 404}
                    and read.status == 200 and read.role_id == "role-b"
                    and read.owner_data_present is True and read.independent_readback):
                return False
        return (by_id["baseline-b-t2"].status == 200
                and by_id["baseline-b-t2"].owner_data_present is True
                and by_id["cleanup-b-baseline"].status == 200
                and by_id["cleanup-b-baseline"].owner_data_present is True
                and by_id["cleanup-b-baseline"].changed_fields == []
                and by_id["cleanup-b-baseline"].relationships_unchanged is True
                and by_id["cleanup-b-baseline"].other_items_unchanged is True)
    if trace.check_id == "juice-address-ownership-transfer-v1":
        if not set(TRANSFER_SCHEDULE) <= by_id.keys():
            return False
        for suffix in ("", "-t2"):
            owner = by_id["oc-t-owner" + suffix]
            denied = by_id["nc-t-deny" + suffix]
            negative_owner = by_id["nc-t-owner" + suffix]
            probe = by_id["probe-t-transfer" + suffix]
            if not (owner.status == 200 and owner.observed_owner_role == "role-b"
                    and denied.status in {400, 401, 403, 404}
                    and negative_owner.status == 200 and negative_owner.observed_owner_role == "role-b"
                    and probe.method == "PUT" and probe.role_id == "role-a"):
                return False
        return True
    # Retained legacy synthetic contract; the real Address route remains denied by Validator.
    if not set(ADDRESS_WRITE_SCHEDULE) <= by_id.keys():
        return False
    owner_write, owner_read = by_id["oc-w-update"], by_id["oc-w-readback"]
    self_write, negative = by_id["sc-w-self"], by_id["nc-w-deny"]
    negative_read, baseline = by_id["nc-w-readback"], by_id["baseline-w-digest"]
    cleanup = by_id["cleanup-w-verify"]
    return (
        owner_write.status in {200, 201}
        and owner_read.status == 200 and owner_read.owner_data_present is True
        and self_write.status in {200, 201} and negative.status in {400, 401, 403, 404}
        and negative_read.status == 200 and negative_read.mutation_effect == "unchanged"
        and baseline.status == 200 and baseline.private_marker_match and baseline.owner_data_present is True
        and cleanup.status == 200 and cleanup.private_marker_match and cleanup.owner_data_present is True
    )


def _ownership_proofs_valid(trace: AccessCheckTrace) -> bool:
    if trace.check_id != "juice-address-ownership-transfer-v1":
        return not trace.ownership_proofs
    if len(trace.ownership_proofs) != 4:
        return False
    for index, generation in enumerate(trace.generations):
        before, after = trace.ownership_proofs[index * 2:index * 2 + 2]
        if not (before.phase == "before" and after.phase == "after"
                and before.generation_sha256 == after.generation_sha256 == generation.generation_sha256
                and before.object_id == after.object_id and before.row_found and after.row_found
                and before.read_only and after.read_only
                and before.query_id == after.query_id == "addresses-owner-readonly-v1"):
            return False
    return True


def _v3_snapshots_valid(trace: AccessCheckTrace) -> bool:
    expected = [
        ("baseline-t1", "oc-b-readback", 0),
        ("after-authn", "authn-b-readback", 0),
        ("probe-t1-readback", "probe-b-t1-readback", 0),
        ("baseline-t2", "baseline-b-t2", 1),
        ("probe-t2-readback", "probe-b-t2-readback", 1),
        ("cleanup", "cleanup-b-baseline", 2),
    ]
    if len(trace.basket_snapshots) != len(expected):
        return False
    refs = {"basket-write-candidate-b", "basket-write-control-b",
            "basket-write-negative-b", "basket-write-default-b"}
    exchange_by_id = {item.exchange_id: item for item in trace.exchanges}
    for snapshot, (phase, exchange_id, generation_index) in zip(
            trace.basket_snapshots, expected, strict=True):
        if (snapshot.phase != phase or snapshot.exchange_id != exchange_id
                or snapshot.generation_sha256 != trace.generations[generation_index].generation_sha256
                or {item.object_ref for item in snapshot.items} != refs
                or len({item.object_identity_sha256 for item in snapshot.items}) != 4):
            return False
        event = exchange_by_id[exchange_id]
        generation = trace.generations[generation_index]
        if (snapshot.reader_identity_sha256 != generation.role_b_identity_sha256
                or snapshot.reader_session_binding_sha256 != generation.role_b_session_binding_sha256
                or snapshot.basket_owner_user_id != generation.role_b_user_id
                or snapshot.basket_owner_identity_sha256 != generation.role_b_identity_sha256
                or event.actor_identity_sha256 != snapshot.reader_identity_sha256
                or event.actor_session_binding_sha256 != snapshot.reader_session_binding_sha256
                or event.object_identity_sha256 != next(
                    item.object_identity_sha256 for item in snapshot.items
                    if item.object_ref == event.object_ref)
                or event.parent_basket_identity_sha256 != snapshot.basket_identity_sha256):
            return False
        item_map = {item.object_ref: item for item in snapshot.items}
        if len({item.parent_basket_identity_sha256 for item in snapshot.items}) != 1:
            return False
        for item in snapshot.items:
            state = item.model_dump(mode="json", exclude={"state_sha256"})
            if (item.parent_basket_identity_sha256 != snapshot.basket_identity_sha256
                    or not item.membership_verified
                    or item.owner_identity_sha256 != generation.role_b_identity_sha256
                    or canonical_value_digest(state) != item.state_sha256):
                return False
        snapshot_data = snapshot.model_dump(mode="json", exclude={"snapshot_sha256"})
        if canonical_value_digest(snapshot_data) != snapshot.snapshot_sha256:
            return False
        products = {ref: (item_map[ref].product_id, item_map[ref].object_identity_sha256)
                    for ref in refs}
        if len({value[0] for value in products.values()}) != 4:
            return False
    # Full snapshots independently recompute the anonymous-authentication control,
    # non-interference, fixed operator object map, and fresh-reset cleanup baseline.
    snapshot_by_phase = {item.phase: item for item in trace.basket_snapshots}
    fixed_products = {"basket-write-candidate-b": 2, "basket-write-control-b": 3,
                      "basket-write-negative-b": 4, "basket-write-default-b": 1}
    fixed_quantities = {
        "baseline-t1": {**{ref: 1 for ref in fixed_products}, "basket-write-control-b": 2,
                        "basket-write-default-b": 2},
        "after-authn": {**{ref: 1 for ref in fixed_products}, "basket-write-control-b": 2,
                        "basket-write-default-b": 2},
        "baseline-t2": {**{ref: 1 for ref in fixed_products}, "basket-write-default-b": 2},
        "cleanup": {**{ref: 1 for ref in fixed_products}, "basket-write-default-b": 2},
    }
    for phase, quantities in fixed_quantities.items():
        states = {item.object_ref: item for item in snapshot_by_phase[phase].items}
        if any(states[ref].product_id != product or states[ref].quantity != quantities[ref]
               for ref, product in fixed_products.items()):
            return False
    def same_states(left, right, refs):
        return all(left[ref].model_dump(mode="json") == right[ref].model_dump(mode="json")
                   for ref in refs)
    base1 = {item.object_ref: item for item in snapshot_by_phase["baseline-t1"].items}
    auth_after = {item.object_ref: item for item in snapshot_by_phase["after-authn"].items}
    post1 = {item.object_ref: item for item in snapshot_by_phase["probe-t1-readback"].items}
    base2 = {item.object_ref: item for item in snapshot_by_phase["baseline-t2"].items}
    post2 = {item.object_ref: item for item in snapshot_by_phase["probe-t2-readback"].items}
    siblings = refs - {"basket-write-candidate-b"}
    if not same_states(base1, auth_after, refs):
        return False
    if not same_states(base1, post1, siblings) or not same_states(base2, post2, siblings):
        return False
    # Every request against a basket item and every snapshot must refer to the same
    # opaque object and basket within its reset generation.
    snapshot_by_phase = {item.phase: item for item in trace.basket_snapshots}
    for exchange_id, phase in (("oc-b-update", "baseline-t1"),
                               ("authn-anon-put", "baseline-t1"),
                               ("authn-b-readback", "after-authn"),
                               ("probe-b-t1", "baseline-t1"),
                               ("probe-b-t1-readback", "probe-t1-readback"),
                               ("baseline-b-t2", "baseline-t2"),
                               ("probe-b-t2", "baseline-t2"),
                               ("probe-b-t2-readback", "probe-t2-readback"),
                               ("cleanup-b-baseline", "cleanup")):
        event = exchange_by_id[exchange_id]
        snap = snapshot_by_phase[phase]
        item = next((value for value in snap.items if value.object_ref == event.object_ref), None)
        if item is None or event.object_identity_sha256 != item.object_identity_sha256:
            return False
        if event.parent_basket_identity_sha256 != snap.basket_identity_sha256:
            return False
    # Reset generations must rotate opaque object identity, while all four members
    # stay linked to the same B owner and product mapping across snapshots.
    if len({trace.generations[i].role_b_session_binding_sha256 for i in range(3)}) != 3:
        return False
    for ref in refs:
        states = [next(item for item in snap.items if item.object_ref == ref)
                  for snap in trace.basket_snapshots]
        if len({item.product_id for item in states}) != 1:
            return False
    return True


def _v3_write_verdict(trace: AccessCheckTrace) -> tuple[str, str]:
    from datetime import datetime

    snapshots = {item.phase: {state.object_ref: state for state in item.items}
                 for item in trace.basket_snapshots}
    candidate = "basket-write-candidate-b"
    trials = [
        (snapshots["baseline-t1"][candidate], snapshots["probe-t1-readback"][candidate],
         next(item for item in trace.exchanges if item.exchange_id == "probe-b-t1-readback")),
        (snapshots["baseline-t2"][candidate], snapshots["probe-t2-readback"][candidate],
         next(item for item in trace.exchanges if item.exchange_id == "probe-b-t2-readback")),
    ]
    confirmed = True
    rejected = True
    for before, after, read in trials:
        try:
            before_updated = datetime.fromisoformat(before.updated_at)
            after_updated = datetime.fromisoformat(after.updated_at)
        except ValueError:
            return "inconclusive", "BasketItem timestamps are not valid ISO timestamps."
        changed = (before.quantity != after.quantity or before.updated_at != after.updated_at
                   or before.created_at != after.created_at
                   or before.product_id != after.product_id
                   or before.object_identity_sha256 != after.object_identity_sha256
                   or before.parent_basket_identity_sha256 != after.parent_basket_identity_sha256
                   or before.owner_role_id != after.owner_role_id
                   or before.owner_identity_sha256 != after.owner_identity_sha256
                   or before.membership_verified != after.membership_verified)
        exact_change = (before.quantity == 1 and after.quantity == 2
                        and before.created_at == after.created_at
                        and after_updated > before_updated
                        and before.product_id == after.product_id
                        and before.object_identity_sha256 == after.object_identity_sha256
                        and before.parent_basket_identity_sha256 == after.parent_basket_identity_sha256)
        confirmed = confirmed and exact_change and read.changed_fields == ["quantity", "updatedAt"]
        rejected = rejected and not changed and read.changed_fields == []
    if confirmed:
        return "confirmed", "Both reset-separated unauthorized quantity changes were independently read back with exact object-local deltas."
    if rejected:
        return "rejected", "Both reset-separated unauthorized writes left the owner-bound BasketItem unchanged."
    return "inconclusive", "Repeated owner readbacks do not show a consistent exact unauthorized write or a consistent unchanged result."
