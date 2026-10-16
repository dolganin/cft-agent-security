"""Strict, secret-free contracts for the registered B05 access checks."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.feedback_verification import FeedbackOwnershipTrial
from schemas.review_verification import ReviewNoSQLTrial, ReviewOwnershipTrial
from schemas.user_verification import UserFieldsTrial

B05CheckId = Literal[
    "juice-basket-own-read-v1", "juice-address-own-write-v1",
    "juice-basket-own-write-v2", "juice-basket-own-write-v3",
    "juice-address-ownership-transfer-v1", "juice-basket-insert-owner-check-v1",
    "juice-review-own-write-v1", "juice-review-nosql-selector-v1",
    "juice-user-private-fields-v1",
    "juice-feedback-owner-v1",
]
AccessRole = Literal["role-a", "role-b"]
AccessObjectRef = Literal[
    "basket-a", "basket-b", "address-a", "address-b",
    "negative-control-b", "write-candidate-b", "write-control-b",
    "write-negative-b", "basket-write-candidate-b", "basket-write-control-b",
    "basket-write-negative-b", "basket-write-self-a",
    "basket-write-default-b",
]


class AccessCheckSelection(BaseModel):
    """The only model-controlled value: one opaque, operator-registered check id."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    check_id: B05CheckId


class AccessExchange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    exchange_id: str = Field(pattern=r"^[a-z][a-z0-9-]{1,47}$")
    index: int = Field(ge=1, le=20)
    role_id: AccessRole | None = None
    actor_kind: Literal["authenticated", "anonymous"] = "authenticated"
    object_ref: AccessObjectRef
    method: Literal["GET", "PUT", "POST"]
    endpoint_id: Literal[
        "basket-read", "basket-write", "address-read", "address-write",
    ]
    status: int = Field(ge=100, le=599)
    object_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    value_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    private_marker_match: bool = False
    owner_data_present: bool | None = None
    mutation_effect: Literal["changed", "unchanged", "unknown"] = "unknown"
    independent_readback: bool = False
    changed_fields: list[str] = Field(default_factory=list, max_length=8)
    timestamp_update_proven: bool | None = None
    created_at_unchanged: bool | None = None
    relationships_unchanged: bool | None = None
    other_items_unchanged: bool | None = None
    observed_owner_role: AccessRole | None = None
    generation_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    actor_identity_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    actor_session_binding_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    request_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    object_identity_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    parent_basket_identity_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    request_shape: Literal[
        "owned-basket-insert", "single-foreign-basket-insert",
        "duplicate-own-first-foreign-last-insert",
    ] | None = None
    product_id: Literal[5] | None = None
    added_item_count: int | None = Field(default=None, ge=0, le=1)


class AccessBasketItemState(BaseModel):
    """Safe state for one synthetic BasketItem; numeric target IDs stay opaque."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    object_ref: Literal[
        "basket-write-candidate-b", "basket-write-control-b",
        "basket-write-negative-b", "basket-write-default-b",
    ]
    object_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    parent_basket_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    product_id: int = Field(gt=0, lt=1_000_000_000)
    owner_role_id: Literal["role-b"] = "role-b"
    owner_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    quantity: int = Field(ge=0, le=100_000)
    created_at: str = Field(min_length=1, max_length=64)
    updated_at: str = Field(min_length=1, max_length=64)
    membership_verified: bool
    state_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class AccessBasketSnapshot(BaseModel):
    """One independent full-basket read with no response body or credentials."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    phase: Literal[
        "baseline-t1", "after-authn", "probe-t1-readback",
        "baseline-t2", "probe-t2-readback", "cleanup",
    ]
    generation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    exchange_id: Literal[
        "oc-b-readback", "authn-b-readback", "probe-b-t1-readback",
        "baseline-b-t2", "probe-b-t2-readback", "cleanup-b-baseline",
    ]
    reader_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    reader_session_binding_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    basket_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    basket_owner_user_id: int = Field(gt=0, lt=1_000_000_000)
    basket_owner_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    items: list[AccessBasketItemState] = Field(min_length=4, max_length=4)
    snapshot_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class DatabaseOwnershipProof(BaseModel):
    """Redacted fixed SQLite observation; only row ID and owner ID are retained."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    generation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    object_ref: Literal["address-b"] = "address-b"
    phase: Literal["before", "after"]
    object_id: int = Field(gt=0, lt=1_000_000_000)
    owner_user_id: int = Field(gt=0, lt=1_000_000_000)
    owner_role: AccessRole | None = None
    query_id: Literal["addresses-owner-readonly-v1"] = "addresses-owner-readonly-v1"
    read_only: Literal[True] = True
    row_found: bool


class AccessGenerationEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    generation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role_a_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role_b_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    role_a_identity_verified: bool
    role_b_identity_verified: bool
    role_a_user_id: int | None = Field(default=None, gt=0, lt=1_000_000_000)
    role_b_user_id: int | None = Field(default=None, gt=0, lt=1_000_000_000)
    permission_profile_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    ownership_verified: bool
    permission_relation_verified: bool
    b04_fixture_ready: bool
    reset_from_previous_verified: bool
    role_a_session_binding_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    role_b_session_binding_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class AccessCheckTrace(BaseModel):
    """Persisted observations. Verdict is intentionally computed elsewhere."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["b05.access.trace.v1"] = "b05.access.trace.v1"
    check_id: B05CheckId
    binding_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    target: Literal["juice-access-fixture"]
    environment: Literal["sandbox"]
    operation: Literal["own_read", "own_write", "ownership_transfer", "basket_insert",
                       "review_update", "review_nosql_selector", "user_private_fields", "feedback_owner"]
    endpoint_id: Literal["basket-read", "basket-write", "address-write", "review-write", "user-fields", "feedback-create"]
    method: Literal["GET", "PUT", "POST", "PATCH"]
    actor_ref: Literal["role-a"] = "role-a"
    object_ref: Literal["basket-b", "basket-write-candidate-b", "address-b", "write-candidate-b", "review-b", "user-a", "feedback-b"]
    mutation_field: Literal["city", "quantity", "BasketId", "message"] | None = None
    mutation_value_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    allowed_technical_fields: list[Literal["updatedAt"]] = Field(default_factory=list, max_length=1)
    controls: dict[str, bool]
    generations: list[AccessGenerationEvidence] = Field(max_length=3)
    exchanges: list[AccessExchange] = Field(max_length=14)
    ownership_proofs: list[DatabaseOwnershipProof] = Field(default_factory=list, max_length=4)
    basket_snapshots: list[AccessBasketSnapshot] = Field(default_factory=list, max_length=6)
    review_trials: list[ReviewOwnershipTrial] = Field(default_factory=list, max_length=2)
    review_nosql_trials: list[ReviewNoSQLTrial] = Field(default_factory=list, max_length=2)
    user_fields_trials: list[UserFieldsTrial] = Field(default_factory=list, max_length=2)
    feedback_trials: list[FeedbackOwnershipTrial] = Field(default_factory=list, max_length=2)
    review_source_snapshot_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    fixture_source_snapshot_digest: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    exchange_count: int = Field(ge=0, le=26)
    request_budget: Literal[7, 12, 14, 20, 26]
    reset_complete: bool
    cleanup_complete: bool
    integrity_verified: bool
    technical_error: str | None = Field(default=None, max_length=96)


class AccessWorkerStep(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["b05.worker-step.v1"]
    operation: Literal[
        "b05-own-read-first", "b05-own-read-second", "b05-own-write-first",
        "b05-own-write-second", "b05-own-write-cleanup",
        "b05-basket-write-first", "b05-basket-write-second", "b05-basket-write-cleanup",
        "b05-basket-write-v3-first", "b05-basket-write-v3-second", "b05-basket-write-v3-cleanup",
        "b05-basket-insert-first", "b05-basket-insert-second",
        "b05-ownership-transfer-first", "b05-ownership-transfer-second",
    ]
    generation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["completed", "failed"]
    http_exchanges: int = Field(ge=1, le=14)
    controls: dict[str, bool]
    exchanges: list[AccessExchange] = Field(min_length=1, max_length=14)
    ownership_proofs: list[DatabaseOwnershipProof] = Field(default_factory=list, max_length=2)
    basket_snapshots: list[AccessBasketSnapshot] = Field(default_factory=list, max_length=4)
    role_a_session_binding_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    role_b_session_binding_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    technical_error: str | None = Field(default=None, max_length=96)


class AccessCheckEvidence(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["b05.access.evidence.v1"] = "b05.access.evidence.v1"
    check_id: B05CheckId
    verdict: Literal["confirmed", "rejected", "inconclusive"]
    reason: str = Field(min_length=1, max_length=240)
    binding_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    control_results: dict[str, bool]
    repeated_trials: int = Field(ge=0, le=2)
    exchange_count: int = Field(ge=0, le=26)
    reset_complete: bool
    cleanup_complete: bool
    integrity_verified: bool
