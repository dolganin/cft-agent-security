"""Secret-free observations of the fixed scalar review-ownership protocol."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

ORDER = ["identity-a-before", "identity-b-before", "create-a", "create-b", "baseline-read",
         "owner-write", "owner-readback", "anonymous-write", "anonymous-readback",
         "cross-write", "cross-readback", "identity-a-after", "identity-b-after"]

NOSQL_ORDER = ["identity-a-before", "identity-b-before", "create-a", "create-b", "baseline-read",
               "scalar-owner-write", "scalar-owner-readback", "anonymous-write",
               "anonymous-readback", "operator-write", "operator-readback",
               "identity-a-after", "identity-b-after"]


class ReviewOwnershipTrial(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["review.owner.trial.v1"]
    generation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    fixture_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    binding_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    identity_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    identity_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    session_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    session_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    object_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    object_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    initial_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    final_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    baseline_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_marker_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    probe_marker_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_readback_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    anonymous_readback_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    probe_readback_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_status: int = Field(ge=100, le=599)
    anonymous_status: int = Field(ge=100, le=599)
    probe_status: int = Field(ge=100, le=599)
    controls: dict[str, bool]
    http_exchanges: Literal[13]
    request_order: list[str] = Field(min_length=13, max_length=13)


class ReviewNoSQLTrial(BaseModel):
    """Redacted proof for a fixed operator selector over exactly two synthetic reviews."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["review.nosql.trial.v1"]
    generation_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    fixture_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    binding_snapshot_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    identity_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    identity_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    session_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    session_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    owner_identity_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    review_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    review_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    unrelated_baseline_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    unrelated_after_scalar_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    unrelated_after_anonymous_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    unrelated_after_operator_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    initial_a_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    initial_b_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scalar_marker_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scalar_a_readback_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scalar_b_readback_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    anonymous_marker_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    anonymous_b_readback_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    operator_marker_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    operator_a_readback_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    operator_b_readback_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    scalar_status: int = Field(ge=100, le=599)
    anonymous_status: int = Field(ge=100, le=599)
    operator_status: int = Field(ge=100, le=599)
    operator_modified_count: int = Field(ge=0, le=2)
    controls: dict[str, bool]
    http_exchanges: Literal[13]
    request_order: list[str] = Field(min_length=13, max_length=13)
