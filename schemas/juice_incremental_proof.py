"""Typed, secret-free outputs for the operator-only Juice Shop mini proofs."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

_HASH = r"^[a-f0-9]{64}$"
_ROLE = Literal["customer", "deluxe", "accounting", "admin"]


class JuiceProofRoute(BaseModel):
    """Fixed benchmark finding-to-proof map; never accepts a caller URL or argv."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    check_id: Literal["role-registration", "anonymous-product-put"]
    rule_id: str = Field(min_length=1, max_length=160)
    source_file: str = Field(min_length=1, max_length=256)


class JuiceProofProfile(BaseModel):
    """Operator-owned immutable target and proof routing configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["juice.incremental.proof-profile.v1"] = (
        "juice.incremental.proof-profile.v1"
    )
    target_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    target_image: str = Field(min_length=1, max_length=256)
    worker_image: str = Field(min_length=1, max_length=256)
    routes: list[JuiceProofRoute] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def validate_fixed_routes(self):
        expected = {
            "role-registration": (
                "juice.authorization.client-role-setter", "models/user.ts",
            ),
            "anonymous-product-put": (
                "juice.authorization.generated-product-put", "server.ts",
            ),
        }
        if self.target_commit != "5658473cf8814459bf89000ce373b20ed0b4eb37":
            raise ValueError("Incremental proof is restricted to pinned Juice Shop v20.2.0")
        if len({route.check_id for route in self.routes}) != len(self.routes):
            raise ValueError("Incremental proof check IDs must be unique")
        for route in self.routes:
            if (route.rule_id, route.source_file) != expected[route.check_id]:
                raise ValueError("Incremental proof route does not match its fixed detector")
        return self


class JuiceProofBinding(BaseModel):
    """Application-created approval binding for one finding and fixed protocol."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["juice.incremental.binding.v1"] = "juice.incremental.binding.v1"
    target: str = Field(min_length=1, max_length=128)
    finding_id: str = Field(min_length=1, max_length=256)
    rule_id: str = Field(min_length=1, max_length=160)
    source_file: str = Field(min_length=1, max_length=256)
    check_id: Literal["role-registration", "anonymous-product-put"]
    route_sha256: str = Field(pattern=_HASH)
    source_snapshot_sha256: str = Field(pattern=_HASH)


class RoleRegistrationTrial(BaseModel):
    """Independent post-login role observation for two synthetic registrations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["juice.role_registration.trial.v1"]
    generation_sha256: str = Field(pattern=_HASH)
    source_snapshot_sha256: str = Field(pattern=_HASH)
    profile_sha256: str = Field(pattern=_HASH)
    worker_sha256: str = Field(pattern=_HASH)
    baseline_registration_status: int = Field(ge=100, le=599)
    baseline_login_status: int = Field(ge=100, le=599)
    baseline_identity_status: int = Field(ge=100, le=599)
    baseline_identity_sha256: str | None = Field(default=None, pattern=_HASH)
    baseline_role: _ROLE | None = None
    candidate_registration_status: int = Field(ge=100, le=599)
    candidate_login_status: int = Field(ge=100, le=599)
    candidate_identity_status: int = Field(ge=100, le=599)
    candidate_identity_present: bool
    candidate_identity_sha256: str | None = Field(default=None, pattern=_HASH)
    candidate_role: _ROLE | None = None
    identities_distinct: bool
    request_order: list[str] = Field(min_length=6, max_length=6)
    http_exchanges: int = Field(ge=6, le=16)

    @model_validator(mode="after")
    def validate_protocol_order(self):
        expected = [
            "baseline-register", "baseline-login", "baseline-identity",
            "candidate-register", "candidate-login", "candidate-identity",
        ]
        if self.request_order != expected:
            raise ValueError("Role-registration protocol request order is fixed")
        if self.candidate_identity_present != (self.candidate_identity_sha256 is not None):
            raise ValueError("Candidate identity presence and digest disagree")
        return self


def role_registration_disposition(trial: RoleRegistrationTrial) -> Literal[
    "confirmed", "rejected", "inconclusive",
]:
    """Recompute the narrow role-assignment claim from typed controls, never worker status."""
    baseline_healthy = (
        trial.baseline_registration_status in {200, 201}
        and trial.baseline_login_status == 200
        and trial.baseline_identity_status == 200
        and trial.baseline_identity_sha256 is not None
        and trial.baseline_role == "customer"
    )
    if not baseline_healthy or not trial.identities_distinct:
        return "inconclusive"
    candidate_authenticated = (
        trial.candidate_login_status == 200
        and trial.candidate_identity_status == 200
        and trial.candidate_identity_present
        and trial.candidate_identity_sha256 is not None
    )
    if candidate_authenticated and trial.candidate_role == "admin":
        return "confirmed"
    if candidate_authenticated and trial.candidate_role == "customer":
        return "rejected"
    if (trial.candidate_registration_status in {400, 401, 403, 409, 422}
            and trial.candidate_login_status == 401
            and trial.candidate_identity_status == 200
            and not trial.candidate_identity_present):
        return "rejected"
    return "inconclusive"


class ProductPutTrial(BaseModel):
    """Independent before/after observations for owned synthetic Product rows."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["juice.product_put.trial.v1"]
    generation_sha256: str = Field(pattern=_HASH)
    source_snapshot_sha256: str = Field(pattern=_HASH)
    profile_sha256: str = Field(pattern=_HASH)
    worker_sha256: str = Field(pattern=_HASH)
    account_registration_status: int = Field(ge=100, le=599)
    account_login_status: int = Field(ge=100, le=599)
    identity_status: int = Field(ge=100, le=599)
    identity_sha256: str | None = Field(default=None, pattern=_HASH)
    identity_role: _ROLE | None = None
    positive_create_status: int = Field(ge=100, le=599)
    positive_product_id_sha256: str | None = Field(default=None, pattern=_HASH)
    positive_authenticated_put_status: int = Field(ge=100, le=599)
    positive_readback_status: int = Field(ge=100, le=599)
    positive_mutation_persisted: bool
    positive_untouched_fields_stable: bool
    candidate_create_status: int = Field(ge=100, le=599)
    candidate_product_id_sha256: str | None = Field(default=None, pattern=_HASH)
    candidate_before_sha256: str | None = Field(default=None, pattern=_HASH)
    anonymous_put_status: int = Field(ge=100, le=599)
    candidate_readback_status: int = Field(ge=100, le=599)
    candidate_after_sha256: str | None = Field(default=None, pattern=_HASH)
    anonymous_mutation_persisted: bool
    candidate_untouched_fields_stable: bool
    anonymous_create_control_status: int = Field(ge=100, le=599)
    anonymous_create_control_readback_status: int = Field(ge=100, le=599)
    anonymous_create_control_absent: bool
    request_order: list[str] = Field(min_length=13, max_length=13)
    http_exchanges: int = Field(ge=13, le=24)

    @model_validator(mode="after")
    def validate_protocol_order(self):
        expected = [
            "register", "login", "identity", "positive-create", "positive-read-before",
            "positive-authenticated-put", "positive-read-after", "candidate-create",
            "candidate-read-before", "candidate-anonymous-put", "candidate-read-after",
            "anonymous-create-control", "anonymous-create-control-readback",
        ]
        if self.request_order != expected:
            raise ValueError("Product-PUT protocol request order is fixed")
        return self


def product_put_disposition(trial: ProductPutTrial) -> Literal[
    "confirmed", "rejected", "inconclusive",
]:
    """Evaluate persisted mutation and controls; HTTP success alone never confirms."""
    healthy_baseline = (
        trial.account_registration_status in {200, 201}
        and trial.account_login_status == 200
        and trial.identity_status == 200
        and trial.identity_sha256 is not None
        and trial.identity_role == "customer"
        and trial.positive_create_status in {200, 201}
        and trial.positive_product_id_sha256 is not None
        and trial.positive_authenticated_put_status in {200, 201, 204}
        and trial.positive_readback_status == 200
        and trial.positive_mutation_persisted
        and trial.positive_untouched_fields_stable
        and trial.candidate_create_status in {200, 201}
        and trial.candidate_product_id_sha256 is not None
        and trial.candidate_before_sha256 is not None
        and trial.candidate_readback_status == 200
        and trial.candidate_after_sha256 is not None
        and trial.candidate_product_id_sha256 != trial.positive_product_id_sha256
        and trial.anonymous_create_control_status in {400, 401, 403}
        and trial.anonymous_create_control_readback_status == 200
        and trial.anonymous_create_control_absent
    )
    if not healthy_baseline:
        return "inconclusive"
    if (trial.anonymous_mutation_persisted
            and trial.anonymous_put_status in {200, 201, 204}
            and trial.candidate_untouched_fields_stable):
        return "confirmed"
    if (not trial.anonymous_mutation_persisted
            and trial.candidate_before_sha256 == trial.candidate_after_sha256
            and trial.candidate_untouched_fields_stable
            and trial.anonymous_put_status in {200, 204, 400, 401, 403, 404}):
        return "rejected"
    return "inconclusive"
