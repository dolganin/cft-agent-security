"""A03 evaluator-only contracts. No modification to locked A01 contracts."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ControlAnchor(BaseModel):
    model_config = ConfigDict(extra="forbid")
    file: str
    start: int = Field(ge=1)
    end: int = Field(ge=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    region_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class SafeControl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^JS-SAFE-[A-Z]+-[0-9]{3}$")
    family: Literal["authorization", "sensitive_data", "redirect", "sql_injection"]
    control_type: Literal["original_safe", "patched_safe", "synthetic_safe"]
    security_property: str = Field(min_length=20)
    root_cause_key: str
    independence_group: str
    split: Literal["development", "holdout"]
    source_anchors: list[ControlAnchor] = Field(min_length=1)
    http_anchors: list[str] = Field(min_length=1)
    service: Literal["juice"]
    required_identities: list[Literal["owner", "other_user"]]
    required_test_data: list[str] = Field(min_length=1)
    availability_checks: list[str] = Field(min_length=1)
    safe_expected_behaviour: str
    failure_meaning: str
    provenance: list[str] = Field(min_length=1)
    reset_contract: Literal["juice-fresh-stage1-v1"]
    cleanup_requirements: list[str] = Field(min_length=1)
    review_status: Literal["reviewed"]
    validation_basis: Literal["runtime", "source_review"]
    truth_validated: Literal[True]
    agent_verifiable_now: Literal[False]
    runtime_eligibility: Literal["evaluator_fixture_only", "truth_only"]
    property_key: Literal["address_owner", "card_owner", "card_mask", "redirect_exact", "address_orm"]
    evidence_reference: str
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    patch_reference: str | None = None
    patch_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    source_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def check_origin(self):
        if self.independence_group != "juice-" + self.root_cause_key:
            raise ValueError("Root cause/group mismatch")
        patch = (self.patch_reference, self.patch_sha256, self.source_sha256)
        if self.control_type == "patched_safe" and not all(patch):
            raise ValueError("Patched control needs complete digest binding")
        if self.control_type != "patched_safe" and any(patch):
            raise ValueError("Patch provenance belongs only to patched slice")
        if (self.validation_basis == "source_review") != (self.runtime_eligibility == "truth_only"):
            raise ValueError("Source proof cannot claim runtime eligibility")
        return self


class ControlCatalog(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["a03.controls.v1"]
    target_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    controls: list[SafeControl]
