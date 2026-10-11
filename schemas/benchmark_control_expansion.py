"""Separate A03.1 evaluator records; frozen A03 schemas/records remain untouched."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.benchmark_controls import ControlAnchor


class ExpandedControl(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=r"^JS-SAFE-[A-Z]+-1[0-9]{2}$")
    control_type: Literal["original_safe", "patched_safe", "synthetic_safe"]
    family: Literal["authentication", "file-validation", "path-traversal", "business-logic", "open-redirect",
                    "nosql-injection", "xss", "xml-external-entities", "code-evaluation"]
    security_property: str = Field(min_length=20)
    oracle: str = Field(min_length=5)
    root_cause_key: str
    independence_group: str
    split: Literal["development", "holdout"]
    related_positive_case_ids: list[str]
    related_root_cause_key: str | None
    relation: Literal["direct_safe_twin", "independent_safe_property"]
    source_anchors: list[ControlAnchor] = Field(min_length=1)
    http_anchors: list[str]
    service: Literal["juice", "synthetic-fixture"]
    required_identities: list[str]
    required_test_data: list[str]
    availability_checks: list[str]
    reset_contract: Literal["juice-fresh-stage1-v1", "synthetic-fresh-process-v1"]
    cleanup_requirements: list[str]
    provenance: list[str]
    validation_basis: Literal["runtime", "source_review", "fixture_behavior"]
    runtime_verdict: None = None
    truth_validated: Literal[True]
    agent_verifiable_now: Literal[False]
    review_status: Literal["reviewed"]
    evidence_reference: str
    evidence_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    patch_reference: str | None = None
    patch_sha256: str | None = Field(default=None,pattern=r"^[a-f0-9]{64}$")
    source_sha256: str | None = Field(default=None,pattern=r"^[a-f0-9]{64}$")
    limitations: str

    @model_validator(mode="after")
    def consistency(self):
        if self.independence_group != "juice-"+self.root_cause_key:
            raise ValueError("Root cause/group mismatch")
        if self.relation=="direct_safe_twin" and (not self.related_positive_case_ids or self.related_root_cause_key!=self.root_cause_key):
            raise ValueError("Twin needs exact positive cause binding")
        if self.relation=="independent_safe_property" and (self.related_positive_case_ids or self.related_root_cause_key is not None):
            raise ValueError("Independent property cannot claim a positive twin")
        if self.control_type=="patched_safe" and (self.validation_basis!="runtime" or not all([self.patch_reference,self.patch_sha256,self.source_sha256])):
            raise ValueError("Patched safe needs full runtime and digest proof")
        if self.control_type=="synthetic_safe" and (self.service!="synthetic-fixture" or self.validation_basis!="fixture_behavior"):
            raise ValueError("Synthetic slice must remain separate")
        return self
