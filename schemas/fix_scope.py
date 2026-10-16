"""Operator-owned Stage C eligibility and evaluator contracts (not permissions)."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class FixFamilySpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str
    case_ids: list[str] = Field(min_length=1)
    capability: str
    endpoint: str
    allowed_files: list[str] = Field(min_length=1)
    root_cause: str
    remediation: str
    functional_tests: list[str] = Field(min_length=2)
    independent_tests: list[str] = Field(min_length=2)
    disallowed_shortcuts: list[str] = Field(min_length=2)


class FixEligibility(BaseModel):
    family_id: str
    status: Literal["eligible", "failed", "ineligible"]
    reason: str
    finding_ids: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)


class FixScopeReport(BaseModel):
    schema_version: Literal["cft.fix-scope.v1"] = "cft.fix-scope.v1"
    source_commit: str
    baseline_archive_sha256: str
    evaluator_lock_sha256: str
    entries: list[FixEligibility]
    eligible: int
    failed: int
    ineligible: int
    fixes_attempted: Literal[0] = 0
    security_verified: Literal[False] = False

    @model_validator(mode="after")
    def require_exact_accounting(self):
        if len({entry.family_id for entry in self.entries}) != len(self.entries):
            raise ValueError("Duplicate family accounting")
        for status in ("eligible", "failed", "ineligible"):
            if getattr(self, status) != sum(entry.status == status for entry in self.entries):
                raise ValueError("Family status totals differ from entries")
        return self
