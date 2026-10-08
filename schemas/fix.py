from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

from schemas.evidence import Evidence
from schemas.report import ReportFinding

FixCheckKind = Literal["rebuild", "static", "runtime"]
FixVerdict = Literal["verified", "not_verified", "inconclusive"]


class ProposedPatch(BaseModel):
    finding_id: str
    rationale: str
    unified_diff: str


class PatchReviewArtifact(BaseModel):
    """A checked proposal, never an execution approval or verified remediation."""

    schema_version: Literal["1.0"] = "1.0"
    id: str
    run_id: str
    finding_id: str
    file: str
    status: Literal["ready_for_review", "rejected"]
    source_sha256: str
    proposal_sha256: str
    model: str | None = None
    generated_at: datetime
    proposal: ProposedPatch
    validation_detail: str
    validation_policy: str = "single_file_scope_v1"
    applied: Literal[False] = False
    security_verified: Literal[False] = False
    limitations: list[str] = Field(default_factory=list)


class FixCheck(BaseModel):
    id: str
    kind: FixCheckKind
    argv: list[str] = Field(min_length=1)
    timeout_seconds: int = Field(default=120, ge=1, le=900)


class FixVerificationPlan(BaseModel):
    checks: list[FixCheck] = Field(default_factory=list)


class FixCheckResult(BaseModel):
    id: str
    kind: FixCheckKind
    argv: list[str]
    status: Literal["passed", "failed", "error", "timed_out"]
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""


class PatchApplicationResult(BaseModel):
    status: Literal["applied", "rejected", "error"]
    detail: str


class FixVerificationArtifact(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    original_finding: ReportFinding
    original_status: str
    proposed_patch: ProposedPatch
    patch_application: PatchApplicationResult
    re_test_actions: list[FixCheck] = Field(default_factory=list)
    re_test_results: list[FixCheckResult] = Field(default_factory=list)
    new_evidence: list[Evidence] = Field(default_factory=list)
    verdict: FixVerdict
    explanation: str
