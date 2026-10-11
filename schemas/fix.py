from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, model_validator

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
    editable_start: int | None = None
    editable_end: int | None = None
    applied: Literal[False] = False
    security_verified: Literal[False] = False
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def require_matching_proposal(self):
        if self.finding_id != self.proposal.finding_id:
            raise ValueError("Patch review finding_id must match proposal.finding_id")
        return self


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
    id: str = ""
    run_id: str = ""
    status: Literal["FIXED", "NOT_FIXED", "REGRESSION", "INCONCLUSIVE", "REJECTED"] = "INCONCLUSIVE"
    applied: bool = False
    security_verified: bool = False
    workspace_id: str = ""
    original_commit: str | None = None
    original_tree_sha256: str = ""
    original_file_sha256: str = ""
    patch_sha256: str = ""
    proposal_sha256: str = ""
    patched_file_sha256: str | None = None
    trusted_binding: dict = Field(default_factory=dict)
    before_evidence: Evidence | None = None
    after_evidence: Evidence | None = None
    before_evidence_sha256: str | None = None
    after_evidence_sha256: str | None = None
    stages: list["FixStageResult"] = Field(default_factory=list)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int = 0
    executor_backend: Literal["docker"] = "docker"
    network_mode: str = "none; internal target network for verification only"
    policy_sha256: str = ""
    original_unchanged: bool = False
    cleanup_complete: bool = False

    @model_validator(mode="after")
    def require_complete_chain(self):
        if self.security_verified != (self.status == "FIXED"):
            raise ValueError("Only FIXED can carry security_verified=true")
        if self.security_verified and not (
            self.applied and self.patch_application.status == "applied"
            and self.before_evidence and self.before_evidence.verdict == "confirmed"
            and self.after_evidence and self.after_evidence.verdict == "rejected"
            and self.original_unchanged and self.cleanup_complete
            and all(any(s.phase == "after" and s.stage == stage and s.status == "passed"
                        for s in self.stages) for stage in ("build", "tests", "start", "smoke"))
        ):
            raise ValueError("FIXED requires the complete evidence chain")
        return self


class FixStageResult(BaseModel):
    phase: Literal["before", "after"]
    stage: Literal["prepare", "build", "tests", "start", "smoke"]
    attempted: bool = True
    profile_id: str
    status: Literal["passed", "failed", "error", "timed_out"]
    exit_code: int
    timed_out: bool = False
    stdout: str = ""
    stderr: str = ""
    duration_ms: int = 0
    execution_ref: str
    audit_ref: str
    backend: Literal["docker"] = "docker"
    network_mode: str = "none"
