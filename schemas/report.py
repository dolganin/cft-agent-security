from typing import Literal

from pydantic import BaseModel, Field, model_validator

from schemas.agent_loop import AgentDecisionRecord, AgentReasoningEvent, AgentStopReason
from schemas.architecture import ArchitectureContext
from schemas.errors import ErrorDetail
from schemas.evidence import Evidence
from schemas.finding import FindingProvenance
from schemas.pipeline import FindingGateEffect, GateCategory
from schemas.pr import PRFindingContext
from schemas.scoring import (
    ContextPriority,
    CVSSResult,
    ScoringReviewResolution,
    TechnicalSeverity,
)
from schemas.verification_binding import BindingResolution

ReportStatus = Literal["confirmed", "rejected", "inconclusive", "policy_blocked"]
DecisionBasis = Literal[
    "agent_budget",
    "capability_specific_evidence",
    "validator_policy",
    "iteration_limit",
    "workflow_state",
]
ValidatorDecision = Literal["approved", "denied", "not_run"]


class ReportFinding(BaseModel):
    id: str
    source: str
    rule_id: str
    title: str
    description: str | None = None
    severity: str | None = None
    service: str | None = None
    file: str
    line_start: int | None = None
    line_end: int | None = None
    pr_context: PRFindingContext | None = None
    provenance: FindingProvenance | None = None


class VerificationSummary(BaseModel):
    action_id: str | None = None
    capability: str | None = None
    target: str | None = None
    environment: str | None = None
    validator_decision: ValidatorDecision = "not_run"
    validator_reason: str | None = None
    evidence_count: int = Field(default=0, ge=0)
    evidence_types: list[str] = Field(default_factory=list)
    decision_basis: DecisionBasis = "workflow_state"


class SandboxActionSummary(BaseModel):
    action_id: str
    capability: str
    target: str
    environment: str
    purpose: str
    parameter_names: list[str] = Field(default_factory=list)
    execution_status: str | None = None
    exit_code: int | None = None
    timed_out: bool = False
    duration_ms: int | None = Field(default=None, ge=0)
    command: list[str] = Field(default_factory=list, max_length=32)
    cwd: str | None = Field(default=None, max_length=1024)
    stdout: str | None = Field(default=None, max_length=8192)
    stderr: str | None = Field(default=None, max_length=8192)
    sandbox_session_id: str | None = Field(default=None, max_length=256)
    artifact_refs: list[str] = Field(default_factory=list)
    error: ErrorDetail | None = None


class PolicyDecisionSummary(BaseModel):
    action_id: str
    decision: ValidatorDecision
    reason: str
    rules: list[str] = Field(default_factory=list)


class CIGateImpact(BaseModel):
    effect: FindingGateEffect
    category: GateCategory
    reason: str


class FinalReport(BaseModel):
    schema_version: Literal["1.0"] = "1.0"
    finding_id: str
    finding: ReportFinding
    status: ReportStatus

    analysis_summary: str | None = None
    risk_signals: list[str] = Field(default_factory=list)
    code_context: str | None = None
    architecture_context: ArchitectureContext | None = None
    hypothesis: str | None = None
    hypothesis_confidence: float | None = None

    verification: VerificationSummary
    cvss: CVSSResult | None = None
    context_priority: ContextPriority | None = None
    technical_severity: TechnicalSeverity | None = None
    scoring_review_resolution: ScoringReviewResolution | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    sandbox_actions: list[SandboxActionSummary] = Field(default_factory=list)
    policy_decisions: list[PolicyDecisionSummary] = Field(default_factory=list)
    agent_decisions: list[AgentDecisionRecord] = Field(default_factory=list)
    workflow_errors: list[ErrorDetail] = Field(default_factory=list)
    reasoning_events: list[AgentReasoningEvent] = Field(default_factory=list)
    ci_gate_impact: CIGateImpact | None = None

    explanation: str
    limitations: list[str] = Field(default_factory=list)
    next_step: str
    iterations: int = 0
    stop_reason: AgentStopReason | None = None
    binding_resolution: BindingResolution | None = None

    @model_validator(mode="after")
    def require_matching_finding(self):
        if self.finding_id != self.finding.id:
            raise ValueError("Report finding_id must match finding.id")
        return self
