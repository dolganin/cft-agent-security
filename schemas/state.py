from datetime import datetime
from typing import TypedDict

from schemas.action import ActionProposal
from schemas.agent_loop import (
    AgentActionRecord,
    AgentDecisionRecord,
    AgentReasoningEvent,
    AgentStopReason,
)
from schemas.agent_outputs import AnalysisResult
from schemas.architecture import ArchitectureContext
from schemas.discovery import ProjectDiscoveryResult
from schemas.errors import ErrorDetail
from schemas.evidence import Evidence
from schemas.execution import ExecutionResult
from schemas.finding import Finding
from schemas.hypothesis import Hypothesis
from schemas.plan import DynamicPlan, PlanValidationResult
from schemas.report import FinalReport
from schemas.runtime import RuntimeServiceMap
from schemas.scoring import (
    ContextPriority,
    CVSSResult,
    ScoringReview,
    ScoringReviewResolution,
    TechnicalSeverity,
)
from schemas.target import TargetProfile
from schemas.validation import ValidationResult
from schemas.verification_binding import BindingResolution


class AgentState(TypedDict, total=False):
    project_discovery: ProjectDiscoveryResult | None
    target_profile: TargetProfile
    runtime_services: RuntimeServiceMap
    binding_resolution: BindingResolution
    finding: Finding
    code_context: str | None
    architecture_context: ArchitectureContext | None

    cvss: CVSSResult | None
    context_priority: ContextPriority | None
    scoring_review: ScoringReview | None
    scoring_review_resolution: ScoringReviewResolution
    technical_severity: TechnicalSeverity

    analysis: AnalysisResult | None
    hypothesis: Hypothesis | None
    dynamic_plan: DynamicPlan | None
    plan_history: list[DynamicPlan]
    plan_validation: PlanValidationResult | None
    proposed_action: ActionProposal | None

    validation: ValidationResult | None
    execution: ExecutionResult | None
    evidence: list[Evidence]
    action_history: list[AgentActionRecord]
    decision_history: list[AgentDecisionRecord]
    workflow_errors: list[ErrorDetail]
    reasoning_events: list[AgentReasoningEvent]

    status: str
    stop_reason: AgentStopReason | None
    iteration_count: int
    max_iterations: int
    max_steps: int
    started_at: datetime
    wall_clock_budget_seconds: float
    sandbox_session_id: str | None

    final_report: FinalReport | None
