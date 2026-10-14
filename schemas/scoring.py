from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class CVSSMetricFact(BaseModel):
    """Operator-reviewed metric justification, not a model verdict."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)
    value: str = Field(pattern=r"^[A-Z]$")
    reasoning: str = Field(min_length=1)
    evidence_refs: list[str] = Field(min_length=1)

    @field_validator("evidence_refs")
    @classmethod
    def nonempty_refs(cls, refs: list[str]) -> list[str]:
        if any(not ref.strip() for ref in refs):
            raise ValueError("Every metric needs a nonempty evidence reference")
        return refs


class CVSSAssessmentInput(BaseModel):
    """Explicit CVSS-B inputs; existence/trust of references is checked by the caller."""

    model_config = ConfigDict(extra="forbid")
    finding_id: str = Field(min_length=1)
    metrics: dict[str, CVSSMetricFact]


ImpactFact = Literal["direct_database_disclosure", "authentication_bypass",
                     "unauthorized_persistent_update", "administrative_role_acquisition"]


class ScoringSourceReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1)
    file: str = Field(min_length=1)
    sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    metrics: list[str] = Field(default_factory=list)
    impacts: list[ImpactFact] = Field(default_factory=list)


class ScoringReview(BaseModel):
    """Trusted operator input, never accepted from a finding/model response."""

    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["scoring.review.b08.v1"] = "scoring.review.b08.v1"
    finding_id: str
    finding_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    reviewed_by: str = Field(min_length=1, pattern=r"\S")
    rationale: str = Field(min_length=1, pattern=r"\S")
    references: list[ScoringSourceReference] = Field(min_length=1, max_length=32)
    cvss: CVSSAssessmentInput | None = None
    impacts: list[ImpactFact] = Field(default_factory=list)


class TechnicalSeverity(BaseModel):
    scheme: Literal["source-impact.a04.v1"] = "source-impact.a04.v1"
    level: Literal["HIGH", "UNASSESSED"] = "UNASSESSED"
    assessment_status: Literal["assessed", "unassessed"] = "unassessed"
    impact_facts: list[ImpactFact] = Field(default_factory=list)
    reasoning: str = "No operator-reviewed source-impact facts supplied."


class ScoringReviewResolution(BaseModel):
    status: Literal["not_supplied", "accepted", "invalid"] = "not_supplied"
    review_digest: str | None = None
    reviewed_by: str | None = None
    diagnostics: list[str] = Field(default_factory=list)
    references: list[ScoringSourceReference] = Field(default_factory=list)


class CVSSResult(BaseModel):
    vector: str
    score: float | None = None
    severity: str
    reasoning: str = ""
    assessment_status: Literal["assessed", "unassessed", "not_applicable"] = "unassessed"
    scheme: Literal["CVSS:4.0/B"] = "CVSS:4.0/B"
    metric_facts: dict[str, CVSSMetricFact] = Field(default_factory=dict)
    missing_metrics: list[str] = Field(default_factory=list)


class ContextPriority(BaseModel):
    level: str
    score: float | None = None
    reasons: list[str] = Field(default_factory=list)
    assessment_status: Literal["assessed", "partial", "unassessed"] = "unassessed"
    unknown_inputs: list[str] = Field(default_factory=list)
    scheme: str = "context-priority.v0.1"
