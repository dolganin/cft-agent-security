"""Serializable R04 choices, observation ledger and operator budgets."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, model_validator

from schemas.research import RESEARCH_REQUESTS
from schemas.scout import CandidateFinding


class ResearchCandidate(CandidateFinding):
    observation_refs: list[str] = Field(min_length=1, max_length=16)
    anchor: str = Field(min_length=1, max_length=2000)


class SourceProofClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["weak_digest_call.v1"]
    file: str = Field(min_length=1, max_length=240)
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    observation_refs: list[str] = Field(min_length=1, max_length=16)


class HttpProofClaim(BaseModel):
    model_config = ConfigDict(extra="forbid")
    protocol: Literal["confidential_marker.v1"]
    spec_id: str = Field(min_length=1, max_length=128)
    observation_refs: list[str] = Field(min_length=1, max_length=16)


class ResearchLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_steps: int = Field(default=16, ge=1, le=64)
    max_model_calls: int = Field(default=20, ge=1, le=128)
    max_schema_corrections: int = Field(default=0, ge=0, le=1)
    max_context_bytes: int = Field(default=48000, ge=4096, le=131072)
    max_model_io_bytes: int = Field(default=1048576, ge=4096, le=16777216)
    max_observation_bytes: int = Field(default=1048576, ge=1024, le=4194304)
    max_write_bytes: int = Field(default=262144, ge=0, le=1048576)
    wall_seconds: int = Field(default=300, ge=1, le=3600)


class ResearchChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: Literal["list_source_files", "read_source", "search_source", "write_workspace_file",
                  "read_workspace_file", "sandbox_command", "target_http"]
    parameters: dict
    purpose: str = Field(min_length=1, max_length=1000)
    expected_evidence: str = Field(min_length=1, max_length=1000)
    service: str | None = None
    endpoint: str | None = None

    @model_validator(mode="after")
    def typed_parameters_and_network_fields(self):
        request = RESEARCH_REQUESTS[self.tool].model_validate(self.parameters)
        if self.tool != "target_http" and (self.service is not None or self.endpoint is not None):
            raise ValueError("Source/workspace tools require service=null and endpoint=null; they have no network scope")
        if self.tool == "target_http" and (not self.service or self.endpoint != request.path):
            raise ValueError("target_http requires the operator service ID and endpoint equal to parameters.path")
        return self


class ResearchTurn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(min_length=1, max_length=2000)
    hypothesis: str = Field(min_length=1, max_length=1000)
    uncertainties: list[str] = Field(default_factory=list, max_length=12)
    observation_refs: list[str] = Field(default_factory=list, max_length=64)
    finish: bool = False
    action: ResearchChoice | None = None
    candidates: list[ResearchCandidate] = Field(default_factory=list, max_length=8)
    source_claims: list[SourceProofClaim] = Field(default_factory=list, max_length=8)
    http_claims: list[HttpProofClaim] = Field(default_factory=list, max_length=8)

    @model_validator(mode="after")
    def one_choice(self, info: ValidationInfo):
        if self.finish == (self.action is not None):
            raise ValueError("Choose exactly one next action or finish")
        if any(len(value) > 1000 for value in self.uncertainties):
            raise ValueError("Uncertainty description is too long")
        if (info.context is not None and "observation_refs" in info.context
                and not set(self.observation_refs) <= set(info.context["observation_refs"])):
            raise ValueError("Use only persisted action IDs from observation_index, never future actions")
        return self


class ResearchObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str
    tool: str
    fingerprint: str
    workspace_revision: int
    evidence_ids: list[str]
    artifact_refs: list[str]
    execution_status: str
    exit_code: int | None
    observation: dict
    bytes_observed: int = Field(ge=0)
    # Describes raw persisted results, never a vulnerability verdict.
    category: Literal["observation", "failed_experiment"]


class ResearchProgress(BaseModel):
    model_config = ConfigDict(extra="forbid")
    model_calls: int = 0
    model_call_reservations: int = 0
    provider_usage: list[dict[str, int] | None] = Field(default_factory=list)
    model_diagnostic: str | None = None
    model_validation_errors: list[dict] = Field(default_factory=list)
    model_io_bytes: int = 0
    observation_bytes: int = 0
    write_bytes: int = 0
    workspace_revision: int = 0
    ledger: list[ResearchObservation] = Field(default_factory=list)
    turns: list[ResearchTurn] = Field(default_factory=list)
    candidates: list[ResearchCandidate] = Field(default_factory=list)
    candidate_rejections: list[str] = Field(default_factory=list)
    source_claims: list[SourceProofClaim] = Field(default_factory=list)
    http_claims: list[HttpProofClaim] = Field(default_factory=list)
