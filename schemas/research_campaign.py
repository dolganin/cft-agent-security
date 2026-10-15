"""R05 shared question queue, distinct from vulnerability findings."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from schemas.finding import Finding
from schemas.research import request_path


class RuntimeScannerObservation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(min_length=1, max_length=128)
    source: str = Field(min_length=1, max_length=128)
    rule_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=1000)
    description: str = Field(min_length=1, max_length=2000)
    service: str = Field(min_length=1, max_length=128)
    endpoint: str = Field(min_length=1, max_length=2048)
    artifact_ref: str = Field(min_length=1, max_length=512)
    _endpoint = field_validator("endpoint")(request_path)


class ResearchQuestion(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    finding: Finding
    origin: Literal["sast", "dast", "model", "surface"]
    is_candidate: bool
    status: Literal["pending", "researched", "failed", "unavailable", "grouped"] = "pending"
    route_ids: list[str] = Field(default_factory=list)
    runtime_observation: RuntimeScannerObservation | None = None


class CampaignLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    max_questions: int = Field(default=4, ge=1, le=64)
    max_model_calls: int = Field(default=32, ge=1, le=256)
    max_actions: int = Field(default=32, ge=1, le=256)
    wall_seconds: int = Field(default=600, ge=1, le=3600)
    max_model_io_bytes: int = Field(default=8388608, ge=4096, le=67108864)
    max_observation_bytes: int = Field(default=4194304, ge=1024, le=16777216)
    max_write_bytes: int = Field(default=1048576, ge=0, le=4194304)
    dev_preferred_families: list[str] = Field(default_factory=list, max_length=8)
    max_consecutive_model_failures: int = Field(default=3, ge=1, le=8)
    max_http_requests: int = Field(default=256, ge=0, le=1024)
