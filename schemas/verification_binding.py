"""Operator-owned route maps and serializable B01 execution provenance."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class SourceSelector(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    file: str
    anchor: str = Field(min_length=1, max_length=4096)
    extent: Literal["anchor", "function"] = "anchor"

    @field_validator("file")
    @classmethod
    def canonical_file(cls, value):
        from security.source_paths import normalize_source_path
        return normalize_source_path(value)


class VerificationRoute(BaseModel):
    """Each selector is an explicit operator-reviewed caller/helper relationship."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
    handler_id: str = Field(min_length=1, max_length=128)
    family: str = Field(min_length=1)
    service: str
    endpoint: str
    method: Literal["GET", "POST"]
    tool: Literal["verify_sql_injection", "verify_sensitive_directory"]
    check: Literal["sql_interpolation", "source_metadata"]
    mode: Literal["search", "authentication"] | None = None
    registration: SourceSelector
    sources: list[SourceSelector] = Field(min_length=1, max_length=16)


class VerificationBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["verification.binding.b01.v1"] = "verification.binding.b01.v1"
    route_id: str
    handler_id: str
    target: str
    finding_id: str
    family: str
    source_file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    anchor_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_snapshot: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_files: dict[str, str]
    map_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    service: str
    endpoint: str
    method: Literal["GET", "POST"]
    tool: str
    check: str
    mode: str | None = None


class BindingResolution(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["bound", "inconclusive"]
    reason: str
    candidates: list[str] = Field(default_factory=list)
    binding: VerificationBinding | None = None
