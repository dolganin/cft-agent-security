"""C04 bounded repair campaign; C02/C03 remain the authoritative artifacts."""
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class RepairLimits(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    max_attempts: int = Field(default=3, ge=1, le=5, strict=True)
    wall_clock_seconds: float = Field(default=3600, ge=1, le=14400)


class RepairFeedback(BaseModel):
    model_config = ConfigDict(extra="forbid")
    attempt: int = Field(ge=1, le=5)
    stage: Literal["generation", "verification"]
    code: Literal["invalid_diff_format_or_window", "finding_id_mismatch", "invalid_structured_output",
                  "NOT_FIXED", "REGRESSION", "AFTER_BUILD_FAILED", "AFTER_TESTS_FAILED"]
    summary: str = Field(max_length=600)
    previous_patch_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class RepairAttempt(BaseModel):
    model_config = ConfigDict(extra="forbid")
    number: int = Field(ge=1, le=5)
    directory: str
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int = Field(default=0, ge=0)
    generation_ms: int = Field(default=0, ge=0)
    verification_ms: int = Field(default=0, ge=0)
    source_snapshot: dict = Field(default_factory=dict)
    workspace_cleanup: bool = False
    generation_status: str | None = None
    generation_reason: str | None = None
    response_patch_sha256: str | None = None
    patch_sha256: str | None = None
    patched_file_sha256: str | None = None
    verification_status: str | None = None
    decision: Literal["pending", "retry", "fixed", "duplicate", "stop"] = "pending"
    reason: str = "attempt_started"
    feedback: RepairFeedback | None = None


class RepairRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["cft.c04.v1"] = "cft.c04.v1"
    family: Literal["sql-search", "redirect-allowlist"]
    limits: RepairLimits
    status: Literal["FIXED", "NOT_FIXED", "TECHNICAL_ERROR", "INTERRUPTED"] = "TECHNICAL_ERROR"
    stop_reason: str = "preflight_failed"
    started_at: datetime
    finished_at: datetime | None = None
    duration_ms: int = Field(default=0, ge=0)
    original_snapshot: dict = Field(default_factory=dict)
    original_unchanged: bool = False
    attempts: list[RepairAttempt] = Field(default_factory=list)
    successful_attempt: int | None = None
