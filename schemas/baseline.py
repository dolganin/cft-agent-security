"""A06 operator configuration, outside production target and agent contracts."""
from typing import Literal

from pydantic import Field, field_validator

from schemas.benchmark import MeasurementModel
from schemas.target import is_repository_digest


class ScannerBudgets(MeasurementModel):
    sast_seconds: int = Field(default=600, ge=30, le=1800)
    startup_seconds: int = Field(default=180, ge=30, le=600)
    spider_seconds: int = Field(default=60, ge=10, le=300)
    ajax_seconds: int = Field(default=60, ge=10, le=300)
    active_seconds: int = Field(default=180, ge=10, le=900)
    passive_seconds: int = Field(default=180, ge=10, le=300)
    passive_body_bytes: int = Field(default=262144, ge=16384, le=1048576)
    max_urls: int = Field(default=200, ge=10, le=1000)
    max_alerts: int = Field(default=10000, ge=100, le=50000)


class ScannerProfile(MeasurementModel):
    schema_version: Literal["baseline.profile.a06.v1"] = "baseline.profile.a06.v1"
    target_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    target_image: str
    semgrep_image: str
    zap_image: str
    role: Literal["anonymous"] = "anonymous"
    rules_file: Literal["semgrep-rules.yaml"] = "semgrep-rules.yaml"
    budgets: ScannerBudgets = Field(default_factory=ScannerBudgets)
    # Public application navigation seeds, not evaluator anchors or attack payloads.
    seeds: list[str] = Field(min_length=1, max_length=50)

    @field_validator("target_image", "semgrep_image", "zap_image")
    @classmethod
    def immutable_image(cls, value):
        if not is_repository_digest(value):
            raise ValueError("Scanner images require immutable repository digests")
        return value

    @field_validator("seeds")
    @classmethod
    def local_paths(cls, values):
        if len(set(values)) != len(values) or any(
            not p.startswith("/") or p.startswith("//") or "\\" in p
            or any(ord(c) < 33 for c in p) for p in values
        ):
            raise ValueError("Seeds must be unique local application paths")
        return values
