"""External measurement contracts; never part of AgentState or TargetProfile."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class MeasurementModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BenchmarkCase(MeasurementModel):
    id: str = Field(pattern=r"^[A-Z0-9-]+$")
    expected: Literal["vulnerable", "safe"]
    category: str = Field(pattern=r"^[a-z][a-z0-9-]+$")
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]*$")
    artifact: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    endpoint: str | None = None
    service: str | None = None
    verification_capability: str | None = None
    rationale: str = Field(min_length=20)
    provenance: list[str] = Field(min_length=1)

    @field_validator("artifact")
    @classmethod
    def canonical_artifact(cls, value):
        value = value.replace("\\", "/")
        path = PurePosixPath(value)
        if (
            not path.parts
            or path.is_absolute()
            or ".." in path.parts
            or re.match(r"^[A-Za-z]:", value)
        ):
            raise ValueError("Ground truth artifact must be relative to target")
        return path.as_posix()

    @model_validator(mode="after")
    def valid_range(self):
        if self.line_end < self.line_start:
            raise ValueError("Reversed source range")
        return self


class BenchmarkDataset(MeasurementModel):
    id: str
    version: Literal["1"] = "1"
    target_name: str
    target_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    scope: str = Field(min_length=20)
    exhaustive: bool = False
    negative_universe: bool = False
    line_tolerance: Literal[0] = 0
    family_aliases: dict[str, list[str]] = Field(default_factory=dict)
    cases: list[BenchmarkCase] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_cases(self):
        ids, locations = set(), set()
        for case in self.cases:
            location = (
                PurePosixPath(case.artifact.replace("\\", "/")).as_posix(),
                case.line_start,
                case.line_end,
                case.category,
            )
            if case.id in ids or location in locations:
                raise ValueError("Duplicate case ID or location/family")
            ids.add(case.id)
            locations.add(location)
            if case.expected == "safe" and not self.negative_universe:
                raise ValueError("Safe cases require an explicit negative universe")
        return self


class BenchmarkObservation(MeasurementModel):
    """Producer-neutral normalized measurement, retaining original verdict."""

    id: str
    source: str
    artifact: str
    line_start: int | None = None
    line_end: int | None = None
    family: str
    service: str | None = None
    verification: Literal[
        "not_run",
        "confirmed",
        "rejected",
        "inconclusive",
        "unsupported",
        "technical_error",
        "timeout",
        "policy_blocked",
    ] = "not_run"
    reported_verdict: str | None = None
    evidence_backed: bool = False
    confirmation_sources: list[Literal["static", "runtime"]] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    capability: str | None = None


class BenchmarkMatch(MeasurementModel):
    observation_id: str
    case_id: str | None = None
    classification: Literal["tp", "fp", "duplicate", "outside_ground_truth", "unreviewed"]


class DetectionMetrics(MeasurementModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int | None = None
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    specificity: float | None = None
    duplicates: int = 0
    duplicate_rate: float | None = None
    unique_findings: int = 0
    outside_ground_truth: int = 0
    unreviewed: int = 0


class VerificationMetrics(MeasurementModel):
    statuses: dict[str, int] = Field(default_factory=dict)
    correctly_confirmed: int = 0
    runtime_confirmed_positives: int = 0
    source_confirmed_positives: int = 0
    false_confirmations: int = 0
    invalid_confirmation_claims: int = 0
    unreviewed_confirmations: int = 0
    unsupported_known_positives: int = 0
    confirmation_rate: float | None = None
    end_to_end_verified_recall: float | None = None
    false_confirmation_rate: float | None = None


class BenchmarkCaseResult(MeasurementModel):
    case_id: str
    expected: str
    category: str
    detected: bool | None
    finding_id: str | None = None
    detection_source: str | None = None
    verification: str = "not_detected"
    reported_verdict: str | None = None
    evidence: list[str] = Field(default_factory=list)
    confirmation_supported: bool = False
    all_matched_findings: list[str] = Field(default_factory=list)


class BenchmarkScore(MeasurementModel):
    detection: DetectionMetrics
    verification: VerificationMetrics
    matches: list[BenchmarkMatch]
    cases: list[BenchmarkCaseResult]


class BenchmarkRunResult(MeasurementModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: str
    producer: str = "pentester"
    configuration_digest: str
    status: Literal["completed", "technical_failure"]
    baseline: BenchmarkScore | None = None
    detection: BenchmarkScore | None = None
    performance: dict[str, float | int | None] = Field(default_factory=dict)
    diagnostics: list[str] = Field(default_factory=list)


class BenchmarkAggregate(MeasurementModel):
    configuration_digest: str
    attempted_runs: int
    completed_runs: int
    technical_failure_rate: float | None
    numeric: dict[str, dict[str, float]]
    stability: dict[str, dict]
    stability_summary: dict[str, int] = Field(default_factory=dict)
    runs: list[BenchmarkRunResult]
