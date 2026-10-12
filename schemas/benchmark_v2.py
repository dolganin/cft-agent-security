"""A05 evaluator-only contracts extending, but never mutating, frozen A01/v1."""

from __future__ import annotations

import re
from pathlib import PurePosixPath
from typing import Literal

from pydantic import Field, model_validator

from schemas.benchmark import MeasurementModel, VerificationMetricsV2

BenchmarkSampleKind = Literal["original", "patched", "synthetic"]
BenchmarkSplit = Literal["development", "holdout"]
BenchmarkVerificationStatus = Literal[
    "not_run", "confirmed", "rejected", "inconclusive", "unsupported",
    "technical_error", "timeout", "policy_blocked",
]


class BenchmarkSourceAnchorV2(MeasurementModel):
    file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    role: str = "source"

    @model_validator(mode="after")
    def canonical_range(self):
        value = self.file.replace("\\", "/")
        path = PurePosixPath(value)
        if (
            not path.parts or path.is_absolute() or ".." in path.parts
            or re.match(r"^[A-Za-z]:", value) or path.as_posix() != value
        ):
            raise ValueError("V2 source anchor must use a canonical relative path")
        if self.line_end < self.line_start:
            raise ValueError("V2 source anchor range is reversed")
        return self


class BenchmarkHTTPAnchorV2(MeasurementModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] | None = None
    endpoint: str = Field(pattern=r"^/[^\s]*$")
    parameter: str | None = None


class BenchmarkEvaluationCaseV2(MeasurementModel):
    id: str = Field(pattern=r"^[A-Z0-9-]+$")
    expected: Literal["vulnerable", "safe"]
    family: str = Field(pattern=r"^[a-z][a-z0-9_-]+$")
    independence_group: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    sample_kind: BenchmarkSampleKind
    split: BenchmarkSplit
    service: str | None = None
    cwe: str | None = Field(default=None, pattern=r"^CWE-[1-9][0-9]*$")
    source_anchors: list[BenchmarkSourceAnchorV2] = Field(default_factory=list)
    http_anchors: list[BenchmarkHTTPAnchorV2] = Field(default_factory=list)
    expected_severity: str | None = None
    expected_context_priority: str | None = None

    @model_validator(mode="after")
    def anchored(self):
        if not self.source_anchors and not self.http_anchors:
            raise ValueError("V2 case requires at least one reviewed source or HTTP anchor")
        return self


class BenchmarkDatasetV2(MeasurementModel):
    schema_version: Literal["benchmark.dataset.v2"] = "benchmark.dataset.v2"
    id: str
    target_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    status: Literal["synthetic", "catalog_adapter_pending_a04", "frozen_a04"]
    family_aliases: dict[str, list[str]] = Field(default_factory=dict)
    cases: list[BenchmarkEvaluationCaseV2] = Field(min_length=1)

    @model_validator(mode="after")
    def independent_cases(self):
        ids: set[str] = set()
        units: set[tuple[str, str]] = set()
        for case in self.cases:
            if case.id in ids:
                raise ValueError("Duplicate V2 case ID")
            unit = (case.independence_group, case.sample_kind)
            if unit in units:
                raise ValueError("One independent cause may define only one case per slice")
            ids.add(case.id)
            units.add(unit)
        return self


class BenchmarkObservationV2(MeasurementModel):
    id: str
    source: str
    family: str
    service: str | None = None
    sample_kind: BenchmarkSampleKind = "original"
    source_file: str | None = None
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    http_method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] | None = None
    http_endpoint: str | None = None
    http_parameter: str | None = None
    verification: BenchmarkVerificationStatus = "not_run"
    reported_verdict: str | None = None
    evidence_backed: bool = False
    evidence: list[str] = Field(default_factory=list)
    capability: str | None = None
    severity: str | None = None
    context_priority: str | None = None

    @model_validator(mode="after")
    def coherent_anchors(self):
        if self.source_file is None and (self.line_start is not None or self.line_end is not None):
            raise ValueError("Source lines require a source file")
        if self.line_start is not None and self.line_end is not None and self.line_end < self.line_start:
            raise ValueError("Observation source range is reversed")
        if self.http_endpoint is not None and not self.http_endpoint.startswith("/"):
            raise ValueError("HTTP endpoint must be an absolute target path")
        if self.evidence_backed and self.verification not in {"confirmed", "rejected"}:
            raise ValueError("Only a binary verdict may be evidence-backed")
        return self


class BenchmarkMatchV2(MeasurementModel):
    observation_id: str
    case_id: str | None = None
    candidate_case_ids: list[str] = Field(default_factory=list)
    classification: Literal["tp", "fp", "duplicate", "unresolved", "outside_ground_truth"]


class DetectionMetricsV2(MeasurementModel):
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    duplicates: int = 0
    unresolved: int = 0
    outside_ground_truth: int = 0


class RubricMetricsV2(MeasurementModel):
    reviewed_cases: int = 0
    assessed_cases: int = 0
    correct_cases: int = 0
    accuracy: float | None = None
    assessed_coverage: float | None = None


class BenchmarkCaseResultV2(MeasurementModel):
    case_id: str
    expected: Literal["vulnerable", "safe"]
    family: str
    detected: bool
    primary_observation_id: str | None = None
    matched_observation_ids: list[str] = Field(default_factory=list)
    verification: str
    confirmation_supported: bool = False
    evidence: list[str] = Field(default_factory=list)
    severity: str | None = None
    context_priority: str | None = None


class BenchmarkScoreV2(MeasurementModel):
    schema_version: Literal["benchmark.score.v2"] = "benchmark.score.v2"
    dataset_id: str
    dataset_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    technically_valid: bool
    technical_errors: list[str] = Field(default_factory=list)
    detection: DetectionMetricsV2 | None
    verification: VerificationMetricsV2 | None
    severity: RubricMetricsV2 | None
    context_priority: RubricMetricsV2 | None
    matches: list[BenchmarkMatchV2]
    cases: list[BenchmarkCaseResultV2]


class BenchmarkArtifactHistoryV2(MeasurementModel):
    schema_version: Literal["benchmark.artifact_history.v2"] = "benchmark.artifact_history.v2"
    run_id: str
    attempt_id: str
    retry_of: str | None = None
    configurations: dict[str, object] = Field(default_factory=dict)
    versions: dict[str, object] = Field(default_factory=dict)
    reports: list[dict[str, object]] = Field(default_factory=list)
    plans: list[dict[str, object]] = Field(default_factory=list)
    validator_decisions: list[dict[str, object]] = Field(default_factory=list)
    action_proposals: list[dict[str, object]] = Field(default_factory=list)
    executions: list[dict[str, object]] = Field(default_factory=list)
    evidence: list[dict[str, object]] = Field(default_factory=list)
    agent_decisions: list[dict[str, object]] = Field(default_factory=list)
    errors: list[dict[str, object]] = Field(default_factory=list)
    retries: list[dict[str, object]] = Field(default_factory=list)
    artifact_sha256: dict[str, str] = Field(default_factory=dict)
