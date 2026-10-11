"""A02 evaluator-only catalog contracts; not Findings, Evidence or frozen truth."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from schemas.benchmark import MeasurementModel
from security.source_paths import normalize_source_path


class CatalogAnchor(MeasurementModel):
    file: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    role: Literal["source", "sink", "helper", "caller", "model", "registration", "template", "provenance"]
    file_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    region_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    required_tokens: list[str] = Field(min_length=1)

    @model_validator(mode="after")
    def canonical_range(self):
        if normalize_source_path(self.file) != self.file or self.line_end < self.line_start:
            raise ValueError("Catalog source anchor requires a canonical relative path/range")
        return self


class CatalogHTTPAnchor(MeasurementModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    endpoint: str = Field(pattern=r"^/[^\s]*$")
    parameter: str | None
    basis: Literal["direct_express", "middleware_mount", "finale_generated"]
    registration: CatalogAnchor


class CatalogRelation(MeasurementModel):
    from_anchor: int = Field(ge=0)
    to_anchor: int = Field(ge=0)
    relation: Literal["calls", "renders", "stores", "supplies", "registers"]


class CatalogProvenance(MeasurementModel):
    kind: Literal["challenge_metadata", "source_annotation", "source_code", "upstream_test"]
    anchor: CatalogAnchor
    explanation: str = Field(min_length=10)


class PositiveCatalogCase(MeasurementModel):
    id: str = Field(pattern=r"^JS-[A-Z0-9-]+$")
    expected: Literal["vulnerable"] = "vulnerable"
    category: str = Field(pattern=r"^[a-z][a-z0-9-]+$")
    cwe: str | None = Field(default=None, pattern=r"^CWE-[1-9][0-9]*$")
    independence_group: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    root_cause_key: str = Field(pattern=r"^[a-z][a-z0-9-]+$")
    root_cause_summary: str = Field(min_length=30)
    primary_candidate: str
    challenge_keys: list[str] = Field(min_length=1)
    source_anchors: list[CatalogAnchor] = Field(min_length=1)
    http_anchors: list[CatalogHTTPAnchor]
    client_route: str | None = None
    relations: list[CatalogRelation] = Field(default_factory=list)
    service: str
    runtime_prerequisites: list[str] = Field(min_length=1)
    required_identity: str | None
    expected_vulnerable_effect: str = Field(min_length=20)
    verification_criterion: str = Field(min_length=30)
    provenance: list[CatalogProvenance] = Field(min_length=2)
    runtime_eligible: bool
    eligibility_reason: str = Field(min_length=20)
    detection_only_eligible: bool
    future_runtime_evaluation: Literal["possible_with_reviewed_environment", "unknown"]
    execution_restrictions: list[str] = Field(min_length=1)
    review_status: Literal["source_reviewed_positive"]
    reviewer_status: Literal["single_reviewer_pending_independent_review"]
    review_basis: str = Field(min_length=30)
    split: Literal["development", "holdout"]

    @model_validator(mode="after")
    def coherent_case(self):
        if self.primary_candidate not in self.challenge_keys:
            raise ValueError("Primary candidate must be a referenced challenge")
        if len(self.challenge_keys) != len(set(self.challenge_keys)):
            raise ValueError("Duplicate challenge references")
        if not any(a.role == "sink" for a in self.source_anchors):
            raise ValueError("Positive root cause needs a decisive sink anchor")
        for relation in self.relations:
            if max(relation.from_anchor, relation.to_anchor) >= len(self.source_anchors):
                raise ValueError("Relation refers to a missing source anchor")
        return self


class PositiveCatalog(MeasurementModel):
    schema_version: Literal["benchmark.positive_catalog.a02.v1"]
    target_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    protocol_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    status: Literal["A02_source_reviewed_not_A04_frozen_ground_truth"]
    reviewer_status: Literal["single_reviewer_pending_independent_review"]
    cases: list[PositiveCatalogCase] = Field(min_length=1)

    @model_validator(mode="after")
    def independent_cases(self):
        for field in ("id", "independence_group", "root_cause_key"):
            values = [getattr(c, field) for c in self.cases]
            if len(values) != len(set(values)):
                raise ValueError("Duplicate positive catalog " + field)
        for i, case in enumerate(self.cases):
            for other in self.cases[i + 1:]:
                if case.category == other.category and any(
                    a.file == b.file and a.line_start <= b.line_end and b.line_start <= a.line_end
                    for a in case.source_anchors if a.role == "sink"
                    for b in other.source_anchors if b.role == "sink"
                ):
                    raise ValueError("Overlapping root-cause sink/family anchors require review")
        return self


class CatalogExclusion(MeasurementModel):
    candidate_key: str
    reason: Literal[
        "duplicate_root_cause", "not_security_vulnerability", "requires_external_service",
        "unsafe_to_execute", "docker_disabled", "no_reliable_source_anchor",
        "no_reliable_runtime_or_source_truth", "pure_game_or_osint",
        "same_independence_group_as_existing_case", "unsupported_environment_but_kept_for_future",
        "other",
    ]
    detail: str = Field(min_length=30)
    represented_by: list[str] = Field(default_factory=list)
    not_a_negative_label: Literal[True] = True


class ExcludedCatalog(MeasurementModel):
    schema_version: Literal["benchmark.exclusions.a02.v1"]
    target_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    exclusions: list[CatalogExclusion]
