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


# V2 is evaluator-only. The historical models and their serialized defaults above
# deliberately remain unchanged; neither version enters production contracts.
V2_METRIC_TERMS = {
    "confirmed_precision": ("correct_confirmations", "confirmed_cases"),
    "supported_verified_recall": ("correct_confirmations", "positive_cases"),
    "false_confirmation_rate": ("false_confirmations", "negative_cases"),
    "answered_accuracy": ("correct_decisions", "decided_cases"),
    "decision_coverage": ("decided_cases", "labeled_cases"),
    "abstention_rate": ("abstained_cases", "labeled_cases"),
    "detection_precision": ("detection_tp", "detection_tp + detection_fp"),
    "detection_recall": ("detection_tp", "detection_tp + detection_fn"),
    "detection_f1": ("2 * detection_precision * detection_recall",
                     "detection_precision + detection_recall"),
    "technical_failure_rate": ("invalid_attempts", "all_attempts"),
    "severity_accuracy": ("correct_severity_labels", "assessed_severity_cases"),
    "severity_assessed_coverage": ("assessed_severity_cases", "reviewed_severity_cases"),
    "context_priority_accuracy": ("correct_context_labels", "assessed_context_cases"),
    "context_priority_assessed_coverage": ("assessed_context_cases", "reviewed_context_cases"),
}


class MetricDefinition(MeasurementModel):
    layer: Literal["verification", "detection", "technical", "rubric"]
    numerator: str = Field(min_length=1)
    denominator: str = Field(min_length=1)
    undefined: Literal["null"]
    note: str = Field(min_length=1)


class CaseUnitPolicy(MeasurementModel):
    unit: Literal["independent_security_root_cause"]
    group_field: Literal["independence_group"]
    positive_limit_per_group_and_slice: Literal[1]
    max_tp_per_case: Literal[1]
    max_primary_cases_per_finding: Literal[1]
    anchors: list[Literal["source", "http", "caller_helper"]] = Field(min_length=3, max_length=3)
    variants: Literal["same_group_separate_original_patched_synthetic_slices"]
    duplicates: Literal["extra_compatible_findings_never_extra_tp"]


class VerdictPolicy(MeasurementModel):
    decided: list[Literal["confirmed", "rejected"]] = Field(min_length=2, max_length=2)
    evidence: Literal["matching_verdict_high_or_medium_persisted_execution_and_audit"]
    conflicts: Literal["inconclusive_preserve_all_evidence"]
    missing_detection: Literal["not_detected_abstention_never_rejected"]
    unbacked_decision: Literal["invalid_evidence_abstention"]
    abstentions: list[str] = Field(min_length=9, max_length=9)
    reason_selection: Literal["primary_observation_unless_valid_duplicate_decides"]
    unknown: Literal["outside_ground_truth_or_unreviewed_excluded_retained_counted"]
    run_invalid: Literal["TECHNICALLY_INVALID_excluded_from_security_metrics"]
    run_invalid_examples: list[str] = Field(min_length=5)
    case_error: Literal["abstention_no_runtime_error_as_detection_fn"]

    @model_validator(mode="after")
    def complete_statuses(self):
        if set(self.decided) != {"confirmed", "rejected"} or set(self.abstentions) != {
            "inconclusive", "unsupported", "timeout", "policy_blocked", "technical_error",
            "not_detected", "not_run", "invalid_evidence", "conflicting_evidence",
        }:
            raise ValueError("V2 verdict/abstention statuses must be complete and disjoint")
        return self


class SplitPolicy(MeasurementModel):
    algorithm: Literal["sha256_seed_nul_group_uint256_threshold"]
    seed: str = Field(min_length=1)
    development_percent: Literal[70]
    group_field: Literal["independence_group"]
    assignment: Literal["development_if_hash_times_100_lt_70_times_2pow256_else_holdout"]
    encoding: Literal["utf8_exact_no_normalization"]
    freeze: Literal["before_tuning_no_score_based_reassignment"]
    families: Literal["report_actual_distribution_no_post_score_rebalancing"]


class FreezePolicy(MeasurementModel):
    protocol: Literal["A01_raw_bytes_sha256"]
    dataset: Literal["A04_new_dataset_lock_no_overwrite"]
    scanners: Literal["A06"]
    changes: Literal["new_version_changelog_reason_new_digest_preserve_old_locks_and_results"]
    discovered_unknown: Literal["review_only_for_new_dataset_version"]


class RepeatPolicy(MeasurementModel):
    real_independent_runs: Literal[3]
    unchanged: list[str] = Field(min_length=9)
    retries: Literal["retain_attempt_reason_error_retry_of_never_silently_replace"]
    aggregate: Literal["valid_runs_only_report_attempts_failure_rate_and_na_counts"]
    independence: Literal["fresh_run_directory_and_reset_target_state_each_attempt"]

    @field_validator("unchanged")
    @classmethod
    def fixed_series_inputs(cls, values):
        if set(values) != {
            "ground_truth", "matching", "split", "target_commit", "model", "budgets",
            "policies", "scanner_configuration", "producer_configuration",
        } or len(values) != 9:
            raise ValueError("Every repeated-series input must be frozen")
        return values


class BaselineConfigurationV2(MeasurementModel):
    source: str
    profile: str
    policy: str
    settings: dict[str, str | bool | int | float]
    max_iterations: int = Field(ge=1)
    llm_transport: dict[str, str | bool | int | float]
    deterministic_limits: dict[str, int | float]
    required_images: list[str] = Field(min_length=1)
    worker_image: str
    input_digest_encoding: Literal["historical_v1_raw_other_text_lf"]
    input_digests: dict[str, str]

    @field_validator("settings")
    @classmethod
    def complete_settings(cls, values):
        text = {"agent_mode", "llm_routes", "llm_reasoning_effort", "sandbox_image"}
        boolean = {"llm_allow_external_fallbacks"}
        numeric = {
            "llm_max_output_tokens", "llm_timeout_seconds", "scout_max_turns",
            "scout_max_candidates", "scout_max_source_chars", "scout_wall_clock_seconds",
            "agent_wall_clock_seconds", "executor_timeout_seconds", "executor_cpu_time_seconds",
            "executor_memory_mb", "executor_max_file_bytes", "executor_max_processes",
            "executor_max_output_bytes", "executor_max_runs_per_action", "executor_max_concurrent_runs",
        }
        if set(values) != text | boolean | numeric:
            raise ValueError("Baseline requires exactly the non-secret frozen settings")
        if any(not isinstance(values[k], str) or not values[k] for k in text):
            raise ValueError("Baseline text settings must be nonempty")
        if any(type(values[k]) is not bool for k in boolean) or any(
            type(values[k]) not in {int, float} or values[k] <= 0 for k in numeric
        ):
            raise ValueError("Baseline budget/settings types or ranges are invalid")
        if values["agent_mode"] != "llm" or values["llm_reasoning_effort"] not in {"low", "high", "max"}:
            raise ValueError("Baseline must use the real LLM adapter")
        return values

    @field_validator("deterministic_limits")
    @classmethod
    def positive_limits(cls, values):
        if not values or any(value <= 0 for value in values.values()):
            raise ValueError("Deterministic baseline limits must be positive")
        return values

    @field_validator("required_images", "worker_image")
    @classmethod
    def pinned_images(cls, values):
        from schemas.target import is_repository_digest

        if any(not is_repository_digest(value) for value in
               (values if isinstance(values, list) else [values])):
            raise ValueError("Baseline images require immutable repository digests")
        return values

    @field_validator("input_digests")
    @classmethod
    def valid_digests(cls, values):
        if not values or any(not re.fullmatch(r"[a-f0-9]{64}", v) for v in values.values()):
            raise ValueError("Baseline inputs require SHA-256 digests")
        return values


class BenchmarkProtocolV2(MeasurementModel):
    schema_version: Literal["benchmark.protocol.v2"]
    dataset_id: Literal["juice-shop-v20.2.0-v2"]
    dataset_version: Literal["2"]
    ground_truth_status: Literal["pending_A02_A03_A04"]
    target_name: Literal["OWASP Juice Shop v20.2.0"]
    target_commit: str = Field(pattern=r"^[a-f0-9]{40}$")
    scope: str = Field(min_length=20)
    slices: list[Literal["original", "patched", "synthetic"]] = Field(min_length=3, max_length=3)
    case_unit: CaseUnitPolicy
    matching: Literal["reuse_v1_normalized_file_inclusive_range_family_declared_service_maximum_matching"]
    matching_extensions: Literal["review_explicit_anchors_before_A04_no_new_matcher_in_A01"]
    line_tolerance: Literal[0]
    detection_counts: list[Literal["detection_tp", "detection_fp", "detection_fn", "detection_tn"]]
    negative_universe: Literal["explicit_labeled_controls_only_tn_otherwise_null"]
    verdicts: VerdictPolicy
    metrics: dict[str, MetricDefinition]
    split: SplitPolicy
    freeze: FreezePolicy
    repeats: RepeatPolicy
    baseline: BaselineConfigurationV2
    leakage: list[str] = Field(min_length=7)
    rubric: Literal["independent_reviewed_labels_only_no_difficulty_scanner_challenge_confidence_proxy"]
    history: Literal["v1_byte_identical_development_regression_never_relabel_or_rescore_as_history"]

    @model_validator(mode="after")
    def fixed_metric_semantics(self):
        if set(self.metrics) != set(V2_METRIC_TERMS):
            raise ValueError("Missing or unknown V2 metric definition")
        for name, terms in V2_METRIC_TERMS.items():
            definition = self.metrics[name]
            if (definition.numerator, definition.denominator) != terms:
                raise ValueError("V2 formula mismatch: " + name)
            layer = (
                "detection" if name.startswith("detection_") else
                "technical" if name == "technical_failure_rate" else
                "rubric" if name.startswith(("severity_", "context_priority_")) else
                "verification"
            )
            if definition.layer != layer:
                raise ValueError("V2 metric layer mismatch: " + name)
        if set(self.slices) != {"original", "patched", "synthetic"}:
            raise ValueError("All sample slices must be reported separately")
        if set(self.case_unit.anchors) != {"source", "http", "caller_helper"}:
            raise ValueError("Anchor kinds must be distinct")
        if set(self.detection_counts) != {
            "detection_tp", "detection_fp", "detection_fn", "detection_tn",
        }:
            raise ValueError("Detection diagnostic counts are required")
        if set(self.leakage) != {
            "expected_labels", "split_labels", "ground_truth_answers", "expected_verdicts",
            "nonproduction_expected_anchors", "safe_vulnerable_status", "protocol_metadata",
        } or len(self.leakage) != 7:
            raise ValueError("Every truth/protocol metadata category must remain evaluator-only")
        return self


class BenchmarkCaseV2(BenchmarkCase):
    """Future reviewed cases; group metadata belongs only to the evaluator.

    Multiple anchors are a protocol concept for A02/A04. This contract retains
    the existing source anchor rather than implementing a new matcher in A01.
    """

    independence_group: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
    sample_kind: Literal["original", "patched", "synthetic"] = "original"


class VerificationMetricsV2(MeasurementModel):
    schema_version: Literal["benchmark.verification.v2"] = "benchmark.verification.v2"
    counts: dict[str, int]
    abstention_reasons: dict[str, int]
    confirmed_precision: float | None
    supported_verified_recall: float | None
    false_confirmation_rate: float | None
    answered_accuracy: float | None
    decision_coverage: float | None
    abstention_rate: float | None
