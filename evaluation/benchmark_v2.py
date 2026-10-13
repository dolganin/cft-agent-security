"""A05 deterministic extension of the frozen benchmark scorer utilities."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter

from evaluation.benchmark import normalize_path, ratio
from schemas.benchmark import VerificationMetricsV2
from schemas.benchmark_v2 import (
    BenchmarkCaseResultV2,
    BenchmarkDatasetV2,
    BenchmarkMatchV2,
    BenchmarkObservationV2,
    BenchmarkScoreV2,
    DetectionMetricsV2,
    RubricMetricsV2,
)


def _canonical_family(value: str, aliases: dict[str, list[str]]) -> str:
    value = value.lower().replace("_", "-")
    candidates = {
        name.lower().replace("_", "-")
        for name, names in aliases.items()
        if value == name.lower().replace("_", "-")
        or value in {item.lower().replace("_", "-") for item in names}
    }
    return next(iter(candidates)) if len(candidates) == 1 else value


def _family_candidates(value: str, aliases: dict[str, list[str]]) -> set[str]:
    value = value.lower().replace("_", "-")
    candidates = {
        name.lower().replace("_", "-")
        for name, names in aliases.items()
        if value == name.lower().replace("_", "-")
        or value in {item.lower().replace("_", "-") for item in names}
    }
    return candidates or {value}


def _route(value: str) -> str:
    value = value.split("?", 1)[0].rstrip("/") or "/"
    return re.sub(r"(?::[^/]+|\{[^/]+\})", "{}", value)


def _candidates(
    dataset: BenchmarkDatasetV2,
    observation: BenchmarkObservationV2,
    *,
    cases: list,
):
    observed_families = _family_candidates(observation.family, dataset.family_aliases)
    candidates = []
    for case in cases:
        if _canonical_family(case.family, dataset.family_aliases) not in observed_families:
            continue
        if case.sample_kind != observation.sample_kind:
            continue
        if case.service is not None and case.service != observation.service:
            continue
        source_match = any(
            observation.source_file is not None
            and normalize_path(observation.source_file) == normalize_path(anchor.file)
            and observation.line_start is not None
            and observation.line_start <= anchor.line_end
            and anchor.line_start <= (observation.line_end or observation.line_start)
            for anchor in case.source_anchors
        )
        http_match = any(
            observation.http_endpoint is not None
            and _route(observation.http_endpoint) == _route(anchor.endpoint)
            and (
                anchor.method is None
                or anchor.method == observation.http_method
            )
            and (
                anchor.parameter is None
                or anchor.parameter == observation.http_parameter
            )
            for anchor in case.http_anchors
        )
        if source_match or http_match:
            candidates.append(case.id)
    return sorted(candidates)


def _rubric_metrics(cases, primary, by_id, expected_field, observed_field):
    reviewed = [case for case in cases if getattr(case, expected_field) is not None]
    assessed = []
    correct = 0
    for case in reviewed:
        observation = by_id.get(primary.get(case.id))
        value = getattr(observation, observed_field) if observation else None
        if value is None or value.upper() in {"N/A", "UNKNOWN", "UNASSESSED"}:
            continue
        assessed.append(case)
        correct += int(value.lower() == getattr(case, expected_field).lower())
    return RubricMetricsV2(
        reviewed_cases=len(reviewed),
        assessed_cases=len(assessed),
        correct_cases=correct,
        accuracy=ratio(correct, len(assessed)),
        assessed_coverage=ratio(len(assessed), len(reviewed)),
    )


def score_v2(
    dataset: BenchmarkDatasetV2,
    observations: list[BenchmarkObservationV2],
    *,
    technically_valid: bool = True,
    technical_errors: list[str] | None = None,
    split: str | None = None,
    sample_kind: str | None = None,
) -> BenchmarkScoreV2:
    """Score reviewed anchors deterministically without execution or model judging."""
    available_splits = {case.split for case in dataset.cases}
    available_kinds = {case.sample_kind for case in dataset.cases}
    if split is None:
        if len(available_splits) != 1:
            raise ValueError("Mixed DEV/HOLDOUT cases must be scored separately")
        split = next(iter(available_splits))
    if sample_kind is None:
        if len(available_kinds) != 1:
            raise ValueError("Mixed sample kinds must be scored separately")
        sample_kind = next(iter(available_kinds))
    selected_cases = [
        case for case in dataset.cases
        if case.split == split and case.sample_kind == sample_kind
    ]
    if not selected_cases:
        raise ValueError(f"No benchmark cases for {split}/{sample_kind}")
    ordered = sorted(
        (item for item in observations if item.sample_kind == sample_kind),
        key=lambda item: (
            item.source_file or "",
            item.line_start or 0,
            item.line_end or item.line_start or 0,
            item.family,
            item.id,
            item.model_dump_json(),
        ),
    )
    by_id = {item.id: item for item in ordered}
    if len(by_id) != len(ordered):
        raise ValueError("Observation IDs must be unique")
    cases = {case.id: case for case in selected_cases}
    edges = {
        item.id: _candidates(dataset, item, cases=selected_cases)
        for item in ordered
    }
    def maximum_matching(observation_ids: list[str], blocked_case: str | None = None):
        case_owner: dict[str, str] = {}

        def assign(observation_id: str, visited: set[str]) -> bool:
            for case_id in edges[observation_id]:
                if case_id == blocked_case or case_id in visited:
                    continue
                visited.add(case_id)
                previous = case_owner.get(case_id)
                if previous is None or assign(previous, visited):
                    case_owner[case_id] = observation_id
                    return True
            return False

        for observation_id in observation_ids:
            assign(observation_id, set())
        return case_owner

    observation_ids = [item.id for item in ordered]
    matched_cases = maximum_matching(observation_ids)
    matched_by_observation = {observation_id: case_id for case_id, observation_id in matched_cases.items()}
    maximum_size = len(matched_cases)
    possible_cases: dict[str, set[str]] = {}
    for observation_id in observation_ids:
        if len(edges[observation_id]) < 2 or observation_id not in matched_by_observation:
            continue
        alternatives = set()
        others = [item for item in observation_ids if item != observation_id]
        for case_id in edges[observation_id]:
            if 1 + len(maximum_matching(others, blocked_case=case_id)) == maximum_size:
                alternatives.add(case_id)
        possible_cases[observation_id] = alternatives

    unresolved_ids = {
        observation_id for observation_id, alternatives in possible_cases.items()
        if len(alternatives) > 1
    }
    primary = {
        case_id: observation_id
        for case_id, observation_id in matched_cases.items()
        if observation_id not in unresolved_ids
    }
    matches = []
    for observation in ordered:
        candidates = edges[observation.id]
        case_id = matched_by_observation.get(observation.id)
        if case_id is None and not candidates:
            classification = "outside_ground_truth"
        elif observation.id in unresolved_ids:
            # More than one assignment occurs in an equally large valid matching;
            # never let case labels or verdicts resolve that ambiguity.
            case_id = None
            classification = "unresolved"
        elif case_id is not None:
            classification = "tp" if cases[case_id].expected == "vulnerable" else "fp"
        elif candidates:
            resolved_candidates = [candidate for candidate in candidates if candidate in primary]
            if resolved_candidates:
                case_id = resolved_candidates[0]
                classification = "duplicate"
            else:
                case_id = None
                classification = "unresolved"
        matches.append(BenchmarkMatchV2(
            observation_id=observation.id,
            case_id=case_id,
            candidate_case_ids=candidates,
            classification=classification,
        ))

    counts = Counter(match.classification for match in matches)
    positives = sum(case.expected == "vulnerable" for case in selected_cases)
    negatives = len(selected_cases) - positives
    detected_positives = sum(cases[case_id].expected == "vulnerable" for case_id in primary)
    detected_negatives = sum(cases[case_id].expected == "safe" for case_id in primary)
    detection = DetectionMetricsV2(
        tp=detected_positives,
        fp=detected_negatives,
        fn=positives - detected_positives,
        tn=negatives - detected_negatives,
        precision=ratio(detected_positives, detected_positives + detected_negatives),
        recall=ratio(detected_positives, positives),
        duplicates=counts["duplicate"],
        unresolved=counts["unresolved"],
        outside_ground_truth=counts["outside_ground_truth"],
    )
    if detection.precision is not None and detection.recall is not None:
        total = detection.precision + detection.recall
        detection.f1 = 2 * detection.precision * detection.recall / total if total else 0.0

    linked = {case.id: [] for case in selected_cases}
    for match in matches:
        if match.case_id is not None:
            linked[match.case_id].append(by_id[match.observation_id])
    verdict_counts = Counter({
        "labeled_cases": len(selected_cases),
        "positive_cases": positives,
        "negative_cases": negatives,
        "confirmed_cases": 0,
        "rejected_cases": 0,
        "decided_cases": 0,
        "correct_confirmations": 0,
        "false_confirmations": 0,
        "correct_rejections": 0,
        "false_rejections": 0,
        "correct_decisions": 0,
        "abstained_cases": 0,
        "unresolved": counts["unresolved"],
        "outside_ground_truth": counts["outside_ground_truth"],
        "duplicates": counts["duplicate"],
    })
    reasons = Counter(dict.fromkeys((
        "inconclusive", "unsupported", "timeout", "policy_blocked", "technical_error",
        "not_detected", "not_run", "invalid_evidence", "conflicting_evidence",
    ), 0))
    case_results = []
    for case in sorted(selected_cases, key=lambda item: item.id):
        observations_for_case = linked[case.id]
        verdicts = {
            item.verification for item in observations_for_case
            if item.evidence_backed and item.verification in {"confirmed", "rejected"}
        }
        supported = False
        if len(verdicts) == 1:
            verdict = next(iter(verdicts))
            supported = True
            verdict_counts[f"{verdict}_cases"] += 1
            verdict_counts["decided_cases"] += 1
            correct_decision = (verdict == "confirmed") == (case.expected == "vulnerable")
            verdict_counts["correct_decisions"] += int(correct_decision)
            noun = "confirmations" if verdict == "confirmed" else "rejections"
            verdict_counts[("correct_" if correct_decision else "false_") + noun] += 1
        else:
            if len(verdicts) > 1:
                verdict = "conflicting_evidence"
            elif not observations_for_case:
                verdict = "not_detected"
            else:
                owner = by_id[primary[case.id]]
                verdict = owner.verification
                if verdict in {"confirmed", "rejected"}:
                    verdict = "invalid_evidence"
            reasons[verdict] += 1
            verdict_counts["abstained_cases"] += 1
        owner = by_id.get(primary.get(case.id))
        case_results.append(BenchmarkCaseResultV2(
            case_id=case.id,
            expected=case.expected,
            family=case.family,
            detected=case.id in primary,
            primary_observation_id=owner.id if owner else None,
            matched_observation_ids=sorted(item.id for item in observations_for_case),
            verification=verdict,
            confirmation_supported=supported and verdict == "confirmed",
            evidence=sorted({value for item in observations_for_case for value in item.evidence}),
            severity=owner.severity if owner else None,
            context_priority=owner.context_priority if owner else None,
        ))
    verification = VerificationMetricsV2(
        counts=dict(verdict_counts),
        abstention_reasons=dict(reasons),
        confirmed_precision=ratio(
            verdict_counts["correct_confirmations"], verdict_counts["confirmed_cases"]
        ),
        supported_verified_recall=ratio(verdict_counts["correct_confirmations"], positives),
        false_confirmation_rate=ratio(verdict_counts["false_confirmations"], negatives),
        answered_accuracy=ratio(
            verdict_counts["correct_decisions"], verdict_counts["decided_cases"]
        ),
        decision_coverage=ratio(verdict_counts["decided_cases"], len(selected_cases)),
        abstention_rate=ratio(verdict_counts["abstained_cases"], len(selected_cases)),
    )
    digest = hashlib.sha256(
        json.dumps(dataset.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return BenchmarkScoreV2(
        dataset_id=dataset.id,
        dataset_digest=digest,
        dataset_status=dataset.status,
        split=split,
        sample_kind=sample_kind,
        technically_valid=technically_valid,
        technical_errors=sorted(technical_errors or []),
        detection=detection if technically_valid else None,
        verification=verification if technically_valid else None,
        severity=_rubric_metrics(
            selected_cases, primary, by_id, "expected_severity", "severity"
        ) if technically_valid else None,
        context_priority=_rubric_metrics(
            selected_cases, primary, by_id,
            "expected_context_priority", "context_priority",
        ) if technically_valid else None,
        matches=matches,
        cases=case_results,
    )
