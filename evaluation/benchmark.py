"""Deterministic external scorer. No model judging, execution or verdict mutation."""

from __future__ import annotations

import json
from collections import Counter
from statistics import mean, pstdev

from schemas.benchmark import (
    BenchmarkAggregate,
    BenchmarkCaseResult,
    BenchmarkDataset,
    BenchmarkMatch,
    BenchmarkObservation,
    BenchmarkRunResult,
    BenchmarkScore,
    DetectionMetrics,
    VerificationMetrics,
    VerificationMetricsV2,
)
from security.source_paths import normalize_source_path


def normalize_path(value: str) -> str:
    return normalize_source_path(value)


def family(rule: str, dataset: BenchmarkDataset) -> str:
    value = rule.lower().replace("_", "-")
    matches = [
        name
        for name, aliases in dataset.family_aliases.items()
        if value == name or any(alias in value for alias in aliases)
    ]
    # Ambiguous aliases never produce a TP.
    return matches[0] if len(matches) == 1 else value


def ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def score(
    dataset: BenchmarkDataset,
    observations: list[BenchmarkObservation],
    *,
    verification_measured: bool = True,
) -> BenchmarkScore:
    """Stable maximum-cardinality bipartite matching, then mark extra matches duplicates.

    Edges require equal normalized file, inclusive intersecting ranges, same family,
    and equal service where the case declares one. Labels/verdicts never rank edges.
    """
    ordered = sorted(
        observations,
        key=lambda o: (
            o.artifact,
            o.line_start or 0,
            o.line_end or o.line_start or 0,
            o.family,
            o.id,
            json.dumps(o.model_dump(), sort_keys=True),
        ),
    )
    if len({o.id for o in ordered}) != len(ordered):
        raise ValueError("Observation IDs must be unique within a producer view")
    cases = {c.id: c for c in dataset.cases}
    edges = {}
    for o in ordered:
        edges[o.id] = sorted(
            c.id
            for c in dataset.cases
            if normalize_path(o.artifact) == normalize_path(c.artifact)
            and o.line_start is not None
            and o.line_start <= c.line_end
            and c.line_start <= (o.line_end or o.line_start)
            and o.family == c.category
            and (c.service is None or c.service == o.service)
        )
    owners: dict[str, str] = {}

    def assign(oid, visited):
        for cid in edges[oid]:
            if cid in visited:
                continue
            visited.add(cid)
            if cid not in owners or assign(owners[cid], visited):
                owners[cid] = oid
                return True
        return False

    for o in ordered:
        assign(o.id, set())
    by_observation = {oid: cid for cid, oid in owners.items()}
    matches = []
    for o in ordered:
        cid = by_observation.get(o.id)
        if cid:
            classification = "tp" if cases[cid].expected == "vulnerable" else "fp"
        elif edges[o.id]:
            cid, classification = edges[o.id][0], "duplicate"
        else:
            in_scope = any(
                normalize_path(o.artifact) == normalize_path(c.artifact)
                and o.line_start is not None
                and o.line_start <= c.line_end
                and c.line_start <= (o.line_end or o.line_start)
                and o.family == c.category
                for c in dataset.cases
            )
            classification = (
                ("fp" if dataset.exhaustive else "unreviewed")
                if in_scope
                else "outside_ground_truth"
            )
        matches.append(
            BenchmarkMatch(observation_id=o.id, case_id=cid, classification=classification)
        )
    counts = Counter(m.classification for m in matches)
    positives = sum(c.expected == "vulnerable" for c in dataset.cases)
    negatives = len(dataset.cases) - positives
    false_negative = positives - counts["tp"]
    safe_detected = sum(cases[cid].expected == "safe" for cid in owners)
    tn = negatives - safe_detected if dataset.negative_universe else None
    p, r = ratio(counts["tp"], counts["tp"] + counts["fp"]), ratio(counts["tp"], positives)
    f1 = None if p is None or r is None else (2 * p * r / (p + r) if p + r else 0.0)
    detection = DetectionMetrics(
        tp=counts["tp"],
        fp=counts["fp"],
        fn=false_negative,
        tn=tn,
        precision=p,
        recall=r,
        f1=f1,
        specificity=ratio(tn, negatives) if tn is not None else None,
        duplicates=counts["duplicate"],
        duplicate_rate=ratio(counts["duplicate"], len(ordered)),
        unique_findings=len(ordered) - counts["duplicate"],
        outside_ground_truth=counts["outside_ground_truth"],
        unreviewed=counts["unreviewed"],
    )
    # A duplicate may have better Evidence than its primary. Credit the case once;
    # selection of primary is never influenced by verification outcome.
    supported = {
        m.case_id
        for m in matches
        if m.case_id
        and next(o for o in ordered if o.id == m.observation_id).evidence_backed
        and next(o for o in ordered if o.id == m.observation_id).verification == "confirmed"
    }
    correct = sum(cases[cid].expected == "vulnerable" for cid in supported)
    false = sum(cases[cid].expected == "safe" for cid in supported)
    safe_false = false
    by_id = {o.id: o for o in ordered}
    unreviewed_confirmations = sum(
        by_id[m.observation_id].verification == "confirmed"
        for m in matches
        if m.classification in {"unreviewed", "outside_ground_truth"}
    )
    false += sum(
        by_id[m.observation_id].verification == "confirmed"
        and by_id[m.observation_id].evidence_backed
        for m in matches
        if m.classification == "fp" and m.case_id is None
    )
    verification = VerificationMetrics(
        statuses=dict(Counter(o.verification for o in ordered)),
        correctly_confirmed=correct,
        runtime_confirmed_positives=len(
            {
                m.case_id
                for m in matches
                if m.case_id
                and cases[m.case_id].expected == "vulnerable"
                and by_id[m.observation_id].evidence_backed
                and "runtime" in by_id[m.observation_id].confirmation_sources
            }
        ),
        source_confirmed_positives=len(
            {
                m.case_id
                for m in matches
                if m.case_id
                and cases[m.case_id].expected == "vulnerable"
                and by_id[m.observation_id].evidence_backed
                and "static" in by_id[m.observation_id].confirmation_sources
            }
        ),
        false_confirmations=false,
        invalid_confirmation_claims=sum(
            o.reported_verdict == "confirmed" and not o.evidence_backed for o in ordered
        ),
        unreviewed_confirmations=unreviewed_confirmations,
        unsupported_known_positives=sum(
            cases[cid].expected == "vulnerable" and by_id[oid].verification == "unsupported"
            for cid, oid in owners.items()
        ),
        confirmation_rate=ratio(correct, counts["tp"]) if verification_measured else None,
        end_to_end_verified_recall=ratio(correct, positives) if verification_measured else None,
        false_confirmation_rate=ratio(safe_false, negatives)
        if dataset.negative_universe and verification_measured
        else None,
    )
    results = []
    for c in sorted(dataset.cases, key=lambda c: c.id):
        o = by_id.get(owners.get(c.id))
        results.append(
            BenchmarkCaseResult(
                case_id=c.id,
                expected=c.expected,
                category=c.category,
                detected=o is not None,
                finding_id=o.id if o else None,
                detection_source=o.source if o else None,
                verification=o.verification if o else "not_detected",
                reported_verdict=o.reported_verdict if o else None,
                evidence=o.evidence if o else [],
                confirmation_supported=c.id in supported,
                all_matched_findings=[m.observation_id for m in matches if m.case_id == c.id],
            )
        )
    return BenchmarkScore(
        detection=detection, verification=verification, matches=matches, cases=results
    )


def aggregate(runs: list[BenchmarkRunResult]) -> BenchmarkAggregate:
    if not runs or len({r.configuration_digest for r in runs}) != 1:
        raise ValueError("Aggregate requires nonempty runs with identical configuration")
    complete = [r for r in runs if r.status == "completed"]
    measurements: dict[str, list[float]] = {}
    for run in complete:
        for view in ("baseline", "detection"):
            result = getattr(run, view)
            if result is None:
                continue
            for layer in ("detection", "verification"):
                for key, value in getattr(result, layer).model_dump().items():
                    if isinstance(value, (int, float)):
                        measurements.setdefault(f"{view}.{layer}.{key}", []).append(value)
        for key, value in run.performance.items():
            if isinstance(value, (int, float)):
                measurements.setdefault(f"performance.{key}", []).append(value)
    stability = {}
    for run in complete:
        if run.detection:
            for c in run.detection.cases:
                entry = stability.setdefault(
                    c.case_id,
                    {
                        "detected_runs": 0,
                        "confirmed_runs": 0,
                        "verdicts": [],
                        "expected": c.expected,
                        "category": c.category,
                    },
                )
                entry["detected_runs"] += int(bool(c.detected))
                entry["confirmed_runs"] += int(c.confirmation_supported)
                entry["verdicts"].append(
                    "confirmed" if c.confirmation_supported else c.verification
                )
    for entry in stability.values():
        entry["unstable_verdict"] = len(set(entry["verdicts"])) > 1
    positives = [e for e in stability.values() if e["expected"] == "vulnerable"]
    summary = {}
    if complete:
        summary = {
            "found_all": sum(e["detected_runs"] == len(complete) for e in positives),
            "found_sometimes": sum(0 < e["detected_runs"] < len(complete) for e in positives),
            "never_found": sum(e["detected_runs"] == 0 for e in positives),
            "confirmed_all": sum(e["confirmed_runs"] == len(complete) for e in positives),
            "unstable_verdicts": sum(e["unstable_verdict"] for e in positives),
            **{
                f"found_in_{n}_of_{len(complete)}": sum(e["detected_runs"] == n for e in positives)
                for n in range(len(complete) + 1)
            },
        }
    return BenchmarkAggregate(
        configuration_digest=runs[0].configuration_digest,
        attempted_runs=len(runs),
        completed_runs=len(complete),
        technical_failure_rate=ratio(len(runs) - len(complete), len(runs)),
        numeric={
            key: {
                "mean": mean(values),
                "min": min(values),
                "max": max(values),
                "stddev": pstdev(values),
            }
            for key, values in measurements.items()
        },
        stability=stability,
        stability_summary=summary,
        runs=runs,
    )


def verification_metrics_v2(
    matched: BenchmarkScore,
    observations: list[BenchmarkObservation],
    *,
    technically_valid: bool = True,
) -> VerificationMetricsV2 | None:
    """Reduce existing matching to case-level V2 metrics; no new detection scorer.

    Input must be one frozen evaluated split/sample slice. ``evidence_backed``
    must certify the observation's *own* verdict, including rejected, using the
    persisted execution/audit checks. The historical V1 adapter certifies only
    confirmed: it must not be used to claim evidence-backed rejections in V2.
    Invalid runs retain their diagnostics/artifacts but have no security metrics.
    """
    if not technically_valid:
        return None
    by_id = {o.id: o for o in observations}
    if len(by_id) != len(observations):
        raise ValueError("Observation IDs must be unique")
    if {m.observation_id for m in matched.matches} != set(by_id):
        raise ValueError("Observations must equal the scored producer view")
    cases = {c.case_id: c for c in matched.cases}
    if len(cases) != len(matched.cases):
        raise ValueError("Case IDs must be unique")
    linked: dict[str, list[BenchmarkObservation]] = {cid: [] for cid in cases}
    for match in matched.matches:
        if match.case_id is not None:
            if match.case_id not in cases:
                raise ValueError("Match refers to an unknown case")
            linked[match.case_id].append(by_id[match.observation_id])
    counts = Counter({
        "labeled_cases": len(cases),
        "positive_cases": sum(c.expected == "vulnerable" for c in cases.values()),
        "negative_cases": sum(c.expected == "safe" for c in cases.values()),
        "confirmed_cases": 0, "rejected_cases": 0, "decided_cases": 0,
        "correct_confirmations": 0, "false_confirmations": 0,
        "correct_rejections": 0, "false_rejections": 0,
        "correct_decisions": 0, "abstained_cases": 0,
        "outside_ground_truth": matched.detection.outside_ground_truth,
        "unreviewed": matched.detection.unreviewed,
        "duplicates": matched.detection.duplicates,
    })
    reasons = Counter(dict.fromkeys((
        "inconclusive", "unsupported", "timeout", "policy_blocked", "technical_error",
        "not_detected", "not_run", "invalid_evidence", "conflicting_evidence",
    ), 0))
    for cid, case in cases.items():
        if case.expected not in {"vulnerable", "safe"}:
            raise ValueError("Only labeled positive/negative cases may enter V2 metrics")
        verdicts = {
            o.verification for o in linked[cid]
            if o.evidence_backed and o.verification in {"confirmed", "rejected"}
        }
        if len(verdicts) == 1:
            verdict = verdicts.pop()
            counts[verdict + "_cases"] += 1
            counts["decided_cases"] += 1
            correct = (verdict == "confirmed") == (case.expected == "vulnerable")
            counts["correct_decisions"] += int(correct)
            term = "confirmations" if verdict == "confirmed" else "rejections"
            counts[("correct_" if correct else "false_") + term] += 1
        else:
            if verdicts:
                reason = "conflicting_evidence"
            elif not linked[cid]:
                reason = "not_detected"
            else:
                primary = by_id.get(case.finding_id)
                if primary is None:
                    raise ValueError("Matched case requires a primary observation")
                reason = primary.verification
                if reason in {"confirmed", "rejected"}:
                    reason = "invalid_evidence"
            reasons[reason] += 1
            counts["abstained_cases"] += 1
    from schemas.benchmark import V2_METRIC_TERMS

    names = (
        "confirmed_precision", "supported_verified_recall", "false_confirmation_rate",
        "answered_accuracy", "decision_coverage", "abstention_rate",
    )
    return VerificationMetricsV2(
        counts=dict(counts), abstention_reasons=dict(reasons),
        **{name: ratio(counts[n], counts[d]) for name in names
           for n, d in [V2_METRIC_TERMS[name]]},
    )
