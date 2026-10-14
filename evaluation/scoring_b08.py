"""Evaluator-only, scheme-aware ordinal/priority comparison; no production imports."""
from schemas.benchmark_v2 import BenchmarkDatasetV2
from schemas.report import FinalReport


def evaluate_scoring(
    dataset: BenchmarkDatasetV2, reports: list[FinalReport], case_reports: dict[str, str],
) -> dict:
    by_id = {report.finding_id: report for report in reports}
    if len(by_id) != len(reports) or len(set(case_reports.values())) != len(case_reports):
        raise ValueError("Duplicate reports or non-independent case mappings")
    cases = {case.id: case for case in dataset.cases}
    for case_id, finding_id in case_reports.items():
        if case_id not in cases or finding_id not in by_id:
            raise ValueError("Unknown case/report mapping")
        case, finding = cases[case_id], by_id[finding_id].finding
        if case.sample_kind != "original" or not any(
            anchor.file == finding.file and finding.line_start is not None
            and anchor.line_start <= (finding.line_end or finding.line_start)
            and finding.line_start <= anchor.line_end for anchor in case.source_anchors
        ):
            raise ValueError("Mapping lacks the original case source anchor")

    def metric(expected, observed):
        reviewed = [case for case in cases.values() if getattr(case, expected) is not None]
        assessed = correct = 0
        for case in reviewed:
            report = by_id.get(case_reports.get(case.id))
            value = observed(report) if report else None
            if value is not None:
                assessed += 1
                correct += int(value == getattr(case, expected).upper())
        return {"total_cases": len(cases), "reviewed_cases": len(reviewed),
                "assessed_cases": assessed, "correct_cases": correct,
                "reviewed_coverage": len(reviewed) / len(cases) if cases else None,
                "assessed_coverage": assessed / len(reviewed) if reviewed else None,
                "accuracy": correct / assessed if assessed else None}

    def ordinal(report):
        item = report.technical_severity
        resolved = report.scoring_review_resolution
        if (item is not None and item.scheme == "source-impact.a04.v1"
                and item.assessment_status == "assessed" and resolved is not None
                and resolved.status == "accepted"):
            return item.level
        return None

    def priority(report):
        item = report.context_priority
        if (item is not None and item.scheme == "context-priority.v0.1"
                and item.assessment_status == "assessed" and not item.unknown_inputs):
            return item.level
        return None

    return {"schema_version": "scoring.evaluation.b08.v1",
            "severity_scheme": "source-impact.a04.v1",
            "severity": metric("expected_severity", ordinal),
            "context_priority": metric("expected_context_priority", priority),
            "cvss_accuracy": None,
            "limitations": ["CVSS is not compared with ordinal A04 labels.",
                            "Absent independent CP labels make CP accuracy unavailable.",
                            "This evaluates supplied matched reports, not detection recall."]}
