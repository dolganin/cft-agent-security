import json
from pathlib import Path

from evaluation.artifact_history import persist_agent_trace
from evaluation.benchmark_v2 import score_v2
from evaluation.catalog_adapter import load_catalog_dataset
from evaluation.offline_rescore import rescore
from schemas.benchmark_v2 import (
    BenchmarkDatasetV2,
    BenchmarkEvaluationCaseV2,
    BenchmarkHTTPAnchorV2,
    BenchmarkObservationV2,
    BenchmarkSourceAnchorV2,
)


ROOT = Path(__file__).resolve().parents[1]


def case(
    case_id,
    expected="vulnerable",
    *,
    file="routes/a.ts",
    start=10,
    end=20,
    family="authorization",
    group=None,
    http=None,
    severity=None,
    priority=None,
):
    return BenchmarkEvaluationCaseV2(
        id=case_id,
        expected=expected,
        family=family,
        independence_group=group or case_id.lower(),
        sample_kind="original",
        split="development",
        service="app",
        source_anchors=[
            BenchmarkSourceAnchorV2(file=file, line_start=start, line_end=end)
        ] if file else [],
        http_anchors=[BenchmarkHTTPAnchorV2(**http)] if http else [],
        expected_severity=severity,
        expected_context_priority=priority,
    )


def dataset(*cases):
    return BenchmarkDatasetV2(
        id="synthetic-a05",
        target_commit="a" * 40,
        status="synthetic",
        family_aliases={"authorization": ["authz"]},
        cases=list(cases),
    )


def observation(observation_id, **updates):
    values = dict(
        id=observation_id,
        source="synthetic",
        family="authorization",
        service="app",
        source_file="routes/a.ts",
        line_start=12,
        line_end=12,
    )
    values.update(updates)
    return BenchmarkObservationV2(**values)


def test_duplicates_are_one_tp_and_order_independent():
    truth = dataset(case("CASE-1"))
    first = score_v2(truth, [observation("b"), observation("a")])
    second = score_v2(truth, [observation("a"), observation("b")])
    assert first == second
    assert first.detection.tp == 1
    assert first.detection.duplicates == 1
    assert first.cases[0].primary_observation_id == "a"


def test_ambiguous_source_and_http_are_unresolved():
    truth = dataset(
        case("CASE-1", group="one"),
        case("CASE-2", group="two"),
    )
    scored = score_v2(truth, [observation("ambiguous")])
    assert scored.detection.unresolved == 1
    assert scored.detection.tp == 0 and scored.detection.fn == 2
    assert scored.matches[0].candidate_case_ids == ["CASE-1", "CASE-2"]

    http_truth = dataset(
        case("HTTP-1", file=None, group="http-one", http={"method": "GET", "endpoint": "/x/{id}"}),
        case("HTTP-2", file=None, group="http-two", http={"method": "GET", "endpoint": "/x/:value"}),
    )
    http_observation = observation(
        "http", source_file=None, line_start=None, line_end=None,
        http_method="GET", http_endpoint="/x/:id",
    )
    assert score_v2(http_truth, [http_observation]).detection.unresolved == 1


def test_http_method_parameter_and_route_template_are_contextual():
    truth = dataset(case(
        "HTTP-1",
        file=None,
        http={"method": "POST", "endpoint": "/items/{id}", "parameter": "body.name"},
    ))
    matching = observation(
        "match", source_file=None, line_start=None, line_end=None,
        http_method="POST", http_endpoint="/items/:itemId?debug=1",
        http_parameter="body.name",
    )
    wrong_method = matching.model_copy(update={"id": "method", "http_method": "GET"})
    wrong_parameter = matching.model_copy(update={"id": "parameter", "http_parameter": "query.name"})
    assert score_v2(truth, [matching]).detection.tp == 1
    assert score_v2(truth, [wrong_method]).detection.outside_ground_truth == 1
    assert score_v2(truth, [wrong_parameter]).detection.outside_ground_truth == 1


def test_detection_confirmation_and_safe_false_confirmation_are_independent():
    truth = dataset(case("POS"), case("SAFE", expected="safe", file="routes/safe.ts"))
    detected_only = observation("pos", verification="inconclusive")
    false_confirmation = observation(
        "safe",
        source_file="routes/safe.ts",
        verification="confirmed",
        reported_verdict="confirmed",
        evidence_backed=True,
        evidence=["execution-1", "audit:run-1"],
    )
    scored = score_v2(truth, [detected_only, false_confirmation])
    assert (scored.detection.tp, scored.detection.fp) == (1, 1)
    assert scored.verification.counts["correct_confirmations"] == 0
    assert scored.verification.counts["false_confirmations"] == 1
    assert scored.verification.confirmed_precision == 0
    assert scored.verification.false_confirmation_rate == 1
    assert scored.verification.supported_verified_recall == 0


def test_unbacked_binary_verdict_abstains_and_absence_is_not_rejected():
    truth = dataset(case("POS"), case("SAFE", expected="safe", file="routes/safe.ts"))
    scored = score_v2(truth, [observation("pos", verification="rejected")])
    assert scored.verification.counts["rejected_cases"] == 0
    assert scored.verification.abstention_reasons["invalid_evidence"] == 1
    assert scored.verification.abstention_reasons["not_detected"] == 1
    assert scored.verification.decision_coverage == 0
    assert scored.verification.abstention_rate == 1


def test_conflicting_supported_duplicate_evidence_abstains():
    truth = dataset(case("POS"))
    confirmed = observation("a", verification="confirmed", evidence_backed=True)
    rejected = observation("b", verification="rejected", evidence_backed=True)
    scored = score_v2(truth, [confirmed, rejected])
    assert scored.detection.tp == 1 and scored.detection.duplicates == 1
    assert scored.verification.counts["decided_cases"] == 0
    assert scored.verification.abstention_reasons["conflicting_evidence"] == 1


def test_unresolved_outside_and_case_technical_error_are_separate():
    truth = dataset(case("ONE"), case("TWO", group="two"))
    observations = [
        observation("ambiguous"),
        observation("outside", family="xss"),
        observation("technical", verification="technical_error"),
    ]
    scored = score_v2(truth, observations)
    assert scored.detection.unresolved == 2
    assert scored.detection.outside_ground_truth == 1
    assert scored.verification.abstention_reasons["technical_error"] == 0

    single = score_v2(dataset(case("ONE")), [observation("technical", verification="technical_error")])
    assert single.verification.abstention_reasons["technical_error"] == 1


def test_run_error_nulls_security_metrics_and_empty_denominators_are_null():
    invalid = score_v2(
        dataset(case("POS")), [], technically_valid=False, technical_errors=["startup failed"]
    )
    assert invalid.detection is None and invalid.verification is None
    assert invalid.severity is None and invalid.context_priority is None

    positives = score_v2(dataset(case("POS")), [])
    assert positives.detection.precision is None
    assert positives.verification.confirmed_precision is None
    assert positives.verification.false_confirmation_rate is None
    negatives = score_v2(dataset(case("SAFE", expected="safe")), [])
    assert negatives.detection.recall is None
    assert negatives.verification.supported_verified_recall is None


def test_partial_independent_rubric_labels_report_sample_sizes():
    truth = dataset(
        case("ONE", severity="high", priority="critical"),
        case("TWO", file="routes/b.ts", severity="low"),
        case("THREE", file="routes/c.ts"),
    )
    scored = score_v2(truth, [
        observation("one", severity="HIGH", context_priority="critical"),
        observation("two", source_file="routes/b.ts"),
    ])
    assert (scored.severity.reviewed_cases, scored.severity.assessed_cases) == (2, 1)
    assert scored.severity.accuracy == 1 and scored.severity.assessed_coverage == 0.5
    assert scored.context_priority.reviewed_cases == 1
    assert scored.context_priority.accuracy == 1


def test_catalog_adapter_preserves_provisional_a02_a03_cases():
    base = ROOT / "benchmarks" / "juice-shop-v20.2.0-v2"
    adapted = load_catalog_dataset(
        base / "catalog/positives.reviewed.yaml",
        base / "controls/controls.reviewed.yaml",
        base / "controls/expansion/controls.reviewed.yaml",
    )
    positives = [item for item in adapted.cases if item.expected == "vulnerable"]
    controls = [item for item in adapted.cases if item.expected == "safe"]
    assert adapted.status == "catalog_adapter_pending_a04"
    assert len(positives) == 27 and len(controls) == 14
    assert sum(item.split == "development" for item in positives) == 20
    assert sum(item.split == "development" for item in controls) == 8
    assert {item.sample_kind for item in controls} == {"original", "patched", "synthetic"}
    assert all(item.expected_severity is None for item in adapted.cases)


def test_offline_rescore_is_byte_deterministic(tmp_path):
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    (artifacts / "gate.json").write_text(
        json.dumps({"technical_errors": 0, "stage_errors": []}), encoding="utf-8"
    )
    observations = [observation("one", verification="inconclusive").model_dump(mode="json")]
    (artifacts / "observations-v2.json").write_text(
        json.dumps(observations), encoding="utf-8"
    )
    first, second = tmp_path / "first", tmp_path / "second"
    truth = dataset(case("ONE"))
    assert rescore(truth, artifacts, first) == rescore(truth, artifacts, second)
    for name in ("scorecard-v2.json", "scorecard-v2.md", "history-v2.json"):
        assert (first / name).read_bytes() == (second / name).read_bytes()


def test_trace_keeps_history_and_redacts_secret_values(tmp_path):
    trace = persist_agent_trace(tmp_path, "finding", {
        "action_history": [{
            "action": {"id": "a", "parameters": {"token": "do-not-store", "path": "/x"}},
            "validation": {"approved": True},
            "execution": {"status": "completed"},
        }],
        "evidence": [],
        "decision_history": [],
    })
    raw = trace.read_text(encoding="utf-8")
    assert "do-not-store" not in raw and "[REDACTED]" in raw
    assert json.loads(raw)["actions"][0]["validation"]["approved"] is True
