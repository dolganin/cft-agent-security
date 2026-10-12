import json
import hashlib
import os
from pathlib import Path
import subprocess
import sys

import pytest
import yaml

from evaluation.artifact_history import persist_agent_trace
from evaluation.benchmark_v2 import score_v2
from evaluation.catalog_adapter import load_catalog_dataset
from evaluation.offline_rescore import observations_from_artifacts, rescore
from executor.sandbox_audit import calculate_sha256_digest
from schemas.evidence import (
    Evidence,
    EvidenceAction,
    EvidenceArtifact,
    EvidenceObservation,
    EvidenceScope,
)
from schemas.benchmark_v2 import (
    BenchmarkDatasetV2,
    BenchmarkEvaluationCaseV2,
    BenchmarkHTTPAnchorV2,
    BenchmarkObservationV2,
    BenchmarkSourceAnchorV2,
    BenchmarkScoreV2,
)
from schemas.finding import Finding, FindingProvenance


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


def test_ambiguous_candidates_use_deterministic_maximum_matching():
    truth = dataset(
        case("CASE-1", group="one", http={"method": "GET", "endpoint": "/shared"}),
        case(
            "CASE-2", group="two", file="routes/b.ts",
            http={"method": "GET", "endpoint": "/shared"},
        ),
    )
    both = observation(
        "a-both", source_file=None, line_start=None, line_end=None,
        http_method="GET", http_endpoint="/shared",
    )
    only_first = observation("b-first")
    scored = score_v2(truth, [only_first, both])
    assert scored.detection.tp == 2
    assert {item.observation_id: item.case_id for item in scored.matches} == {
        "a-both": "CASE-2", "b-first": "CASE-1",
    }
    assert score_v2(truth, [both, only_first]) == scored

    unresolved = score_v2(
        dataset(case("CASE-1", group="one"), case("CASE-2", group="two")),
        [observation("ambiguous")],
    )
    assert unresolved.detection.unresolved == 1
    assert unresolved.detection.tp == 0 and unresolved.detection.fn == 2

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
    truth = dataset(
        case("ONE", http={"method": "GET", "endpoint": "/shared"}),
        case(
            "TWO", group="two", file="routes/b.ts",
            http={"method": "GET", "endpoint": "/shared"},
        ),
    )
    observations = [
        observation(
            "ambiguous", source_file=None, line_start=None, line_end=None,
            http_method="GET", http_endpoint="/shared",
        ),
        observation("outside", family="xss"),
        observation("technical", verification="technical_error"),
    ]
    scored = score_v2(truth, observations)
    assert scored.detection.unresolved == 0
    assert scored.detection.outside_ground_truth == 1
    assert scored.detection.tp == 2
    assert scored.verification.abstention_reasons["technical_error"] == 1

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
    artifacts = make_valid_artifacts(tmp_path, include_finding=True)
    (artifacts / "configuration.json").write_text(json.dumps({
        "configuration_digest": "test-digest",
        "api_key": "do-not-store",
        "max_output_tokens": 1024,
    }), encoding="utf-8")
    # Keep the run seal valid after changing the fixture configuration.
    reseal(artifacts)
    first, second = tmp_path / "first", tmp_path / "second"
    truth = dataset(case("ONE"))
    dataset_path = tmp_path / "dataset.yaml"
    dataset_path.write_text(
        yaml.safe_dump(truth.model_dump(mode="json"), sort_keys=False), encoding="utf-8"
    )
    command = [
        sys.executable, "-m", "evaluation.offline_rescore",
        "--dataset", str(dataset_path), "--artifacts", str(artifacts),
    ]
    subprocess.run([*command, "--output", str(first)], check=True, capture_output=True, text=True)
    subprocess.run([*command, "--output", str(second)], check=True, capture_output=True, text=True)
    scored_first = BenchmarkScoreV2.model_validate(
        json.loads((first / "scorecard-v2.json").read_text(encoding="utf-8"))
    )
    scored_second = BenchmarkScoreV2.model_validate(
        json.loads((second / "scorecard-v2.json").read_text(encoding="utf-8"))
    )
    assert scored_first == scored_second
    assert (
        scored_first.detection.tp, scored_first.detection.fp,
        scored_first.detection.fn, scored_first.detection.tn,
    ) == (1, 0, 0, 0)
    assert scored_first.verification.supported_verified_recall == 0
    assert scored_first.verification.false_confirmation_rate is None
    assert scored_first.verification.decision_coverage == 0
    assert scored_first.verification.abstention_rate == 1
    report_text = (first / "scorecard-v2.md").read_text(encoding="utf-8")
    assert "PROVISIONAL DATASET" in report_text
    assert "not formal benchmark metrics" in report_text
    for name in (
        "scorecard-v2.json", "scorecard-v2.md", "history-v2.json",
        "observations-v2.json", "scorecard-v2-development-original.json",
    ):
        assert (first / name).read_bytes() == (second / name).read_bytes()
    history = json.loads((first / "history-v2.json").read_text(encoding="utf-8"))
    assert history["configurations"]["configuration.json"]["api_key"] == "[REDACTED]"
    assert history["configurations"]["configuration.json"]["max_output_tokens"] == 1024


def test_offline_rescore_fails_closed_for_missing_gate_and_model_unavailable(tmp_path):
    artifacts = make_valid_artifacts(tmp_path)
    (artifacts / "pipeline/gate.json").unlink()
    score = rescore(dataset(case("ONE")), artifacts / "pipeline", tmp_path / "missing-gate")
    assert not score.technically_valid
    assert score.detection is None
    assert any("gate.json" in value for value in score.technical_errors)

    unavailable = make_valid_artifacts(tmp_path / "unavailable")
    (unavailable / "pipeline/scout/summary.json").write_text(
        json.dumps({"stop_reason": "model_unavailable"}), encoding="utf-8"
    )
    reseal(unavailable)
    score = rescore(dataset(case("ONE")), unavailable / "pipeline", tmp_path / "unavailable-score")
    assert not score.technically_valid
    assert any("model stage unavailable" in value for value in score.technical_errors)

    broken_seal = make_valid_artifacts(tmp_path / "broken-seal")
    (broken_seal / "pipeline/gate.json").write_text(
        json.dumps({"decision": "pass", "exit_code": 0, "technical_errors": 1}),
        encoding="utf-8",
    )
    score = rescore(
        dataset(case("ONE")), broken_seal / "pipeline", tmp_path / "broken-seal-score"
    )
    assert not score.technically_valid
    assert any("gate reports technical failure" in value for value in score.technical_errors)
    assert any("seal mismatch" in value for value in score.technical_errors)


def test_offline_rescore_rebuilds_evidence_instead_of_trusting_normalized_flag(tmp_path):
    artifacts = make_valid_artifacts(tmp_path, include_finding=True)
    normalized = [observation(
        "finding-1", verification="confirmed", reported_verdict="confirmed",
        evidence_backed=True, evidence=["fabricated-execution", "audit:fake"],
    ).model_dump(mode="json")]
    (artifacts / "pipeline/observations-v2.json").write_text(
        json.dumps(normalized), encoding="utf-8"
    )
    reseal(artifacts)
    rebuilt = observations_from_artifacts(artifacts / "pipeline")
    assert rebuilt[0].verification == "unsupported"
    assert rebuilt[0].evidence_backed is False


def test_supported_evidence_requires_report_trace_execution_and_audit_binding(tmp_path):
    artifacts = make_valid_artifacts(tmp_path, include_finding=True)
    pipeline = artifacts / "pipeline"
    execution_ref = "execution-" + "a" * 32
    payload = {
        "run_id": "run-1", "action_id": "action-1", "tool": "observe_http_surface",
        "status": "completed", "exit_code": 0, "target": "juice-shop",
        "session_id": "session-1", "action_digest": "proposal-digest",
    }
    record = {"id": execution_ref, "type": "executor_result", "created_at": "now", **payload}
    evidence = Evidence(
        id="evidence-1", action_id="action-1", type="http_observation",
        summary="Persisted test evidence", artifact_refs=[execution_ref, "audit:run-1"],
        reliability="high", verdict="confirmed", source="runtime",
        sandbox_session_id="session-1", hypothesis_id="hypothesis-1",
        action=EvidenceAction(id="action-1", tool="observe_http_surface", run_id="run-1"),
        observation=EvidenceObservation(kind="http_observation"),
        scope=EvidenceScope(
            target="juice-shop", environment="sandbox", description="test endpoint",
        ),
        artifacts=[
            EvidenceArtifact(ref=execution_ref, role="execution"),
            EvidenceArtifact(ref="audit:run-1", role="audit"),
        ],
    )
    (pipeline / "evidence").mkdir()
    (pipeline / "evidence" / f"{execution_ref}.json").write_text(
        json.dumps(record), encoding="utf-8"
    )
    audit = {
        "evidence_ref": execution_ref, "action_id": "action-1", "run_id": "run-1",
        "status": "completed", "exit_code": 0, "proposal_digest": "proposal-digest",
        "evidence_digest": calculate_sha256_digest(payload),
    }
    (pipeline / "audit/executor.jsonl").write_text(json.dumps(audit) + "\n", encoding="utf-8")
    report_path = pipeline / "reports/finding-1.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    report["status"] = "confirmed"
    report["verification"] = {
        "capability": "observe_http_surface", "validator_decision": "approved",
        "evidence_count": 1,
    }
    report["evidence"] = [evidence.model_dump(mode="json")]
    report_path.write_text(json.dumps(report), encoding="utf-8")
    trace = {
        "finding_id": "finding-1",
        "actions": [{
            "action": {"id": "action-1"},
            "validation": {"action_id": "action-1", "approved": True},
            "execution": {
                "action_id": "action-1", "run_id": "run-1",
                "status": "completed", "exit_code": 0,
            },
        }],
    }
    (pipeline / "traces/finding-1.json").write_text(json.dumps(trace), encoding="utf-8")
    assert observations_from_artifacts(pipeline)[0].evidence_backed is True

    audit["evidence_digest"] = "0" * 64
    (pipeline / "audit/executor.jsonl").write_text(json.dumps(audit) + "\n", encoding="utf-8")
    assert observations_from_artifacts(pipeline)[0].evidence_backed is False


def test_finding_provenance_family_and_action_endpoint_are_canonical(tmp_path):
    artifacts = make_valid_artifacts(tmp_path, include_finding=True)
    pipeline = artifacts / "pipeline"
    raw = json.loads((pipeline / "scout/merged-findings.json").read_text())
    raw[0]["rule_id"] = "scanner-specific-rule-123"
    raw[0]["provenance"] = FindingProvenance(
        family="sql-injection",
        fingerprint="a" * 64,
        normalized_file="routes/a.ts",
        anchor_status="source_bound",
    ).model_dump(mode="json")
    (pipeline / "scout/merged-findings.json").write_text(json.dumps(raw))
    trace_path = pipeline / "traces/finding-1.json"
    trace_path.write_text(json.dumps({
        "finding_id": "finding-1",
        "actions": [{"action": {"id": "a-1", "endpoint": "/api/items", "method": "GET"}}],
    }))
    observations = observations_from_artifacts(pipeline)
    assert observations[0].family == "sql-injection"
    assert observations[0].http_endpoint == "/api/items"
    assert observations[0].http_method == "GET"


def test_scorecards_are_partitioned_by_split_and_sample_kind():
    truth = BenchmarkDatasetV2(
        id="partitioned",
        target_commit="a" * 40,
        status="synthetic",
        cases=[
            case("DEV-ORIGINAL", group="one").model_copy(update={"split": "development"}),
            case("HOLDOUT-ORIGINAL", file="routes/b.ts", group="two").model_copy(
                update={"split": "holdout"}
            ),
            case("DEV-SYNTHETIC", file="routes/c.ts", group="three").model_copy(
                update={"sample_kind": "synthetic", "split": "development", "expected": "safe"}
            ),
        ],
    )
    with pytest.raises(ValueError, match="scored separately"):
        score_v2(truth, [])
    dev_original = score_v2(truth, [], split="development", sample_kind="original")
    holdout_original = score_v2(truth, [], split="holdout", sample_kind="original")
    dev_synthetic = score_v2(truth, [], split="development", sample_kind="synthetic")
    assert len(dev_original.cases) == len(holdout_original.cases) == len(dev_synthetic.cases) == 1
    assert (dev_original.split, dev_original.sample_kind) == ("development", "original")
    assert (holdout_original.split, holdout_original.sample_kind) == ("holdout", "original")

    with pytest.raises(ValueError, match="share a split"):
        dataset(
            case("ORIGINAL", group="same-cause"),
            case("HOLDOUT-TWIN", group="same-cause").model_copy(
                update={"sample_kind": "patched", "split": "holdout"}
            ),
        )


def test_offline_rescore_writes_separate_slice_scorecards(tmp_path):
    artifacts = make_valid_artifacts(tmp_path, include_finding=True)
    truth = BenchmarkDatasetV2(
        id="synthetic-a05",
        target_commit="a" * 40,
        status="synthetic",
        cases=[
            case("DEV-ORIGINAL", group="one"),
            case("HOLDOUT-ORIGINAL", file="routes/b.ts", group="two").model_copy(
                update={"split": "holdout"}
            ),
            case("DEV-SYNTHETIC", file="routes/c.ts", group="three").model_copy(
                update={"sample_kind": "synthetic", "expected": "safe"}
            ),
        ],
    )
    output = tmp_path / "partitioned-score"
    scored = rescore(truth, artifacts, output)
    assert len(scored.slices) == 3
    assert (output / "scorecard-v2-development-original.json").is_file()
    assert (output / "scorecard-v2-holdout-original.json").is_file()
    assert (output / "scorecard-v2-development-synthetic.json").is_file()
    assert [len(item.cases) for item in scored.slices] == [1, 1, 1]


def test_saved_juice_shop_demo_artifact_regression_when_available():
    location = os.environ.get("CFT_A05_DEMO_ARTIFACTS")
    if not location or not Path(location).is_dir():
        pytest.skip("set CFT_A05_DEMO_ARTIFACTS to the saved Juice Shop demo artifacts")
    observations = observations_from_artifacts(Path(location))
    assert observations
    assert any(item.family in {"sql-injection", "file-exposure"} for item in observations)
    assert any(item.http_endpoint for item in observations)


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


def make_valid_artifacts(tmp_path, *, include_finding=False):
    run = tmp_path / "run"
    pipeline = run / "pipeline"
    for relative in (
        "sast", "scout", "reports", "traces", "audit",
    ):
        (pipeline / relative).mkdir(parents=True, exist_ok=True)
    findings = []
    reports_index = []
    if include_finding:
        finding = Finding(
            id="finding-1", source="synthetic", rule_id="authorization",
            title="Synthetic finding", description="Test-only", file="routes/a.ts",
            line_start=12, line_end=12, service="app",
        )
        findings = [finding.model_dump(mode="json")]
        report_path = pipeline / "reports/finding-1.json"
        report_path.write_text(json.dumps({
            "finding_id": finding.id,
            "finding": finding.model_dump(mode="json"),
            "status": "inconclusive",
            "verification": {"validator_decision": "not_run", "evidence_count": 0},
            "explanation": "Synthetic fixture",
            "next_step": "none",
            "stop_reason": "insufficient_evidence",
        }), encoding="utf-8")
        reports_index = [{
            "finding_id": finding.id,
            "status": "inconclusive",
            "report_path": "reports/finding-1.json",
        }]
        (pipeline / "traces/finding-1.json").write_text(json.dumps({
            "finding_id": finding.id, "actions": [], "evidence": [],
        }), encoding="utf-8")
    (pipeline / "sast/findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (pipeline / "sast/summary.json").write_text(
        json.dumps({"total": len(findings), "semgrep_errors": 0}), encoding="utf-8"
    )
    (pipeline / "scout/merged-findings.json").write_text(json.dumps(findings), encoding="utf-8")
    (pipeline / "scout/summary.json").write_text(
        json.dumps({"stop_reason": "complete"}), encoding="utf-8"
    )
    (pipeline / "reports-index.json").write_text(json.dumps(reports_index), encoding="utf-8")
    (pipeline / "audit/llm-attempts.jsonl").write_text(
        '{"status":"ok"}\n', encoding="utf-8"
    )
    (pipeline / "gate.json").write_text(json.dumps({
        "decision": "pass", "exit_code": 0, "technical_errors": 0,
        "errors": [], "stage_errors": [],
    }), encoding="utf-8")
    (pipeline / "ci-summary.json").write_text(
        json.dumps({"status": "completed", "exit_code": 0}), encoding="utf-8"
    )
    (run / "configuration.json").write_text(json.dumps({
        "configuration_digest": "test-digest", "api_key": "test-secret",
    }), encoding="utf-8")
    (run / "manifest.json").write_text(json.dumps({
        "configuration_digest": "test-digest", "dataset_id": "synthetic-a05",
        "target_commit": "a" * 40,
    }), encoding="utf-8")
    (run / "metrics.json").write_text(json.dumps({
        "status": "completed", "diagnostics": [],
    }), encoding="utf-8")
    reseal(run)
    return run


def reseal(run):
    seal = {
        path.relative_to(run).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(run.rglob("*"))
        if path.is_file() and path.name != "seal.json"
    }
    (run / "seal.json").write_text(
        json.dumps(seal, sort_keys=True), encoding="utf-8"
    )
