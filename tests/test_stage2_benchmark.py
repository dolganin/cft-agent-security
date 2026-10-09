"""Scoring edge cases and isolation, independent of Docker/model availability."""

from __future__ import annotations

import json
from copy import deepcopy
from itertools import permutations

import pytest
from pydantic import ValidationError

from agent.llm_model import _reasoning_context
from agent.repository_scout import RepositoryScout
from evaluation.benchmark import aggregate, family, normalize_path, score
from evaluation.benchmark_harness import (
    ROOT,
    artifact_hashes,
    evaluate_artifacts,
    load_dataset,
    measure_stages,
    persisted_evidence_matches,
    production_arguments,
    validate_dataset_lock,
    validate_target,
    write_json,
)
from schemas.benchmark import (
    BenchmarkCase,
    BenchmarkDataset,
    BenchmarkObservation,
    BenchmarkRunResult,
)
from schemas.discovery import ProjectDiscoveryResult
from schemas.finding import Finding
from schemas.scout import ScoutTurn
from schemas.target import TargetProfile


def case(cid="CASE-1", expected="vulnerable", start=10, end=12, category="sql-injection"):
    return BenchmarkCase(
        id=cid,
        expected=expected,
        category=category,
        cwe="CWE-89",
        artifact="routes/search.ts",
        line_start=start,
        line_end=end,
        rationale="Source-backed narrowly defined test condition",
        provenance=["routes/search.ts"],
    )


def dataset(cases=None, **updates):
    values = {
        "id": "unit-v1",
        "target_name": "Unit corpus",
        "target_commit": "a" * 40,
        "scope": "Explicit labeled source windows for matcher unit tests",
        "cases": cases if cases is not None else [case()],
        "family_aliases": {"sql-injection": ["sqli", "sequelize-injection"]},
    }
    values.update(updates)
    return BenchmarkDataset(**values)


def observation(oid="one", start=10, end=10, **updates):
    values = {
        "id": oid,
        "source": "semgrep",
        "artifact": "routes/search.ts",
        "line_start": start,
        "line_end": end,
        "family": "sql-injection",
    }
    values.update(updates)
    return BenchmarkObservation(**values)


def test_perfect_result():
    result = score(dataset(), [observation(verification="confirmed", evidence_backed=True)])
    assert (result.detection.tp, result.detection.fp, result.detection.fn) == (1, 0, 0)
    assert result.detection.precision == result.detection.recall == result.detection.f1 == 1
    assert result.verification.end_to_end_verified_recall == 1


def test_all_false_negatives_and_zero_denominator():
    result = score(dataset(), [])
    assert result.detection.fn == 1 and result.detection.recall == 0
    assert result.detection.precision is None and result.detection.f1 is None
    assert result.verification.confirmation_rate is None
    assert result.verification.end_to_end_verified_recall == 0


def test_false_positive_negative_and_true_negative():
    d = dataset(
        [case(expected="safe"), case("CASE-2", expected="safe", start=50, end=50)],
        negative_universe=True,
    )
    m = score(d, [observation()]).detection
    assert (m.tp, m.fp, m.tn) == (0, 1, 1)
    assert m.precision == 0 and m.recall is None and m.specificity == 0.5


def test_duplicates_not_multiple_true_positives():
    result = score(dataset(), [observation("a"), observation("b")])
    assert result.detection.tp == 1 and result.detection.duplicates == 1
    assert result.detection.unique_findings == 1 and result.detection.duplicate_rate == 0.5


@pytest.mark.parametrize("start,end,tp", [(9, 10, 1), (12, 14, 1), (1, 9, 0), (13, 14, 0)])
def test_inclusive_overlapping_ranges(start, end, tp):
    assert score(dataset(), [observation(start=start, end=end)]).detection.tp == tp


def test_incompatible_family_and_service_do_not_match():
    assert score(dataset(), [observation(family="xss")]).detection.tp == 0
    d = dataset([case().model_copy(update={"service": "juice"})])
    assert score(d, [observation(service="other")]).detection.tp == 0


@pytest.mark.parametrize("path", ["routes\\search.ts", "./routes/search.ts", "routes//search.ts"])
def test_posix_and_windows_paths(path):
    assert normalize_path(path) == "routes/search.ts"
    assert score(dataset(), [observation(artifact=path)]).detection.tp == 1


@pytest.mark.parametrize(
    "path", ["../routes/search.ts", "C:\\repo\\routes\\search.ts", "/tmp/x", ""]
)
def test_absolute_and_traversal_paths_rejected(path):
    with pytest.raises(ValueError):
        normalize_path(path)


def test_one_finding_cannot_be_two_true_positives():
    d = dataset([case(), case("CASE-2", start=13, end=20)])
    m = score(d, [observation(start=10, end=20)]).detection
    assert m.tp == 1 and m.fn == 1


def test_maximum_matching_not_naive_greedy_and_order_independent():
    d = dataset([case(), case("CASE-2", start=13, end=20)])
    observations = [observation("wide", start=10, end=20), observation("narrow", start=10)]
    expected = score(d, observations).model_dump()
    assert expected["detection"]["tp"] == 2
    for order in permutations(observations):
        for cases in permutations(d.cases):
            assert (
                score(d.model_copy(update={"cases": list(cases)}), list(order)).model_dump()
                == expected
            )


def test_tn_unavailable_without_negative_universe():
    m = score(dataset(), [observation()]).detection
    assert m.tn is None and m.specificity is None


def test_negative_false_confirmation():
    d = dataset([case(expected="safe")], negative_universe=True)
    v = score(d, [observation(verification="confirmed", evidence_backed=True)]).verification
    assert v.false_confirmations == 1 and v.false_confirmation_rate == 1
    assert v.correctly_confirmed == 0


def test_unbacked_model_claim_is_not_verified_recall():
    result = score(dataset(), [observation(verification="confirmed", evidence_backed=False)])
    assert result.verification.correctly_confirmed == 0


def test_duplicate_evidence_credits_case_once():
    result = score(
        dataset(),
        [
            observation("a", verification="inconclusive"),
            observation("b", verification="confirmed", evidence_backed=True),
            observation("c", verification="confirmed", evidence_backed=True),
        ],
    )
    assert result.verification.correctly_confirmed == 1
    assert result.verification.confirmation_rate == 1
    assert result.cases[0].confirmation_supported


def test_static_confirmation_is_separate_from_runtime_confirmation():
    v = score(
        dataset(),
        [
            observation(
                verification="confirmed", evidence_backed=True, confirmation_sources=["static"]
            )
        ],
    ).verification
    assert v.correctly_confirmed == v.source_confirmed_positives == 1
    assert v.runtime_confirmed_positives == 0


@pytest.mark.parametrize("mutation", [None, "action_id", "digest", "missing_audit"])
def test_persisted_evidence_binding(tmp_path, mutation):
    from executor.sandbox_audit import calculate_sha256_digest
    from schemas.evidence import (
        Evidence,
        EvidenceAction,
        EvidenceArtifact,
        EvidenceObservation,
        EvidenceScope,
    )

    ref = "execution-" + "a" * 32
    payload = {
        "run_id": "run1",
        "action_id": "action1",
        "tool": "verify_sql_injection",
        "status": "completed",
        "exit_code": 0,
        "target": "juice",
        "session_id": "session1",
        "action_digest": "bound",
        "audit_ref": "audit:run1",
    }
    record = {"id": ref, "type": "executor_result", "created_at": "now", **payload}
    audit = {
        "evidence_ref": ref,
        "action_id": "action1",
        "run_id": "run1",
        "status": "completed",
        "exit_code": 0,
        "proposal_digest": "bound",
        "evidence_digest": calculate_sha256_digest(payload),
    }
    if mutation == "action_id":
        record["action_id"] = "another-action"
    if mutation == "digest":
        record["stdout"] = "changed persisted output"
    write_json(tmp_path / "evidence" / (ref + ".json"), record)
    (tmp_path / "audit").mkdir()
    if mutation != "missing_audit":
        (tmp_path / "audit/executor.jsonl").write_text(json.dumps(audit) + "\n")
    artifacts = [
        EvidenceArtifact(ref=ref, role="execution"),
        EvidenceArtifact(ref="audit:run1", role="audit"),
    ]
    e = Evidence(
        id="e1",
        action_id="action1",
        type="sql_differential_check",
        summary="Bounded result",
        verdict="confirmed",
        reliability="high",
        source="runtime",
        sandbox_session_id="session1",
        hypothesis_id="h1",
        action=EvidenceAction(id="action1", tool="verify_sql_injection", run_id="run1"),
        observation=EvidenceObservation(kind="sql_differential_check"),
        scope=EvidenceScope(target="juice", environment="sandbox", description="Bounded endpoint"),
        artifact_refs=[a.ref for a in artifacts],
        artifacts=artifacts,
    )
    assert persisted_evidence_matches(e, tmp_path) is (mutation is None)


def test_unmatched_nonexhaustive_finding_not_false_positive():
    m = score(dataset(), [observation(start=99, end=99)]).detection
    assert m.fp == 0 and m.outside_ground_truth == 1 and m.precision is None


def test_nonexhaustive_in_scope_wrong_service_unreviewed():
    d = dataset([case().model_copy(update={"service": "juice"})])
    assert score(d, [observation(service="other")]).detection.unreviewed == 1
    assert (
        score(
            d.model_copy(update={"exhaustive": True}), [observation(service="other")]
        ).detection.fp
        == 1
    )


def test_family_mapping_is_frozen_and_ambiguous_alias_not_matched():
    d = dataset()
    assert family("sequelize-injection.presentation", d) == "sql-injection"
    d.family_aliases["other"] = ["sequelize"]
    assert family("sequelize-injection.presentation", d) != "sql-injection"


@pytest.mark.parametrize(
    "field,value",
    [
        ("expected", "unknown"),
        ("line_start", 0),
        ("line_end", 9),
        ("cwe", "CWE-xyz"),
        ("category", "SQL"),
        ("provenance", []),
    ],
)
def test_invalid_truth_fields_rejected(field, value):
    values = case().model_dump()
    values[field] = value
    with pytest.raises(ValidationError):
        BenchmarkCase.model_validate(values)


def test_duplicate_case_ids_and_locations_and_undefined_negative_universe():
    for cases in ([case(), case()], [case(), case("CASE-2")], [case(expected="safe")]):
        with pytest.raises(ValidationError):
            dataset(cases)


def test_aggregate_excludes_technical_failures_and_detects_instability():
    s = score(dataset(), [observation(verification="inconclusive")])
    missing = score(dataset(), [])
    runs = [
        BenchmarkRunResult(
            run_id="a",
            configuration_digest="same",
            status="completed",
            detection=s,
            performance={"total_seconds": 2},
        ),
        BenchmarkRunResult(
            run_id="b",
            configuration_digest="same",
            status="completed",
            detection=missing,
            performance={"total_seconds": 4},
        ),
        BenchmarkRunResult(run_id="c", configuration_digest="same", status="technical_failure"),
    ]
    a = aggregate(runs)
    assert a.completed_runs == 2 and a.technical_failure_rate == 1 / 3
    assert a.numeric["performance.total_seconds"]["mean"] == 3
    assert a.stability["CASE-1"]["unstable_verdict"]
    assert a.stability["CASE-1"]["detected_runs"] == 1
    with pytest.raises(ValueError):
        aggregate([*runs, runs[0].model_copy(update={"configuration_digest": "other"})])


def test_startup_failure_never_becomes_all_fn(tmp_path):
    result = evaluate_artifacts(dataset(), tmp_path, "failure", "same", 2, 1)
    assert result.status == "technical_failure"
    assert result.detection is None and result.baseline is None
    assert aggregate([result]).numeric == {}


def test_adapter_ok_status_is_successful_real_llm_attempt(tmp_path):
    pipeline = tmp_path / "pipeline"
    write_json(pipeline / "sast/findings.json", [])
    write_json(pipeline / "scout/merged-findings.json", [])
    write_json(pipeline / "scout/summary.json", {"stop_reason": "completed"})
    write_json(pipeline / "gate.json", {"technical_errors": 0, "stage_errors": []})
    (pipeline / "audit").mkdir()
    (pipeline / "audit/llm-attempts.jsonl").write_text(
        '{"provider":"nsu","model":"Qwen3.8-27B","status":"ok"}\n'
    )
    result = evaluate_artifacts(dataset(), tmp_path, "test", "same", 0, 1)
    assert result.status == "completed"
    assert result.performance["llm_calls"] == result.performance["llm_successes"] == 1


def test_seal_detects_changed_artifacts(tmp_path):
    write_json(tmp_path / "metrics.json", {"value": 1})
    seal = artifact_hashes(tmp_path)
    write_json(tmp_path / "seal.json", seal)
    assert artifact_hashes(tmp_path) == seal
    write_json(tmp_path / "metrics.json", {"value": 2})
    assert artifact_hashes(tmp_path) != seal


def test_measurement_restores_real_calls_on_exception():
    import app.pipeline_run as pipeline
    from app.pipeline_run import _resolve_findings

    with pytest.raises(RuntimeError), measure_stages():
        assert pipeline._resolve_findings is not _resolve_findings
        raise RuntimeError("intentional unit-test fault")
    assert pipeline._resolve_findings is _resolve_findings


def test_truth_does_not_cross_production_arguments_profile_prompts_or_proposal(tmp_path):
    import yaml

    from agent.model import DeterministicAgentModel
    from schemas.agent_outputs import AnalysisResult
    from schemas.hypothesis import Hypothesis

    config = yaml.safe_load((ROOT / "benchmarks/juice-shop-v20.2.0/benchmark.yaml").read_text())
    sentinel = "BENCHMARK-TRUTH-SECRET-SENTINEL"
    malicious = deepcopy(config)
    malicious.update(
        expected=sentinel, case_id=sentinel, endpoint=sentinel, ground_truth={"expected": sentinel}
    )
    normal = production_arguments(config, tmp_path, tmp_path / "output")
    injected = production_arguments(malicious, tmp_path, tmp_path / "output")
    assert vars(normal) == vars(injected)
    profile = TargetProfile.from_yaml(ROOT / config["profile"], repository_path_override=tmp_path)
    finding = Finding(
        id="ordinary",
        source="semgrep",
        rule_id="ordinary",
        title="Ordinary",
        description="Source observation",
        file="routes/search.ts",
        line_start=1,
    )
    state = {
        "finding": finding,
        "target_profile": profile,
        "code_context": "query(req.query.q)",
        "iteration_count": 0,
        "max_steps": 1,
    }
    context = _reasoning_context(state)
    analysis = AnalysisResult.model_validate(DeterministicAgentModel().analyse(state))
    hypothesis = Hypothesis.model_validate(
        DeterministicAgentModel().form_hypothesis(state, analysis)
    )
    proposal = DeterministicAgentModel().propose_action(state, analysis, hypothesis)
    serialized = json.dumps(
        [vars(injected), profile.model_dump(mode="json"), context, proposal.model_dump(mode="json")]
    )
    assert sentinel not in serialized
    assert "ground_truth" not in serialized and "benchmark_case" not in serialized
    source = tmp_path / "routes/search.ts"
    source.parent.mkdir()
    source.write_text("query(req.query.q)\n")
    payloads = []

    class CapturingClient:
        def complete_model(self, **kwargs):
            payloads.append(kwargs)
            return ScoutTurn(stop=True)

    RepositoryScout(CapturingClient()).scout(
        ProjectDiscoveryResult(repository_root=tmp_path, project_files=["routes/search.ts"])
    )
    assert sentinel not in str(payloads) and "ground_truth" not in str(payloads)


def test_pinned_ground_truth_validates_real_source_if_available():
    target = ROOT / "artifacts/stage1-juice-shop"
    if not target.exists():
        pytest.skip("Pinned checkout is an operator prerequisite")
    d = load_dataset(ROOT / "benchmarks/juice-shop-v20.2.0/ground_truth.yaml")
    p = TargetProfile.from_yaml(
        ROOT / "targets/juice-presentation.yaml", repository_path_override=target
    )
    manifest = validate_target(d, target, p)
    assert manifest["commit"] == d.target_commit
    assert len(d.cases) == 12 and sum(c.expected == "vulnerable" for c in d.cases) == 10
    assert len({c.category for c in d.cases}) == 6
    with pytest.raises(ValueError, match="commit"):
        validate_target(d.model_copy(update={"target_commit": "a" * 40}), target, p)


def test_dataset_lock_prevents_silent_scoring_policy_change(tmp_path):
    import shutil

    folder = ROOT / "benchmarks/juice-shop-v20.2.0"
    target = ROOT / "artifacts/benchmark-target/juice-shop"
    if not target.exists():
        pytest.skip("Pinned checkout not provisioned")
    for name in ("ground_truth.yaml", "benchmark.yaml", "dataset.lock.json"):
        shutil.copyfile(folder / name, tmp_path / name)
    d = load_dataset(tmp_path / "ground_truth.yaml")
    validate_dataset_lock(tmp_path / "benchmark.yaml", d, target)
    with (tmp_path / "ground_truth.yaml").open("a") as stream:
        stream.write("\n# Changed after freeze\n")
    with pytest.raises(ValueError, match="lock mismatch"):
        validate_dataset_lock(tmp_path / "benchmark.yaml", d, target)


@pytest.mark.parametrize(
    "field,value,error",
    [
        ("artifact", "missing.ts", "artifact"),
        ("line_end", 99, "range"),
        ("service", "unknown", "service"),
        ("endpoint", "/missing", "endpoint"),
        ("provenance", ["missing.ts"], "provenance"),
    ],
)
def test_invalid_ground_truth_source_stops_preflight(tmp_path, monkeypatch, field, value, error):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/search.ts").write_text("statement\n" * 30)
    (tmp_path / "server.ts").write_text("app.get('/rest/products/search', handler)\n")
    p = TargetProfile.from_yaml(
        ROOT / "targets/juice-presentation.yaml", repository_path_override=tmp_path
    )
    c = case().model_copy(update={field: value})
    d = dataset([c])

    def git_command(argv):
        if "rev-parse" in argv:
            return "a" * 40
        if "status" in argv:
            return ""
        if "--eol" in argv:
            return "i/lf w/lf attr/\troutes/search.ts"
        return "routes/search.ts\0server.ts\0"

    monkeypatch.setattr("evaluation.benchmark_harness.command", git_command)
    with pytest.raises(ValueError, match=error):
        validate_target(d, tmp_path, p)
