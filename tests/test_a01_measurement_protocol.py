"""A01 semantics only: synthetic unit observations, never a scored V2 benchmark."""

from __future__ import annotations

import hashlib
import json
import shutil
from copy import deepcopy
from itertools import permutations

import pytest
import yaml
from pydantic import ValidationError
from test_stage2_benchmark import case, dataset, observation

from evaluation.benchmark import score, verification_metrics_v2
from evaluation.benchmark_protocol import PROTOCOL, ROOT, load_protocol, split_cases, split_group
from schemas.benchmark import V2_METRIC_TERMS, BenchmarkCaseV2, BenchmarkProtocolV2


def measure(cases, observations, **kwargs):
    d = dataset(cases, negative_universe=any(c.expected == "safe" for c in cases))
    return verification_metrics_v2(score(d, observations), observations, **kwargs)


def test_protocol_is_valid_frozen_v2_with_real_baseline():
    p = load_protocol()
    assert p.dataset_id == "juice-shop-v20.2.0-v2" and p.dataset_version == "2"
    assert p.target_commit == "5658473cf8814459bf89000ce373b20ed0b4eb37"
    assert p.repeats.real_independent_runs == 3
    config = yaml.safe_load((ROOT / "benchmarks/juice-shop-v20.2.0/benchmark.yaml").read_text())
    assert all(p.baseline.settings[k] == v for k, v in config["settings"].items())
    assert p.baseline.max_iterations == config["max_iterations"]
    from agent.llm import parse_route_specs
    from app.config import Settings

    defaults = Settings(_env_file=None)
    for name, value in p.baseline.settings.items():
        if name.startswith("executor_") or name == "llm_allow_external_fallbacks":
            assert value == getattr(defaults, name)
    route, = parse_route_specs(p.baseline.settings["llm_routes"])
    assert route.provider == p.baseline.llm_transport["provider"] == "nsu"
    assert route.model == p.baseline.llm_transport["model"] == "Qwen3.8-27B"
    assert p.freeze.scanners == "A06" and p.ground_truth_status == "pending_A02_A03_A04"
    if (PROTOCOL.parent / "ground_truth.yaml").exists():
        # A01's frozen pending status is historical; A04 adds a separate lock.
        from evaluation.benchmark_freeze import validate
        assert validate()["status"] == "valid_frozen_a04"
    else:
        assert not (PROTOCOL.parent / "dataset.lock.json").exists()


def test_metric_definitions_have_explicit_fixed_denominators():
    p = load_protocol()
    for name, (n, d) in V2_METRIC_TERMS.items():
        assert p.metrics[name].numerator == n
        assert p.metrics[name].denominator == d
        assert p.metrics[name].undefined == "null"
    invalid = p.model_dump()
    invalid["metrics"]["supported_verified_recall"]["denominator"] = "supported_positives_only"
    with pytest.raises(ValidationError, match="formula mismatch"):
        BenchmarkProtocolV2.model_validate(invalid)


@pytest.mark.parametrize("mutation", [
    "missing_metric", "extra_field", "missing_status", "wrong_layer", "missing_budget",
    "bad_budget", "mutable_image", "missing_leakage", "missing_repeat_input",
])
def test_invalid_protocol_is_rejected(mutation):
    p = load_protocol().model_dump()
    if mutation == "missing_metric":
        del p["metrics"]["answered_accuracy"]
    elif mutation == "extra_field":
        p["expected_answers"] = "not permitted"
    elif mutation == "missing_status":
        p["verdicts"]["abstentions"].remove("technical_error")
    elif mutation == "wrong_layer":
        p["metrics"]["confirmed_precision"]["layer"] = "detection"
    elif mutation == "missing_budget":
        del p["baseline"]["settings"]["scout_max_candidates"]
    elif mutation == "bad_budget":
        p["baseline"]["settings"]["scout_max_candidates"] = -1
    elif mutation == "mutable_image":
        p["baseline"]["worker_image"] = "python:3.12-alpine"
    elif mutation == "missing_leakage":
        p["leakage"][0] = "split_labels"
    else:
        p["repeats"]["unchanged"][0] = "matching"
    with pytest.raises(ValidationError):
        BenchmarkProtocolV2.model_validate(p)


def test_zero_confirmations_negatives_and_decisions_are_na():
    v = measure([case()], [])
    assert v.confirmed_precision is None and v.false_confirmation_rate is None
    assert v.answered_accuracy is None
    assert v.supported_verified_recall == 0
    assert v.decision_coverage == 0 and v.abstention_rate == 1
    assert v.abstention_reasons["not_detected"] == 1


@pytest.mark.parametrize("status", [
    "inconclusive", "unsupported", "timeout", "technical_error", "policy_blocked", "not_run",
])
def test_abstentions_remain_separate_never_rejected_or_runtime_detection_fn(status):
    observations = [observation(verification=status)]
    d = dataset()
    matched = score(d, observations)
    v = verification_metrics_v2(matched, observations)
    assert matched.detection.fn == 0
    assert v.counts["rejected_cases"] == v.counts["decided_cases"] == 0
    assert v.abstention_reasons[status] == 1
    assert v.supported_verified_recall == 0 and v.abstention_rate == 1


def test_primary_metric_denominators_accuracy_and_coverage():
    cases = [case("P1"), case("P2", start=30, end=30),
             case("N1", "safe", 50, 50), case("N2", "safe", 70, 70),
             case("N3", "safe", 90, 90)]
    observations = [
        observation("p1", verification="confirmed", evidence_backed=True),
        observation("p2", start=30, end=30, verification="unsupported"),
        observation("n1", start=50, end=50, verification="confirmed", evidence_backed=True),
        observation("n2", start=70, end=70, verification="rejected", evidence_backed=True),
    ]
    v = measure(cases, observations)
    assert v.confirmed_precision == 1 / 2
    assert v.supported_verified_recall == 1 / 2
    assert v.false_confirmation_rate == 1 / 3
    assert v.answered_accuracy == 2 / 3
    assert v.decision_coverage == 3 / 5 and v.abstention_rate == 2 / 5
    assert v.counts["correct_rejections"] == 1 and v.counts["false_confirmations"] == 1


def test_evidence_rejected_positive_is_an_incorrect_answer():
    v = measure([case()], [observation(verification="rejected", evidence_backed=True)])
    assert v.answered_accuracy == 0 and v.decision_coverage == 1
    assert v.counts["false_rejections"] == 1 and v.confirmed_precision is None


@pytest.mark.parametrize("status", ["confirmed", "rejected"])
def test_unbacked_binary_claim_is_abstention(status):
    v = measure([case()], [observation(verification=status)])
    assert v.counts["decided_cases"] == 0
    assert v.abstention_reasons["invalid_evidence"] == 1


def test_duplicate_confirmation_counts_once_and_order_does_not_change_metrics():
    obs = [observation("a", verification="inconclusive"),
           observation("b", verification="confirmed", evidence_backed=True),
           observation("c", verification="confirmed", evidence_backed=True)]
    for order in permutations(obs):
        v = measure([case()], list(order))
        assert v.counts["correct_confirmations"] == v.counts["confirmed_cases"] == 1
        assert v.counts["duplicates"] == 2
        assert v.confirmed_precision == v.supported_verified_recall == 1


def test_duplicate_rejection_can_decide_negative_once():
    v = measure([case(expected="safe")], [observation("a", verification="timeout"),
                observation("b", verification="rejected", evidence_backed=True)])
    assert v.counts["correct_rejections"] == 1
    assert v.decision_coverage == v.answered_accuracy == 1


def test_conflicting_evidence_abstains_without_cherry_picking():
    v = measure([case()], [
        observation("a", verification="confirmed", evidence_backed=True),
        observation("b", verification="rejected", evidence_backed=True),
    ])
    assert v.counts["decided_cases"] == 0
    assert v.abstention_reasons["conflicting_evidence"] == 1


def test_unknown_confirmed_is_retained_outside_primary_precision():
    observations = [observation("known", verification="confirmed", evidence_backed=True),
                    observation("unknown", start=99, end=99,
                                verification="confirmed", evidence_backed=True)]
    matched = score(dataset(), observations)
    v = verification_metrics_v2(matched, observations)
    assert matched.detection.fp == 0 and v.counts["outside_ground_truth"] == 1
    assert len(matched.matches) == 2
    assert v.confirmed_precision == 1 and v.counts["confirmed_cases"] == 1


def test_wrong_service_unreviewed_never_false_confirmation():
    c = case().model_copy(update={"service": "juice"})
    v = measure([c], [observation(service="other", verification="confirmed", evidence_backed=True)])
    assert v.counts["unreviewed"] == 1 and v.counts["false_confirmations"] == 0
    assert v.confirmed_precision is None


def test_one_finding_cannot_confirm_two_independent_cases():
    v = measure([case(), case("CASE-2", start=13, end=20)], [
        observation(start=10, end=20, verification="confirmed", evidence_backed=True),
    ])
    assert v.counts["correct_confirmations"] == 1 and v.supported_verified_recall == 0.5


def test_run_invalid_has_no_security_metrics_or_all_fn_result():
    assert measure([case()], [], technically_valid=False) is None


def grouped(cid="P1", group="root-1", expected="vulnerable", sample="original"):
    return BenchmarkCaseV2(**case(cid, expected).model_dump(),
                           independence_group=group, sample_kind=sample)


def test_split_is_deterministic_order_independent_and_keeps_twins_together():
    policy = load_protocol().split
    cases = [grouped(), grouped("N1", expected="safe", sample="patched"),
             grouped("N2", expected="safe", sample="synthetic"), grouped("P2", "root-2")]
    expected = split_cases(cases, policy)
    assert expected["P1"] == expected["N1"] == expected["N2"]
    for order in permutations(cases):
        assert split_cases(list(order), policy) == expected
    # Fixed vectors protect algorithm, encoding, threshold and seed interpretation.
    assert split_group("root-1", policy) == "holdout"
    assert split_group("root-2", policy) == "holdout"
    assert split_group("root-4", policy) == "development"
    more = [*cases, grouped("P3", "new-root")]
    assert all(split_cases(more, policy)[c.id] == expected[c.id] for c in cases)


def test_split_rejects_inflated_positive_roots_and_duplicate_ids():
    policy = load_protocol().split
    with pytest.raises(ValueError, match="independent cause"):
        split_cases([grouped(), grouped("P2")], policy)
    with pytest.raises(ValueError, match="Duplicate case ID"):
        split_cases([grouped(), grouped()], policy)


def test_protocol_mutation_after_lock_is_detected(tmp_path):
    for name in ("protocol.yaml", "protocol.lock.json"):
        shutil.copyfile(PROTOCOL.parent / name, tmp_path / name)
    path = tmp_path / "protocol.yaml"
    assert load_protocol(path)
    with path.open("ab") as stream:
        stream.write(b"\n# post-lock alteration\n")
    with pytest.raises(ValueError, match="Protocol lock mismatch"):
        load_protocol(path)


def test_frozen_baseline_mismatch_fails_before_any_producer_call(tmp_path, monkeypatch):
    monkeypatch.setattr("evaluation.benchmark_protocol.ROOT", tmp_path)
    with pytest.raises(ValueError, match="Frozen baseline input"):
        load_protocol()


def test_baseline_transport_matches_actual_adapter_without_network(monkeypatch):
    from agent.llm import ProviderFailoverClient, parse_route_specs

    p = load_protocol()
    captured = []

    def capture(url, payload, **kwargs):
        captured.append((url, payload, kwargs["timeout"]))
        return {"choices": [{"message": {"content": "{}"}}]}

    monkeypatch.setattr("agent.llm._post_json", capture)
    settings = p.baseline.settings
    routes = parse_route_specs(settings["llm_routes"])
    client = ProviderFailoverClient(
        routes=routes, credentials={routes[0].key_env: "unit-test-credential"},
        timeout_seconds=settings["llm_timeout_seconds"],
        max_output_tokens=settings["llm_max_output_tokens"],
        reasoning_effort=settings["llm_reasoning_effort"],
    )
    client._request_openai(routes[0], "ordinary system", "ordinary source")
    url, payload, timeout = captured[0]
    assert url == p.baseline.llm_transport["base_url"] + "/chat/completions"
    assert payload["model"] == p.baseline.llm_transport["model"]
    assert payload["temperature"] == p.baseline.llm_transport["temperature"]
    assert payload["stream"] == p.baseline.llm_transport["stream"]
    assert payload["max_tokens"] == settings["llm_max_output_tokens"]
    assert payload["reasoning_effort"] == settings["llm_reasoning_effort"]
    assert timeout == settings["llm_timeout_seconds"]
    assert payload["response_format"]["type"] == p.baseline.llm_transport["response_format"]
    assert "seed" not in payload


def test_historical_v1_files_remain_byte_identical():
    p = load_protocol()
    folder = ROOT / "benchmarks/juice-shop-v20.2.0"
    expected_files = {f.relative_to(ROOT).as_posix() for f in folder.iterdir() if f.is_file()}
    frozen_files = {s for s in p.baseline.input_digests if s.startswith("benchmarks/juice-shop-v20.2.0/")}
    assert expected_files == frozen_files
    for name in frozen_files:
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == p.baseline.input_digests[name]
    lock = json.loads((folder / "dataset.lock.json").read_text())
    assert lock["ground_truth_digest"] == p.baseline.input_digests[
        "benchmarks/juice-shop-v20.2.0/ground_truth.yaml"]


def test_protocol_split_and_truth_do_not_enter_real_prompt_boundaries(tmp_path):
    from agent.llm_model import FallbackLLMAgentModel, _reasoning_context
    from agent.model import DeterministicAgentModel
    from agent.repository_scout import RepositoryScout
    from evaluation.benchmark_harness import production_arguments
    from schemas.agent_outputs import AnalysisResult
    from schemas.discovery import ProjectDiscoveryResult
    from schemas.finding import Finding
    from schemas.scout import ScoutTurn
    from schemas.target import TargetProfile

    sentinel = "A01-HOLDOUT-TRUTH-SECRET-SENTINEL"
    config = yaml.safe_load((ROOT / "benchmarks/juice-shop-v20.2.0/benchmark.yaml").read_text())
    injected = deepcopy(config)
    metadata = {key: sentinel for key in (*load_protocol().leakage, "independence_group")}
    injected.update(metadata)
    assert vars(production_arguments(config, tmp_path, tmp_path / "out")) == vars(
        production_arguments(injected, tmp_path, tmp_path / "out"))
    profile = TargetProfile.from_yaml(ROOT / config["profile"], repository_path_override=tmp_path)
    assert all(key not in profile.model_dump() for key in metadata)
    finding = Finding(id="ordinary", source="semgrep", rule_id="ordinary", title="Ordinary",
                      description="Source observation", file="routes/search.ts", line_start=1)
    state = {"finding": finding, "target_profile": profile, "code_context": "query(req.query.q)",
             "iteration_count": 0, "max_steps": 1, **metadata}
    payloads = []

    class CapturingClient:
        def complete_model(self, **kwargs):
            payloads.append(kwargs)
            if kwargs["output_model"] is ScoutTurn:
                return ScoutTurn(stop=True)
            return DeterministicAgentModel().analyse(state)

    analysis = AnalysisResult.model_validate(FallbackLLMAgentModel(CapturingClient()).analyse(state))
    hypothesis = DeterministicAgentModel().form_hypothesis(state, analysis)
    proposal = DeterministicAgentModel().propose_action(state, analysis, hypothesis)
    source = tmp_path / "routes/search.ts"
    source.parent.mkdir()
    source.write_text("query(req.query.q)\n")
    RepositoryScout(CapturingClient()).scout(ProjectDiscoveryResult(
        repository_root=tmp_path, project_files=["routes/search.ts"]))
    captured = json.dumps([
        [{k: v for k, v in payload.items() if k != "output_model"} for payload in payloads],
        _reasoning_context(state), proposal.model_dump(mode="json"),
    ])
    assert sentinel not in captured
    assert not any(key in captured for key in metadata)
