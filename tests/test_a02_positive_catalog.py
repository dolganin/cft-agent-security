"""A02 read-only extraction, grounding, independence and evaluator isolation."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from itertools import permutations

import pytest
import yaml
from pydantic import ValidationError

from evaluation.benchmark_protocol import ROOT, load_protocol, split_group
from evaluation.positive_catalog import (
    CATALOG,
    anchor,
    challenge_metadata,
    extract_annotations,
    extract_candidates,
    snapshot,
    validate_anchor,
    validate_catalog,
    validate_http,
    write_yaml,
)
from schemas.benchmark_catalog import (
    CatalogAnchor,
    CatalogHTTPAnchor,
    ExcludedCatalog,
    PositiveCatalog,
)
from schemas.source_map import ExpressSourceMap

TARGET = ROOT / "artifacts/benchmark-target/juice-shop"


def reviewed_data():
    return yaml.safe_load((CATALOG / "positives.reviewed.yaml").read_text(encoding="utf-8"))


@pytest.fixture
def fake_target(tmp_path, monkeypatch):
    """Immutable mocked Git tree: literal test code is read, never executed."""
    files = {
        "data/static/challenges.yml": b"---\n-\n  key: firstChallenge\n  name: First\n  category: XSS\n  description: Literal source test\n-\n  key: secondChallenge\n  name: Second\n  category: Injection\n  description: Second source test\n  disabledEnv: [Docker]\n",
        "server.ts": b"import express from 'express'\nconst app = express()\n// vuln-code-snippet start firstChallenge secondChallenge\napp.get('/one', (req, res) => res.send(req.query.q)) // vuln-code-snippet vuln-line firstChallenge\napp.get('/two', (req, res) => res.send(req.query.id)) // vuln-code-snippet vuln-line secondChallenge\n// vuln-code-snippet end firstChallenge secondChallenge\n",
        "routes/handler.ts": b"// source reference firstChallenge\n",
        "test/server/handler.unit.test.ts": b"// upstream reference secondChallenge\n",
    }
    for name, raw in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(raw)
    tree = b"".join(
        b"100644 blob " + hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest().encode()
        + b"\t" + name.encode() + b"\0" for name, raw in sorted(files.items())
    )

    def fake_git(target, *args):
        if args[:1] == ("rev-parse",):
            return load_protocol().target_commit.encode() + b"\n"
        if args[:1] == ("status",):
            return b""
        return tree

    monkeypatch.setattr("evaluation.positive_catalog.git", fake_git)
    return tmp_path, files


def test_extractor_deterministic_and_order_independent(fake_target, monkeypatch):
    target, files = fake_target
    original = extract_candidates(target)
    assert original == extract_candidates(target)
    monkeypatch.setattr("evaluation.positive_catalog.snapshot", lambda *_: dict(reversed(list(files.items()))))
    assert original == extract_candidates(target)
    assert [c["key"] for c in original["candidates"]] == ["firstChallenge", "secondChallenge"]


def test_exact_target_commit_required(fake_target, monkeypatch):
    target, _ = fake_target
    monkeypatch.setattr("evaluation.positive_catalog.git", lambda *_: b"a" * 40)
    with pytest.raises(ValueError, match="exact protocol target commit"):
        snapshot(target, load_protocol().target_commit)


def test_source_bytes_bound_to_immutable_git_tree(fake_target):
    target, _ = fake_target
    (target / "server.ts").write_bytes(b"changed source bytes\n")
    with pytest.raises(ValueError, match="pinned Git blob"):
        snapshot(target, load_protocol().target_commit)


def test_challenge_metadata_and_annotations_parsed(fake_target):
    target, files = fake_target
    metadata = challenge_metadata(files)
    assert metadata["firstChallenge"]["name"] == "First"
    assert metadata["secondChallenge"]["disabled_environments"] == ["Docker"]
    parsed = extract_annotations(files, set(metadata))
    assert parsed["firstChallenge"]["spans"][0]["line_start"] == 3
    assert parsed["firstChallenge"]["spans"][0]["line_end"] == 6
    assert parsed["firstChallenge"]["vulnerable_lines"][0]["line_start"] == 4
    assert parsed["secondChallenge"]["vulnerable_lines"][0]["line_start"] == 5
    generated = extract_candidates(target)
    assert generated["source_map"]["routes"][0]["path"] == "/one"
    second = generated["candidates"][1]
    assert any(ref["kind"] == "upstream_test" for ref in second["references"])


def test_unclosed_annotations_are_rejected(fake_target):
    _, files = fake_target
    files = {**files, "routes/handler.ts": b"// vuln-code-snippet start firstChallenge\n"}
    with pytest.raises(ValueError, match="Unclosed"):
        extract_annotations(files, {"firstChallenge", "secondChallenge"})


@pytest.mark.parametrize("mutation", ["file", "range", "file_digest", "region_digest", "tokens"])
def test_anchor_grounding_rejects_invalid_source_regions(fake_target, mutation):
    _, files = fake_target
    value = anchor(files, "server.ts", 4, 4, "sink", ["req.query.q"])
    validate_anchor(CatalogAnchor.model_validate(value), files)
    if mutation == "file":
        value["file"] = "missing.ts"
    elif mutation == "range":
        value["line_end"] = 9999
    elif mutation == "file_digest":
        value["file_sha256"] = "a" * 64
    elif mutation == "region_digest":
        value["region_sha256"] = "b" * 64
    else:
        value["required_tokens"] = ["NOT-IN-SOURCE"]
    with pytest.raises(ValueError):
        validate_anchor(CatalogAnchor.model_validate(value), files)


def test_http_registration_validated_without_new_matching(fake_target):
    target, files = fake_target
    generated = extract_candidates(target)
    mapping = ExpressSourceMap.model_validate(generated["source_map"])
    value = {"method": "GET", "endpoint": "/one", "parameter": "query.q", "basis": "direct_express",
             "registration": anchor(files, "server.ts", 4, 4, "registration", ["/one"])}
    validate_http(CatalogHTTPAnchor.model_validate(value), mapping, files)
    with pytest.raises(ValueError, match="supporting registration"):
        validate_http(CatalogHTTPAnchor.model_validate({**value, "endpoint": "/missing"}), mapping, files)


@pytest.fixture
def grounded_unit_catalog(fake_target):
    target, files = fake_target
    generated = extract_candidates(target)
    metadata = generated["candidates"][0]["metadata_anchor"]
    sink = anchor(files, "server.ts", 4, 4, "sink", ["res.send(req.query.q)"])
    p = load_protocol()
    group = "unit-unescaped-html-response"
    case = {
        "id": "JS-UNIT-001", "category": "xss", "cwe": "CWE-79",
        "independence_group": group, "root_cause_key": "unit-unescaped-html-response",
        "root_cause_summary": "A literal unit fixture sends request q as unescaped HTML.",
        "primary_candidate": "firstChallenge", "challenge_keys": ["firstChallenge"],
        "source_anchors": [sink], "http_anchors": [{
            "method": "GET", "endpoint": "/one", "parameter": "query.q", "basis": "direct_express",
            "registration": anchor(files, "server.ts", 4, 4, "registration", ["/one"]),
        }], "service": "juice", "runtime_prerequisites": ["Unit source is never executed."],
        "required_identity": None, "expected_vulnerable_effect": "Unescaped request data reaches an HTML response.",
        "verification_criterion": "Unit source-only grounding of the request-to-response operation; no runtime claim.",
        "provenance": [{"kind": "challenge_metadata", "anchor": metadata,
                        "explanation": "Literal unit challenge metadata."},
                       {"kind": "source_code", "anchor": sink,
                        "explanation": "Literal unit request-to-response source."}],
        "runtime_eligible": True, "eligibility_reason": "Unit source fixture only; no disabled metadata.",
        "detection_only_eligible": True, "future_runtime_evaluation": "unknown",
        "execution_restrictions": ["Never execute this unit fixture."],
        "review_status": "source_reviewed_positive",
        "reviewer_status": "single_reviewer_pending_independent_review",
        "review_basis": "Synthetic unit contract testing only; this is not a Juice Shop positive or control.",
        "split": split_group(group, p.split),
    }
    directory = target.parent / (target.name + "-catalog")
    raw = {
        "schema_version": "benchmark.positive_catalog.a02.v1", "target_commit": p.target_commit,
        "protocol_sha256": reviewed_data()["protocol_sha256"],
        "status": "A02_source_reviewed_not_A04_frozen_ground_truth",
        "reviewer_status": "single_reviewer_pending_independent_review", "cases": [case],
    }
    excluded = {"schema_version": "benchmark.exclusions.a02.v1", "target_commit": p.target_commit,
                "exclusions": [{"candidate_key": "secondChallenge", "reason": "other",
                                "detail": "Unit candidate retained as unreviewed; no negative label."}]}
    write_yaml(directory / "candidates.generated.yaml", generated)
    write_yaml(directory / "positives.reviewed.yaml", raw)
    write_yaml(directory / "excluded.yaml", excluded)
    assert validate_catalog(target, directory)["selected_positives"] == 1
    return target, directory, raw, excluded


@pytest.mark.parametrize("mutation", [
    "unknown_challenge", "unknown_service", "wrong_split", "invented_http",
    "missing_exclusion", "duplicate_exclusion", "altered_generated", "docker_disabled",
])
def test_full_catalog_preflight_rejects_mismatches(grounded_unit_catalog, mutation):
    target, directory, raw, excluded = grounded_unit_catalog
    case = raw["cases"][0]
    if mutation == "unknown_challenge":
        case["challenge_keys"].append("missingChallenge")
    elif mutation == "unknown_service":
        case["service"] = "foreign"
    elif mutation == "wrong_split":
        case["split"] = "holdout" if case["split"] == "development" else "development"
    elif mutation == "invented_http":
        case["http_anchors"][0]["endpoint"] = "/not-registered"
    elif mutation == "missing_exclusion":
        excluded["exclusions"] = []
    elif mutation == "duplicate_exclusion":
        excluded["exclusions"].append(deepcopy(excluded["exclusions"][0]))
    elif mutation == "altered_generated":
        saved = yaml.safe_load((directory / "candidates.generated.yaml").read_text(encoding="utf-8"))
        saved["candidates"][0]["name"] = "post-generation alteration"
        write_yaml(directory / "candidates.generated.yaml", saved)
    else:
        saved = yaml.safe_load((directory / "candidates.generated.yaml").read_text(encoding="utf-8"))
        case["primary_candidate"] = "secondChallenge"
        case["challenge_keys"] = ["secondChallenge"]
        case["provenance"][0]["anchor"] = saved["candidates"][1]["metadata_anchor"]
    write_yaml(directory / "positives.reviewed.yaml", raw)
    write_yaml(directory / "excluded.yaml", excluded)
    with pytest.raises(ValueError):
        validate_catalog(target, directory)


@pytest.mark.parametrize("field", ["id", "independence_group", "root_cause_key"])
def test_duplicate_positive_identity_or_root_cause_rejected(field):
    values = reviewed_data()
    values["cases"][1][field] = values["cases"][0][field]
    with pytest.raises(ValidationError, match="Duplicate"):
        PositiveCatalog.model_validate(values)


def test_shared_challenge_is_not_itself_a_root_cause_collision():
    values = reviewed_data()
    # A challenge may describe two different source defects. Structural catalog
    # validation must compare root causes/anchors, not impose one challenge = one case.
    key = values["cases"][0]["primary_candidate"]
    values["cases"][1]["primary_candidate"] = key
    values["cases"][1]["challenge_keys"].append(key)
    result = PositiveCatalog.model_validate(values)
    assert result.cases[0].primary_candidate == result.cases[1].primary_candidate
    assert result.cases[0].independence_group != result.cases[1].independence_group


def test_renaming_ids_groups_and_ranges_does_not_hide_duplicate_sink():
    values = reviewed_data()
    clone = deepcopy(values["cases"][0])
    clone.update(id="JS-DUPLICATE-999", independence_group="renamed-group", root_cause_key="renamed-cause",
                 primary_candidate="ghostLoginChallenge", challenge_keys=["ghostLoginChallenge"])
    values["cases"].append(clone)
    with pytest.raises(ValidationError, match="Overlapping root-cause"):
        PositiveCatalog.model_validate(values)


@pytest.mark.parametrize("group", ["", "../foreign", "contains space", "has\0nul"])
def test_independence_group_format_is_strict(group):
    values = reviewed_data()
    values["cases"][0]["independence_group"] = group
    with pytest.raises(ValidationError):
        PositiveCatalog.model_validate(values)


def test_multiple_source_anchors_and_relationships_are_preserved():
    catalog = PositiveCatalog.model_validate(reviewed_data())
    case = next(c for c in catalog.cases if c.id == "JS-REDIRECT-001")
    assert {a.file for a in case.source_anchors} == {"routes/redirect.ts", "lib/insecurity.ts"}
    assert {a.role for a in case.source_anchors} == {"caller", "sink"}
    assert case.relations[0].relation == "calls"
    assert case.http_anchors[0].endpoint == "/redirect"
    assert len(next(c for c in catalog.cases if c.id == "JS-XSS-002").source_anchors) == 5


def test_excluded_dispositions_preserve_reason_and_are_not_negative_controls():
    excluded = ExcludedCatalog.model_validate(yaml.safe_load(
        (CATALOG / "excluded.yaml").read_text(encoding="utf-8")))
    assert len({e.candidate_key for e in excluded.exclusions}) == len(excluded.exclusions)
    assert all(e.detail and e.not_a_negative_label for e in excluded.exclusions)
    assert any(e.reason == "duplicate_root_cause" and e.represented_by for e in excluded.exclusions)
    assert any(e.reason == "docker_disabled" for e in excluded.exclusions)
    assert all(c["expected"] == "vulnerable" for c in reviewed_data()["cases"])


def test_runtime_ineligible_cases_remain_explicit_and_review_is_not_invented():
    catalog = PositiveCatalog.model_validate(reviewed_data())
    ineligible = {c.id for c in catalog.cases if not c.runtime_eligible}
    assert ineligible == {"JS-NOSQL-002", "JS-XSS-002", "JS-CODE-001", "JS-SSRF-001", "JS-PATH-001", "JS-XXE-001"}
    assert all(c.detection_only_eligible and c.eligibility_reason for c in catalog.cases)
    assert catalog.reviewer_status == "single_reviewer_pending_independent_review"
    assert all(c.reviewer_status == catalog.reviewer_status for c in catalog.cases)


def test_split_uses_only_a01_helper_and_is_stable_for_related_groups():
    cases = PositiveCatalog.model_validate(reviewed_data()).cases
    policy = load_protocol().split
    for c in cases:
        assert c.split == split_group(c.independence_group, policy)
    selected = cases[:4]
    expected = {c.id: c.split for c in selected}
    for order in permutations(selected):
        assert {c.id: split_group(c.independence_group, policy) for c in order} == expected
    groups = {c.independence_group for c in cases}
    for group in groups:
        assert len({split_group(group, policy) for _ in range(3)}) == 1
    assert sum(c.split == "development" for c in cases) == 20


def test_evaluator_catalog_cannot_be_placed_inside_target(fake_target):
    target, _ = fake_target
    with pytest.raises(ValueError, match="outside target discovery"):
        validate_catalog(target, target / "catalog")


def test_v1_and_a01_lock_still_validate():
    p = load_protocol()
    for file, digest in p.baseline.input_digests.items():
        if file.startswith("benchmarks/juice-shop-v20.2.0/"):
            assert hashlib.sha256((ROOT / file).read_bytes()).hexdigest() == digest
    assert p.dataset_id == "juice-shop-v20.2.0-v2"


@pytest.mark.skipif(not TARGET.exists(), reason="Pinned operator checkout is required for source grounding")
def test_reviewed_real_catalog_validates_pinned_sources_and_every_candidate_disposition():
    summary = validate_catalog(TARGET)
    assert summary["candidates"] == 116 and summary["selected_positives"] == 27
    assert summary["runtime_eligible"] == 21 and summary["detection_only"] == 6
    assert len(summary["families"]) == 18


def test_catalog_truth_does_not_enter_scout_agent_profile_or_production_arguments(tmp_path):
    from agent.llm_model import FallbackLLMAgentModel
    from agent.model import DeterministicAgentModel
    from agent.repository_scout import RepositoryScout
    from evaluation.benchmark_harness import production_arguments
    from schemas.discovery import ProjectDiscoveryResult
    from schemas.finding import Finding
    from schemas.scout import ScoutTurn
    from schemas.target import TargetProfile

    sentinel = "A02-CATALOG-TRUTH-SECRET-SENTINEL"
    metadata = {k: sentinel for k in ("positive_catalog", "reviewed_labels", "expected_vulnerable_effect",
                                     "independence_group", "catalog_split", "source_anchors")}
    config = yaml.safe_load((ROOT / "benchmarks/juice-shop-v20.2.0/benchmark.yaml").read_text())
    normal = production_arguments(config, tmp_path, tmp_path / "out")
    injected = production_arguments({**config, **metadata}, tmp_path, tmp_path / "out")
    assert vars(normal) == vars(injected)
    profile = TargetProfile.from_yaml(ROOT / config["profile"], repository_path_override=tmp_path)
    assert sentinel not in profile.model_dump_json()
    finding = Finding(id="ordinary", source="semgrep", rule_id="ordinary", title="Ordinary",
                      description="Source observation", file="routes/handler.ts", line_start=1)
    state = {"finding": finding, "target_profile": profile, "code_context": "query(req.query.q)",
             "iteration_count": 0, "max_steps": 1, **metadata}
    payloads = []

    class CapturingClient:
        def complete_model(self, **kwargs):
            payloads.append({k: v for k, v in kwargs.items() if k != "output_model"})
            return ScoutTurn(stop=True) if kwargs["output_model"] is ScoutTurn else DeterministicAgentModel().analyse(state)

    analysis = FallbackLLMAgentModel(CapturingClient()).analyse(state)
    hypothesis = DeterministicAgentModel().form_hypothesis(state, analysis)
    proposal = DeterministicAgentModel().propose_action(state, analysis, hypothesis)
    source = tmp_path / "routes/handler.ts"
    source.parent.mkdir()
    source.write_text("query(req.query.q)\n")
    RepositoryScout(CapturingClient()).scout(ProjectDiscoveryResult(
        repository_root=tmp_path, project_files=["routes/handler.ts"]))
    captured = json.dumps([payloads, proposal.model_dump(mode="json")])
    assert sentinel not in captured
    assert not any(k in captured for k in metadata)
