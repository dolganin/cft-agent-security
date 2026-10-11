from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent.llm import LLMUnavailableError
from agent.repository_scout import RepositoryScout
from app.config import settings
from app.pipeline_run import _append_scout_findings
from discovery.scout import merge_scout_candidates
from discovery.service import ProjectDiscovery
from schemas.discovery import ProjectDiscoveryResult
from schemas.finding import Finding
from schemas.scout import CandidateFinding, ScoutReadRequest, ScoutTurn
from tools.repository_source import RepositorySource


def inventory(root: Path, files: dict[str, str]) -> ProjectDiscoveryResult:
    for file, text in files.items():
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return ProjectDiscoveryResult(repository_root=root, project_files=list(files))


def candidate(file="routes/search.ts", line=2, rule="sql-injection", provenance=None):
    return CandidateFinding(
        file=file, line_start=line, line_end=line, rule_id=rule,
        title="Unsafe query", description="Request input reaches query construction",
        provenance_paths=provenance or [file],
        rationale="Trace input and compare controlled requests before any verdict",
    )


class Client:
    def __init__(self, results):
        self.results = iter(results)
        self.payloads = []

    def complete_model(self, **kwargs):
        self.payloads.append(kwargs["user_payload"])
        result = next(self.results)
        if isinstance(result, Exception):
            raise result
        return result


def test_scout_reads_source_and_follows_model_symbol_search(tmp_path):
    discovery = inventory(tmp_path, {
        "routes/search.ts": "import { lookup } from '../lib/db'\nlookup(req.query.q)\n",
        "lib/db.ts": "export function lookup(q) { return query(q) }\n",
    })
    client = Client([
        ScoutTurn(search_queries=["lookup"],
                  read_requests=[ScoutReadRequest(file="lib/db.ts", line_end=1)]),
        ScoutTurn(candidates=[candidate(provenance=["routes/search.ts", "lib/db.ts"])],
                  stop=True),
    ])
    batch = RepositoryScout(client, max_turns=2).scout(discovery)
    assert len(batch.candidates) == 1
    assert client.payloads[0]["remaining_candidate_budget"] == 32
    assert "lookup(req.query.q)" in str(client.payloads[0]["source_snippets"])
    assert "lib/db.ts" in client.payloads[0]["related_files"]
    assert client.payloads[1]["search_results"][0]["matches"]
    assert "lib/db.ts" in str(client.payloads[1])


def test_real_discovery_preserves_source_without_technology_signals(tmp_path):
    inventory(tmp_path, {
        "package.json": '{"dependencies":{"express":"5"}}',
        "routes/search.ts": "query(req.query.q)\n",
        "node_modules/library/index.js": "dependency",
    })
    discovery = ProjectDiscovery().discover(tmp_path)
    assert "routes/search.ts" in discovery.project_files
    assert not any("node_modules" in path for path in discovery.project_files)
    client = Client([ScoutTurn(candidates=[candidate(line=1)], stop=True)])
    assert len(RepositoryScout(client).scout(discovery).candidates) == 1


def test_candidate_must_reference_read_lines_and_read_provenance(tmp_path):
    discovery = inventory(tmp_path, {"routes/search.ts": "query(req.query.q)\n"})
    client = Client([ScoutTurn(candidates=[
        candidate(line=999_999_999),
        candidate(line=1, provenance=["routes/search.ts", "not-read.ts"]),
        candidate(file="../../outside.ts", line=1),
        candidate(line=1),
    ], stop=True)])
    scout = RepositoryScout(client)
    assert len(scout.scout(discovery).candidates) == 1
    assert scout.audit["rejected_candidates"] == 3


def test_source_reader_blocks_links_tests_secrets_and_answer_annotations(tmp_path):
    discovery = inventory(tmp_path, {
        "routes/search.ts": "const password = 'private-value'\n"
                            "query(req.query.q) // vuln-code-snippet vuln-line answer\n",
        "tests/unit.ts": "test fixture",
        ".env": "PRIVATE=yes",
        "data/codefixes/solution.ts": "answer",
        "frontend/src/hacking-instructor/helpers/answers.ts": "answer",
        "benchmark/oracle.ts": "answer",
    })
    outside = tmp_path.parent / "scout-outside.ts"
    outside.write_text("outside", encoding="utf-8")
    try:
        (tmp_path / "link.ts").symlink_to(outside)
    except OSError:
        pytest.skip("Windows symlinks require developer mode or privilege")
    discovery.project_files.append("link.ts")
    source = RepositorySource(discovery)
    assert source.files == ["routes/search.ts"]
    content = source.read("routes/search.ts")["content"]
    assert "private-value" not in content
    assert "vuln-code-snippet" not in content
    assert "2: query(req.query.q)" in content
    with pytest.raises(ValueError):
        source.read("../scout-outside.ts")


def test_source_redaction_preserves_flow_indentation_and_read_limits(tmp_path):
    discovery = inventory(tmp_path, {
        "routes/search.ts": "  const password = req.body.password\n"
                            "  const token = 'private-value'\n" + "x\n" * 200,
    })
    source = RepositorySource(discovery)
    window = source.read("routes/search.ts", 1, 999_999)
    assert window["line_end"] == 160
    assert "1:   const password = req.body.password" in window["content"]
    assert "private-value" not in window["content"]
    assert len(source.search("x")) <= 16


def test_scout_rejects_candidate_spanning_unread_gap(tmp_path):
    discovery = inventory(tmp_path, {
        "routes/search.ts": "query(req.query.q)\n" + "line\n" * 500,
    })
    invalid = candidate(line=1)
    invalid.line_end = 450
    client = Client([ScoutTurn(candidates=[invalid], stop=True)])
    scout = RepositoryScout(client, max_source_chars=2_000)
    assert scout.scout(discovery).candidates == []


def test_scout_retains_candidates_if_next_model_call_fails(tmp_path):
    discovery = inventory(tmp_path, {
        "routes/search.ts": "query(req.query.q)\n" + "ordinary line\n" * 200,
    })
    client = Client([
        ScoutTurn(candidates=[candidate(line=1)],
                  read_requests=[ScoutReadRequest(file="routes/search.ts", line_start=170,
                                                  line_end=200)]),
        LLMUnavailableError("Unavailable"),
    ])
    # First window capped by size, leaving enough source to request a later region.
    scout = RepositoryScout(client, max_source_chars=5_000)
    assert len(scout.scout(discovery).candidates) == 1
    assert scout.audit["stop_reason"] == "model_unavailable"


def test_scout_budgets_and_cancellation(tmp_path):
    discovery = inventory(tmp_path, {"routes/search.ts": "query(req.query.q)\n"})
    client = Client([])
    scout = RepositoryScout(client, max_source_chars=1)
    assert scout.scout(discovery).candidates == []
    assert not client.payloads
    assert scout.audit["stop_reason"] == "source_budget"
    with pytest.raises(RuntimeError, match="cancelled"):
        RepositoryScout(client, check_cancelled=lambda: (_ for _ in ()).throw(
            RuntimeError("cancelled")
        )).scout(discovery)


def test_search_and_source_share_budget_and_preserve_investigation_context(tmp_path):
    discovery = inventory(tmp_path, {
        "routes/search.ts": "query(req.query.q)\n" + "ordinary line\n" * 300,
    })
    client = Client([
        ScoutTurn(search_queries=["query"]),
        ScoutTurn(stop=True),
    ])
    scout = RepositoryScout(client, max_source_chars=4_000)
    scout.scout(discovery)
    assert scout.audit["source_chars"] + scout.audit["search_chars"] <= 4_000
    assert client.payloads[1]["previous_context"]
    assert "query(req.query.q)" in str(client.payloads[1]["previous_context"])


def test_scout_distributes_initial_windows_across_files(tmp_path):
    discovery = inventory(tmp_path, {
        "routes/large.ts": "query(req.query.q)\n" * 1_000,
        "routes/small.ts": "query(req.query.q)\n",
    })
    client = Client([ScoutTurn(stop=True)])
    RepositoryScout(client).scout(discovery)
    snippets = client.payloads[0]["source_snippets"]
    assert snippets[0]["file"] == "routes/large.ts"
    assert snippets[1]["file"] == "routes/small.ts"


def test_scout_cannot_assign_measured_severity():
    item = candidate()
    item.severity = "HIGH"
    assert item.to_finding(finding_id="candidate").severity is None


def test_merge_deduplicates_family_but_preserves_different_defects_and_stable_ids(tmp_path):
    inventory(tmp_path, {"routes/search.ts": "query(req.query.q)\n" * 8})
    initial = [Finding(id="sast", source="semgrep", rule_id="vendor.sequelize-injection",
                       title="SQL", description="SAST", file="routes/search.ts",
                       line_start=2, line_end=2)]
    merged, duplicates = merge_scout_candidates(initial, [
        candidate(line=2), candidate(line=2, rule="access-control"), candidate(line=8),
    ], service_resolver=lambda file: "backend", repository_root=tmp_path)
    assert duplicates == 1
    assert len(merged) == 3
    assert initial[0].description == "SAST"
    assert len(initial) == 1
    assert merged[1].service == "backend"
    again, _ = merge_scout_candidates([], [candidate(line=8)], repository_root=tmp_path)
    assert merged[-1].id == again[0].id


def test_pipeline_saves_scout_and_merges_into_normal_queue(tmp_path, monkeypatch):
    discovery = inventory(tmp_path / "repo", {"routes/search.ts": "query(req.query.q)\n"})
    client = Client([ScoutTurn(candidates=[candidate(line=1)], stop=True)])

    class Model:
        @classmethod
        def from_settings(cls, settings):
            instance = cls()
            instance.client = client
            return instance

    monkeypatch.setattr("app.pipeline_run.FallbackLLMAgentModel", Model)
    monkeypatch.setattr(settings, "agent_mode", "llm")
    result = _append_scout_findings([], discovery, output_dir=tmp_path / "run")
    assert result[0].source == "model_scout"
    summary = json.loads((tmp_path / "run/scout/summary.json").read_text())
    assert summary["merged_candidates"] == 1
    assert summary["accepted_candidates"] == 1
    assert (tmp_path / "run/scout/merged-findings.json").exists()
