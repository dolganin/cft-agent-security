from pathlib import Path

import pytest

from agent.llm import LLMUnavailableError
from agent.repository_scout import RepositoryScout
from agent.scout_schedule import source_schedule, unread_coverage
from schemas.discovery import ProjectDiscoveryResult
from schemas.scout import CandidateFinding, ScoutReadRequest, ScoutTurn
from schemas.source_map import ExpressRouteRegistration, ExpressSourceMap
from tools.repository_source import RepositorySource


def corpus(root: Path, files: dict[str, str]):
    for file, text in files.items():
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return ProjectDiscoveryResult(repository_root=root, project_files=list(files))


class Client:
    def __init__(self, fail=False):
        self.payloads = []
        self.fail = fail

    def complete_model(self, **kwargs):
        self.payloads.append(kwargs["user_payload"])
        if self.fail:
            raise LLMUnavailableError("test failure")
        return ScoutTurn()


def test_focused_schedule_reaches_tail_without_changing_legacy(tmp_path):
    discovery = corpus(tmp_path, {
        "routes/search.ts": "// padding\n" * 300 + "query(req.query.q)\n",
    })
    source = RepositorySource(discovery)
    assert source_schedule(source, None, "round_robin")[0] == ("routes/search.ts", 1, 160)
    assert source_schedule(source, None, "handlers")[0][1] == 281
    legacy, focused = Client(), Client()
    RepositoryScout(legacy, max_turns=1, max_source_chars=1800).scout(discovery)
    scout = RepositoryScout(focused, schedule_mode="handlers", max_turns=1,
                            max_source_chars=1800)
    scout.scout(discovery)
    assert "query(req.query.q)" not in str(legacy.payloads)
    assert "query(req.query.q)" in str(focused.payloads)
    assert scout.audit["unread_ranges"]
    assert scout.audit["model_calls"] == 1
    assert scout.audit["turns"][0]["latency_ms"] >= 0


def test_failed_response_does_not_count_as_reviewed(tmp_path):
    discovery = corpus(tmp_path, {"routes/a.ts": "query(req.query.q)\n"})
    scout = RepositoryScout(Client(fail=True), schedule_mode="handlers")
    scout.scout(discovery)
    assert scout.audit["reviewed_source_lines"] == 0
    assert scout.audit["submitted_ranges"]
    assert scout.audit["unread_files"] == ["routes/a.ts"]
    assert scout.audit["stop_reason"] == "model_unavailable"


def test_coverage_union_and_gaps(tmp_path):
    source = RepositorySource(corpus(tmp_path, {"a.ts": "line\n" * 10}))
    result = unread_coverage(source, {"a.ts": [(2, 4), (3, 7), (9, 10)]})
    assert result["unread_ranges"] == [
        {"file": "a.ts", "line_start": 1, "line_end": 1},
        {"file": "a.ts", "line_start": 8, "line_end": 8},
    ]
    assert result["fully_reviewed_files"] == 0
    assert unread_coverage(source, {"a.ts": [(1, 10)]})["fully_reviewed_files"] == 1


def test_private_pem_and_fixtures_never_reach_model(tmp_path):
    source = RepositorySource(corpus(tmp_path, {
        "routes/a.ts": "const privateKey = `-----BEGIN RSA PRIVATE KEY-----\n"
                       "PRIVATE_MATERIAL\n-----END RSA PRIVATE KEY-----`;\n"
                       "query(req.query.q)\n",
        "b.ts": "const k = '-----BEGIN PRIVATE KEY-----hidden-----END PRIVATE KEY-----'\n",
        "benchmarks/answer.ts": "answer",
        "fixtures/data.ts": "answer",
        "foo.spec.tsx": "answer",
        "bar.test.mjs": "answer",
    }))
    assert set(source.files) == {"routes/a.ts", "b.ts"}
    text = source.read("routes/a.ts", 1, 4)["content"]
    assert "PRIVATE_MATERIAL" not in text
    assert "4: query(req.query.q)" in text
    assert "hidden" not in source.read("b.ts")["content"]


def test_relative_import_followup_is_bounded_and_read_only(tmp_path):
    files = {"routes/a.ts": "import { lookup } from '../lib/b';\n"
                              "query(req.query.q)\n" + "//" + "x" * 1500 + "\n"}
    # These large first windows force the imported helper into the next turn.
    files.update({f"routes/r{i}.ts": "query(req.query.q)\n" + "//" + "x" * 1500 + "\n"
                  for i in range(20)})
    files["lib/b.ts"] = "export function lookup(q) { return query(q); }\n"
    discovery = corpus(tmp_path, files)
    scout = RepositoryScout(Client(), schedule_mode="handlers", max_turns=2)
    scout.scout(discovery)
    assert scout.audit["dependency_followups"] == [{
        "file": "lib/b.ts", "from_file": "routes/a.ts",
        "reason": "relative_import_in_indexed_source",
    }]
    assert any(r["file"] == "lib/b.ts" for r in scout.audit["reviewed_ranges"])
    assert len(scout.audit["dependency_followups"]) <= 16


def test_invalid_schedule_rejected():
    with pytest.raises(ValueError):
        RepositoryScout(Client(), schedule_mode="unknown")


def test_solution_serving_controllers_are_not_model_source(tmp_path):
    source = RepositorySource(corpus(tmp_path, {
        "routes/vulnCodeSnippet.ts": "return expectedAnswer;\n",
        "routes/vulnCodeFixes.ts": "return correctFix;\n",
        "routes/application.ts": "query(req.query.q);\n",
    }))
    assert source.files == ["routes/application.ts"]


def test_symbol_search_does_not_hide_definition_behind_first_16_callers(tmp_path):
    source = RepositorySource(corpus(tmp_path, {
        "server.ts": "appendUserId();\n" * 40,
        "lib/auth.ts": "export const appendUserId = () => {};\n",
    }))
    matches = source.search("appendUserId")
    assert len(matches) == 16
    assert matches[0]["file"] == "lib/auth.ts"


def test_backend_models_are_indexed_before_large_frontend_trees(tmp_path):
    files = {f"frontend/src/page-{i:03}.ts": "export const page = true;\n"
             for i in range(300)}
    files["models/user.ts"] = "export class User { password = hash(input); }\n"
    source = RepositorySource(corpus(tmp_path, files))

    assert len(source.lines) == 256
    assert "models/user.ts" in source.lines
    assert source.search("User") == [{
        "file": "models/user.ts", "line": 1,
        "text": "export class User { password = hash(input); }",
    }]
    assert len([path for path in source.lines if path.startswith("frontend/")]) < 256


def test_source_map_prioritizes_only_indexed_handlers(tmp_path):
    source = RepositorySource(corpus(tmp_path, {
        "routes/a.ts": "query(req.query.q)\n", "lib/b.ts": "const safe = 1;\n",
    }))
    source_map = ExpressSourceMap(routes=[ExpressRouteRegistration(
        id="test-route", file="routes/a.ts", receiver="app", method="get",
        path="/example", path_is_static=True, line_start=1, line_end=1,
        registration_order=0,
        handler_files=["lib/b.ts", "../../outside.ts"],
    )])
    schedule = source_schedule(source, source_map, "handlers")
    assert schedule[0][0] == "lib/b.ts"
    assert all(item[0] in source.lines for item in schedule)


def test_requests_cannot_starve_scheduled_windows(tmp_path):
    discovery = corpus(tmp_path, {
        f"routes/r{i}.ts": "query(req.query.q)\n" + ("//" + "x" * 1400 + "\n") * 15
        for i in range(10)
    })

    class RequestClient(Client):
        def complete_model(self, **kwargs):
            self.payloads.append(kwargs["user_payload"])
            return ScoutTurn(read_requests=[
                ScoutReadRequest(file="routes/r0.ts", line_start=i, line_end=i + 4)
                for i in range(1, 9)
            ])

    client = RequestClient()
    scout = RepositoryScout(client, schedule_mode="handlers", max_turns=2)
    scout.scout(discovery)
    first = {s["file"] for s in client.payloads[0]["source_snippets"]}
    second = {s["file"] for s in client.payloads[1]["source_snippets"]}
    assert second - first


def test_automatic_followups_have_global_cap(tmp_path):
    discovery = corpus(tmp_path, {
        **{f"routes/r{i}.ts": f"import {{ helper }} from '../lib/b{i}';\nquery(req.query.q)\n"
           for i in range(25)},
        **{f"lib/b{i}.ts": "//" + "padding\n" * 200 for i in range(25)},
    })
    scout = RepositoryScout(Client(), schedule_mode="handlers", max_turns=1,
                            max_source_chars=1500)
    scout.scout(discovery)
    assert len(scout.audit["dependency_followups"]) == 16


def test_standalone_candidate_comparison_never_claims_confirmation(tmp_path, monkeypatch):
    from app import scout as cli
    from schemas.finding import Finding

    discovery = corpus(tmp_path / "target", {
        "routes/a.ts": "query(req.query.q)\n",
        "lib/b.ts": "createHash('md5')\n",
    })
    baseline = tmp_path / "baseline.json"
    baseline.write_text("[" + Finding(
        id="sast-one", rule_id="sql-injection", file="routes/a.ts", line_start=1,
        description="Candidate", title="Candidate", source="semgrep", severity="WARNING",
    ).model_dump_json() + "]", encoding="utf-8")
    class CandidateClient(Client):
        def complete_model(self, **kwargs):
            self.payloads.append(kwargs["user_payload"])
            return ScoutTurn(candidates=[CandidateFinding(
                rule_id="weak-cryptography", title="Hash candidate",
                description="Use of MD5 requires investigation", file="lib/b.ts",
                line_start=1, line_end=1, provenance_paths=["lib/b.ts"],
                rationale="Trace hash consumer before any verdict",
            )])

    client = CandidateClient()
    monkeypatch.setattr(cli.ProjectDiscovery, "discover", lambda *args: discovery)
    monkeypatch.setattr(cli.FallbackLLMAgentModel, "from_settings",
                        lambda *args: type("Model", (), {"client": client})())
    import sys
    monkeypatch.setattr(sys, "argv", ["scout", "--target", str(discovery.repository_root),
                                      "--output-dir", str(tmp_path / "results"),
                                      "--schedule", "handlers", "--max-turns", "1",
                                      "--sast-findings", str(baseline)])
    assert cli.main() == 0
    import json
    result = json.loads((tmp_path / "results/summary.json").read_text())
    assert result["sast_vs_sast_scout"]["sast_queue"] == 1
    assert result["sast_vs_sast_scout"]["combined_queue"] == 2
    assert result["sast_vs_sast_scout"]["new_scout_candidates"] == 1
    assert "not_precision_recall_or_confirmed" in result["sast_vs_sast_scout"]["scope"]
    assert "sast-one" not in str(client.payloads)
    with pytest.raises(FileExistsError):
        cli.main()
