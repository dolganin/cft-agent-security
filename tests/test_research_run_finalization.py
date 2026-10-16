"""Cancellation/slow transport regression and conservative research grouping."""
import json
import multiprocessing
import threading
import time
from contextlib import ExitStack
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace

import pytest

from agent.budget import (
    ReasoningBudgetExpired,
    bounded_timeout,
    provider_deadline,
    reasoning_budget,
)
from agent.http_transport import post_json
from app.research_run import failure_checkpoint
from pipeline.cancellation import CancellationToken, RunCancelled, cancellation_scope
from pipeline.research_queue import ResearchQueue
from schemas.finding import Finding
from schemas.research_agent import ResearchProgress
from schemas.source_map import ExpressSourceMap
from schemas.target import TargetProfile


@pytest.fixture
def provider():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            if self.path == "/slow":
                self.send_response(200)
                self.send_header("Content-Length", "100000")
                self.end_headers()
                try:
                    for _ in range(100):
                        self.wfile.write(b" ")
                        self.wfile.flush()
                        time.sleep(.05)
                except (BrokenPipeError, ConnectionResetError):
                    pass
            else:
                self.send_response(401 if self.path == "/unauthorized" else 200)
                self.end_headers()
                self.wfile.write(b'{"ready":true}')

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()
    server.server_close()
    thread.join(timeout=2)


def test_transport_returns_json_and_preserves_auth_error(provider):
    assert post_json(provider, {}, headers={}, timeout=3) == {"ready": True}
    with pytest.raises(RuntimeError, match="HTTP 401"):
        post_json(provider + "/unauthorized", {}, headers={}, timeout=3)


def test_trickling_response_has_total_deadline_and_no_live_child(provider):
    children = {p.pid for p in multiprocessing.active_children()}
    started = time.monotonic()
    with pytest.raises(RuntimeError, match="total request deadline"):
        post_json(provider + "/slow", {}, headers={}, timeout=.8)
    assert time.monotonic() - started < 2.5
    assert {p.pid for p in multiprocessing.active_children()} == children


def test_operator_cancel_joins_transport_child(provider):
    token = CancellationToken()
    timer = threading.Timer(.4, token.cancel)
    children = {p.pid for p in multiprocessing.active_children()}
    timer.start()
    try:
        with cancellation_scope(token), pytest.raises(RunCancelled):
            post_json(provider + "/slow", {}, headers={}, timeout=10)
    finally:
        timer.cancel()
        timer.join()
    assert {p.pid for p in multiprocessing.active_children()} == children


def test_question_deadline_cannot_extend_campaign_deadline():
    with provider_deadline(time.monotonic() + .1), reasoning_budget({"wall_clock_budget_seconds": 300}):
        assert 0 < bounded_timeout(45) <= .1
    assert bounded_timeout(45) == 45


def test_total_deadline_is_budget_expiration_not_provider_outage(provider):
    from agent.llm import _post_json

    with provider_deadline(time.monotonic() + .3), pytest.raises(ReasoningBudgetExpired):
        _post_json(provider + "/slow", {}, headers={}, timeout=bounded_timeout(10))


def test_expired_reasoning_keeps_current_research_accounting():
    from test_research_agent import finding, scope

    from agent.recovery import protected_node
    from agent.research import ResearchAgentModel, research_context

    model = ResearchAgentModel(client=None, scope=scope(), validator=None)
    def expired(_state):
        model.progress.model_calls = 2
        raise ReasoningBudgetExpired("test")

    with research_context(model):
        state = protected_node("analyse", expired)({"finding": finding()})
    assert state["stop_reason"] == "wall_clock_budget_exhausted"
    assert state["research_progress"].model_calls == 2
    assert not state.get("workflow_errors")


def test_interrupted_question_keeps_progress_and_records_cleanup(tmp_path):
    runtime = SimpleNamespace(actions=2, requests=1, closed=False)
    model = SimpleNamespace(progress=ResearchProgress(model_calls=3))
    with pytest.raises(KeyboardInterrupt), failure_checkpoint(tmp_path, lambda: (runtime, model)), ExitStack() as stack:
        stack.callback(setattr, runtime, "closed", True)
        raise KeyboardInterrupt
    summary = json.loads((tmp_path / "summary.json").read_text())
    assert summary["cleanup_verified"] and not summary["completed"]
    assert summary["stop_reason"] == "operator_cancelled"
    assert summary["model_calls"] == 3
    assert json.loads((tmp_path / "progress.json").read_text())["model_calls"] == 3


def test_cancelled_campaign_writes_partial_summary_and_propagates(tmp_path, monkeypatch):
    from app import research_campaign as module

    root = tmp_path / "target"
    root.mkdir()
    (root / "app.ts").write_text("const value = 1;\n")
    def interrupted(**kwargs):
        path = kwargs["output"]
        path.mkdir(parents=True)
        (path / "summary.json").write_text(json.dumps({"completed": False, "cleanup_verified": True,
            "model_calls": 1, "actions": 0, "status": "inconclusive"}))
        (path / "progress.json").write_text(json.dumps({"model_calls": 1, "ledger": []}))
        raise RunCancelled("test")

    monkeypatch.setattr(module, "run_research", interrupted)
    with pytest.raises(RunCancelled):
        module.campaign(profile=TargetProfile(id="test", environment="sandbox", repository_path=root),
            configuration={"worker_image": "unused"}, client=None, output=tmp_path / "out")
    summary = json.loads((tmp_path / "out/summary.json").read_text())
    assert summary["completed"] is False and summary["model_calls"] == 1
    assert summary["cleanup_verified"] is True
    assert summary["canonical_runtime_review_counts"] == {}


def test_cancelled_runner_records_source_and_seals_failure(tmp_path, monkeypatch):
    from app import research_diagnostic_run as module

    def interrupted(_checkout, _image, _browser, output, **_kwargs):
        output.mkdir()
        (output / "run-state.json").write_text(json.dumps({"phase": "campaign", "target": {"commit": "fixed"},
                                                         "cleanup_verified": True}))
        raise KeyboardInterrupt

    monkeypatch.setattr(module, "_run", interrupted)
    monkeypatch.setattr(module, "validate_target_snapshot", lambda *_: {"commit": "fixed"})
    output = tmp_path / "result"
    with pytest.raises(KeyboardInterrupt):
        module.run(tmp_path, "image", "browser", output)
    result = json.loads((output / "run-result.json").read_text())
    assert result["source_unchanged"] and result["target_cleanup_verified"] and not result["completed"]
    seal = json.loads((output / "seal.json").read_text())
    assert "run-result.json" in seal and "seal.json" not in seal


def test_identical_sql_observations_group_without_verdict_transfer(tmp_path):
    (tmp_path / "app.ts").write_text("db.query(input);\nother(input);\n")
    queue = ResearchQueue(profile=TargetProfile(id="test", environment="sandbox", repository_path=tmp_path),
        source_map=ExpressSourceMap(), source_files=["app.ts"])
    rules = ["javascript.express.security.injection.tainted-sql-string.tainted-sql-string",
             "javascript.sequelize.security.audit.sequelize-raw-query.sequelize-raw-query", "sql-injection"]
    items = [Finding(id=str(i), source="semgrep", rule_id=rule, title="Candidate", description="Pending",
        file="app.ts", line_start=1, line_end=1) for i, rule in enumerate(rules)]
    queue.import_findings(items, "sast")
    before = len(queue.findings)
    first = queue.next_question()
    queue.complete(first)
    assert len(queue.findings) == before
    assert queue.next_question() is None
    assert any(q.status == "grouped" for q in queue.questions)
    assert queue.coverage([])["grouped_observations_have_no_inherited_verdict"]
    queue.import_findings([items[0].model_copy(update={"id": "different-sink", "line_start": 2, "line_end": 2})], "sast")
    assert queue.next_question().finding.line_start == 2


def test_failed_representative_does_not_hide_other_observation(tmp_path):
    (tmp_path / "app.ts").write_text("db.query(input);\n")
    queue = ResearchQueue(profile=TargetProfile(id="test", environment="sandbox", repository_path=tmp_path),
        source_map=ExpressSourceMap(), source_files=["app.ts"])
    queue.import_findings([Finding(id=str(i), source="semgrep", rule_id=rule, title="Candidate", description="Pending",
        file="app.ts", line_start=1) for i, rule in enumerate([
            "javascript.express.security.injection.tainted-sql-string.tainted-sql-string", "sql-injection"])], "sast")
    first = queue.next_question()
    queue.complete(first, failed=True)
    assert queue.next_question() is not None
    assert not queue.grouped_questions
