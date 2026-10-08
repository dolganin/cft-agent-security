import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from types import SimpleNamespace

from agent.llm import LLMRoute, LLMUnavailableError, ProviderFailoverClient
from agent.verification import register_source_artifacts, verification_candidates
from evidence.interpreter import _bounded_result_matches_action
from executor import worker
from schemas.action import ActionProposal
from schemas.finding import Finding
from schemas.runtime import RuntimeService, RuntimeServiceMap
from schemas.security_tools import BoundedVerificationResult
from schemas.target import TargetArtifact, TargetProfile, TargetService
from validator.validator import PolicyValidator


def test_scout_sql_family_uses_only_the_exact_operator_binding():
    finding = Finding(id="scout-1", source="model_scout", rule_id="sql-injection",
                      title="Unverified query", description="Needs Evidence",
                      file="routes/search.ts", line_start=23)
    profile = TargetProfile(
        id="demo", environment="sandbox",
        services={"juice": TargetService(id="juice", root=".")},
        artifacts={"source-search": TargetArtifact(
            id="source-search", kind="javascript", path="routes/search.ts",
        )},
        metadata={"verification.routes/search.ts:23.endpoint": "/search",
                  "verification.routes/search.ts:23.mode": "search",
                  "verification.routes/search.ts:23.check": "sql_interpolation"},
    )
    runtime = RuntimeServiceMap(session_id="session", services={
        "juice": RuntimeService(name="juice", address="http://juice:3000", ready=True,
                                readiness_source="http_probe", allowed_endpoints=["/search"]),
    })
    state = {"finding": finding, "target_profile": profile, "runtime_services": runtime}
    assert verification_candidates(state)[0]["tool"] == "verify_sql_injection"
    state["finding"] = finding.model_copy(update={"line_start": 24})
    assert [item["tool"] for item in verification_candidates(state)] == [
        "inspect_javascript_security",
    ]


def _payload(root, source, *, line=1, check="sql_interpolation"):
    path = root / "routes" / "search.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return {
        "tool": "inspect_javascript_security",
        "repository_path": str(root),
        "artifacts": {"source-search": {"kind": "javascript", "path": "routes/search.ts"}},
        "parameters": {"artifact_id": "source-search", "line": line, "check": check},
    }


def test_source_sql_check_confirms_only_direct_request_interpolation(tmp_path):
    line = "models.sequelize.query(`SELECT * FROM Products WHERE name LIKE '%${req.query.q}%'`)"
    code, stdout, _ = worker._execute(_payload(tmp_path, line))
    result = BoundedVerificationResult.model_validate_json(stdout)

    assert code == 0
    assert result.scope == "source_sql_interpolation"
    assert result.verdict == "confirmed"
    assert result.facts["runtime_exploitability_verified"] is False
    assert "req.query.q" not in stdout


def test_source_artifact_registration_is_bounded_and_does_not_mutate_profile(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes" / "search.ts").write_text("export const search = true", encoding="utf-8")
    profile = TargetProfile(id="fixture", repository_path=tmp_path)
    finding = SimpleNamespace(file="routes/search.ts")
    updated = register_source_artifacts(profile, [finding], tmp_path)

    assert profile.artifacts == {}
    assert len(updated.artifacts) == 1
    artifact = next(iter(updated.artifacts.values()))
    assert artifact.kind == "javascript" and artifact.relative_path == "routes/search.ts"


def test_source_sql_check_does_not_confirm_bound_or_sanitized_input(tmp_path):
    cases = [
        "models.sequelize.query(`SELECT * FROM T WHERE name='${escape(req.query.q)}'`) ",
        "models.sequelize.query(`SELECT * FROM T WHERE name='${req.query.q}'`, { replacements: { q: req.query.q } })",
        "models.sequelize.query(`SELECT * FROM T WHERE name='${product.name}'`) ",
    ]
    for index, line in enumerate(cases):
        payload = _payload(tmp_path / str(index), line)
        code, stdout, _ = worker._execute(payload)
        assert code == 0
        assert BoundedVerificationResult.model_validate_json(stdout).verdict == "inconclusive"


def test_source_verification_rejects_unregistered_path_and_line(tmp_path):
    payload = _payload(tmp_path, "models.sequelize.query(`SELECT '${req.query.q}'`)")
    payload["artifacts"]["source-search"]["path"] = "../outside.ts"
    assert worker._execute(payload)[0] != 0

    payload = _payload(tmp_path, "models.sequelize.query(`SELECT '${req.query.q}'`)", line=4)
    assert worker._execute(payload)[0] != 0


def test_sql_differential_requires_repeatable_controlled_difference():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            has_control = "cft-no-match-" in self.path
            body = json.dumps({"data": [] if has_control else [{"id": 1}]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        url = f"http://127.0.0.1:{server.server_port}/search"
        code, stdout, _ = worker._verify_sql_injection(
            url,
            {"mode": "search", "artifact_id": "source-search", "line": 1,
             "check": "sql_interpolation"},
            2.0,
            None,
        )
        result = BoundedVerificationResult.model_validate_json(stdout)
        assert code == 0
        assert result.verdict == "confirmed"
        assert len(result.facts["observations"]) == 4

        action = ActionProposal(
            id="check-search", tool="verify_sql_injection", target="juice-test",
            environment="sandbox", iteration=1,
            parameters={"mode": "search", "artifact_id": "source-search", "line": 1,
                        "check": "sql_interpolation"},
            purpose="Test a trusted endpoint", expected_evidence="Repeated structured difference",
            service="api", endpoint="/search",
        )
        assert _bounded_result_matches_action(result, action)
        wrong_endpoint = action.model_copy(update={"endpoint": "/other"})
        assert not _bounded_result_matches_action(result, wrong_endpoint)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_directory_check_returns_only_names_and_never_follows_redirect():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/logs":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/external")
                self.end_headers()
                return
            body = b'<html><title>Index of /logs</title><a href="access.log">access.log</a></html>'
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        params = {"artifact_id": "server-ts", "line": 2, "check": "source_metadata"}
        code, stdout, _ = worker._verify_sensitive_directory(base + "/logs/", params, 1.0, None)
        result = BoundedVerificationResult.model_validate_json(stdout)
        assert code == 0 and result.verdict == "confirmed"
        assert result.facts["sensitive_file_names"] == ["access.log"]
        assert "file_contents_read\":false" in stdout

        code, stdout, _ = worker._verify_sensitive_directory(base + "/logs", params, 1.0, None)
        assert code == 0
        assert BoundedVerificationResult.model_validate_json(stdout).verdict == "inconclusive"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_validator_binds_runtime_capability_to_profile_and_source_line():
    profile = TargetProfile(
        id="juice-test", environment="sandbox",
        services={"api": TargetService(id="api", root=".", runtime_endpoints=["/search"])},
        artifacts={"source-search": TargetArtifact(id="source-search", kind="javascript", path="routes/search.ts")},
        metadata={"verification.routes/search.ts:1.endpoint": "/search",
                  "verification.routes/search.ts:1.mode": "search",
                  "verification.routes/search.ts:1.check": "sql_interpolation"},
    )
    validator = PolicyValidator.from_yaml("policies/default.yaml", target_profile=profile)
    action = ActionProposal(
        id="sql-check", tool="verify_sql_injection", target=profile.id,
        environment="sandbox", iteration=1,
        parameters={"mode": "search", "artifact_id": "source-search", "line": 1,
                    "check": "sql_interpolation"},
        purpose="Bounded check", expected_evidence="Four requests with repeated controls",
        service="api", endpoint="/search",
    )
    assert validator.validate(action).approved
    action.endpoint = "/admin"
    assert not validator.validate(action).approved


def test_live_model_diagnostics_store_no_response_or_credential(tmp_path):
    route = LLMRoute(provider="nsu", model="fixture-model", key_env="TEST_API_KEY", protocol="openai")
    diagnostics = tmp_path / "llm-attempts.jsonl"
    client = ProviderFailoverClient(
        routes=(route,), credentials={"TEST_API_KEY": "private-test-token"},
        diagnostics_path=diagnostics,
    )
    client._request_route = lambda *args: '{"not":"the requested schema private-test-token"}'
    from schemas.llm import LLMProbeResult

    try:
        client.complete_model(output_model=LLMProbeResult, system_prompt="", user_payload={}, operation="fixture")
    except LLMUnavailableError:
        pass
    else:
        raise AssertionError("invalid model response unexpectedly passed schema validation")
    text = diagnostics.read_text(encoding="utf-8")
    assert "schema_validation_failed" in text
    assert "private-test-token" not in text
    assert "the requested schema" not in text
