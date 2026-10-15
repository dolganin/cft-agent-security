"""R05–R06 positive, negative and unavailable proofs; no live LLM required."""
import json
from hashlib import sha256
from types import SimpleNamespace

import pytest

from agent.research import ResearchAgentModel
from evidence.research_http_replay import marker_trial
from evidence.research_review import review_source_claims
from evidence.research_source_reviewer import review
from pipeline.research_queue import ResearchQueue
from schemas.finding import Finding
from schemas.research import ResearchFile, ResearchScope
from schemas.research_agent import (
    ResearchChoice,
    ResearchObservation,
    ResearchProgress,
    SourceProofClaim,
)
from schemas.research_campaign import RuntimeScannerObservation
from schemas.research_review import HttpMarkerSpec
from schemas.source_map import ExpressRouteRegistration, ExpressSourceMap
from schemas.target import TargetProfile
from security.research_scope import expand_search_paths


@pytest.mark.parametrize("source,file,status", [
    ("import hashlib\nhashlib.md5(b'owned')\n", "app.py", "confirmed"),
    ("import hashlib\nhashlib.sha256(b'owned')\n", "app.py", "rejected"),
    ("import hashlib as h\nh.md5(b'owned')\n", "app.py", "confirmed"),
    ("from hashlib import md5 as digest\ndigest(b'owned')\n", "app.py", "confirmed"),
    ("import hashlib\ndef f(hashlib):\n return hashlib.md5(b'owned')\n", "app.py", "review_pending"),
    ("text = 'hashlib.md5(data)'\n", "app.py", "review_pending"),
    ("import hashlib\nhashlib.md5 = lambda x: x\nhashlib.md5(b'owned')\n", "app.py", "review_pending"),
    ("import crypto from 'node:crypto';\ncrypto.createHash('md5');\n", "app.ts", "confirmed"),
    ("import crypto from 'node:crypto';\ncrypto.createHash('sha256');\n", "app.ts", "rejected"),
    ("import {createHash as hash} from 'crypto';\nhash('sha1');\n", "app.ts", "confirmed"),
    ("import * as crypto from 'crypto';\ncrypto.createHash('md5');\n", "app.ts", "confirmed"),
    ("import crypto from 'crypto';\nfunction f(crypto) {return crypto.createHash('md5')}\n", "app.ts", "review_pending"),
    ("import crypto from 'crypto';\ncrypto.createHash(algorithm);\n", "app.ts", "review_pending"),
    ("const crypto = {createHash: () => 'safe'};\ncrypto.createHash('md5');\n", "app.ts", "review_pending"),
    ("// crypto.createHash('md5')\n", "app.ts", "review_pending"),
    ("import type crypto from 'crypto';\ncrypto.createHash('md5');\n", "app.ts", "review_pending"),
    ("import crypto from 'crypto';\ncrypto.createHash = () => 'safe';\ncrypto.createHash('md5');\n", "app.ts", "review_pending"),
    ("import crypto from 'crypto';\ncrypto.createHash('md5'); crypto.createHash('sha256');\n", "app.ts", "review_pending"),
])
def test_independent_source_conditions(source, file, status):
    result = review(source.encode(), file, 1, len(source.splitlines()))
    assert result["status"] == status
    assert result["scope"] == "source_condition"
    assert result["runtime_exploit_verified"] is False


def marker_spec():
    return HttpMarkerSpec(id="owned-proof", service="app", owner_path="/owner", probe_path="/probe",
                          negative_path="/negative", owner_role="owner", marker="owned-marker-123456789")


def http_observation(status, body="", role=None, truncated=False):
    return {"status_code": status, "body": body, "role_handle": role,
            "redirect_followed": False, "body_truncated": truncated}


@pytest.mark.parametrize("scenario,expected", [("disclosed", "confirmed"), ("denied", "rejected"),
    ("owner-lost", "review_pending"), ("negative-broken", "review_pending"),
    ("not-found", "review_pending"), ("empty-200", "review_pending"), ("truncated-denial", "review_pending")])
def test_marker_protocol_does_not_require_one_failure_template(scenario, expected):
    spec = marker_spec()
    marker = spec.marker.get_secret_value()
    observations = [http_observation(200, marker, "owner"), http_observation(403),
                    http_observation(200, marker), http_observation(200, marker, "owner")]
    if scenario == "denied":
        observations[2] = http_observation(403)
    elif scenario == "owner-lost":
        observations[0] = http_observation(401)
    elif scenario == "negative-broken":
        observations[1] = http_observation(200, marker)
    elif scenario == "not-found":
        observations[2] = http_observation(404)
    elif scenario == "empty-200":
        observations[2] = http_observation(200)
    elif scenario == "truncated-denial":
        observations[2] = http_observation(403, truncated=True)
    assert marker_trial(observations, spec) == expected
    assert marker not in json.dumps(spec.public())


def fixture_source(tmp_path):
    path = tmp_path / "app.ts"
    raw = b"import crypto from 'crypto';\ncrypto.createHash('md5');\n"
    path.write_bytes(raw)
    scope = ResearchScope(target_id="test", session_id="research-" + "a" * 32,
        worker_image="sha256:" + "b" * 64, worker_sha256="c" * 64,
        source_files={"app.ts": ResearchFile(original_sha256=sha256(raw).hexdigest(), visible_sha256=sha256(raw).hexdigest())})
    observation = ResearchObservation(action_id="read-1", tool="read_source", fingerprint="first", workspace_revision=0,
        evidence_ids=["e1"], artifact_refs=[], execution_status="completed", exit_code=0, bytes_observed=100,
        category="observation", observation={"path": "app.ts", "content": "1: import crypto from 'crypto';\n2: crypto.createHash('md5');"})
    return path, scope, observation


def test_candidates_must_bind_real_read_lines(tmp_path):
    _, scope, observation = fixture_source(tmp_path)
    model = ResearchAgentModel(client=None, scope=scope, validator=None)
    model.progress.ledger.append(observation)
    assert model.read_anchor("app.ts", 2, 2, ["read-1"], "crypto.createHash('md5')")
    assert not model.read_anchor("app.ts", 3, 3, ["read-1"], "invented")
    assert not model.read_anchor("app.ts", 2, 2, ["script-stdout"], "crypto")
    assert not model.read_anchor("outside.ts", 2, 2, ["read-1"])


def test_source_detector_channel_keeps_origin_and_requires_source_inventory(tmp_path):
    (tmp_path / "app.ts").write_text("store.update(req.body)\n")
    queue = ResearchQueue(profile=TargetProfile(id="detector-test", environment="sandbox",
        repository_path=tmp_path), source_map=ExpressSourceMap(), source_files=["app.ts"])
    candidate = Finding(id="detected", source="juice_source_detector", rule_id="access-control",
        title="Unverified body update", description="Requires independent ownership verification",
        file="app.ts", line_start=1, line_end=1)
    queue.import_findings([candidate, candidate.model_copy(update={"id": "outside", "file": "other.ts"})],
                          "source_detector")
    selected = queue.next_question()
    assert selected.id == "detected" and selected.origin == "source_detector"
    assert selected.finding.source == "juice_source_detector"
    assert selected.finding.provenance.anchor_status == "source_bound"
    assert queue.raw[0]["origin"] == "source_detector"
    assert queue.rejections[0]["id"] == "outside"
    assert len(queue.findings) == 1


def test_explicit_fixed_only_campaign_writes_empty_research_streams_without_model_calls(tmp_path):
    from app.research_campaign import campaign

    target = tmp_path / "target"
    target.mkdir()
    (target / "app.ts").write_text("const value = 1\n")

    class ForbiddenClient:
        def complete_model(self, **_kwargs):
            raise AssertionError("Fixed-only acceptance must not call a provider")

    output = tmp_path / "out"
    result = campaign(profile=TargetProfile(id="fixed-only", environment="sandbox",
        repository_path=target), configuration={"worker_image": "unused"},
        client=ForbiddenClient(), output=output, verification_only=True)
    assert result["model_calls"] == 0 and result["stop_reason"] == "fixed_verification_only"
    assert result["completed"] and not result["degraded"]
    assert json.loads((output / "reports.json").read_text()) == []
    assert json.loads((output / "reviews.json").read_text()) == []
    assert json.loads((output / "manifest.json").read_text())["engine"] == "fixed_verification_only"


def test_source_review_is_independent_and_changed_source_not_confirmed(tmp_path):
    path, scope, observation = fixture_source(tmp_path)
    progress = ResearchProgress(ledger=[observation], source_claims=[SourceProofClaim(protocol="weak_digest_call.v1",
        file="app.ts", line_start=2, line_end=2, observation_refs=["read-1"])])
    results = review_source_claims(root=tmp_path, scope=scope, progress=progress, output=tmp_path / "review")
    assert results[0]["status"] == "confirmed"
    path.write_text("// replaced by safe source\n")
    results = review_source_claims(root=tmp_path, scope=scope, progress=progress, output=tmp_path / "review-mutated")
    assert results[0]["status"] == "review_pending"


def test_queue_preserves_duplicates_and_exploration_is_not_finding(tmp_path):
    (tmp_path / "app.ts").write_text("const x = 'source';\n")
    (tmp_path / "unread.ts").write_text("const y = 'source';\n")
    profile = TargetProfile(id="queue-test", environment="sandbox", repository_path=tmp_path)
    surface = ExpressSourceMap(routes=[
        ExpressRouteRegistration(id="route", file="app.ts", receiver="app",
            method="get", path="/unread", path_is_static=True, line_start=1, line_end=1,
            registration_order=0, handler_files=["unread.ts"]),
        ExpressRouteRegistration(id="direct-route", file="app.ts", receiver="app",
            method="get", path="/other", path_is_static=True, line_start=1, line_end=1,
            registration_order=1),
    ])
    queue = ResearchQueue(profile=profile, source_map=surface, source_files=["app.ts", "unread.ts"])
    def finding(id, source):
        return Finding(id=id, source=source, rule_id="weak-hash", title="Digest candidate", description="Unverified",
                       file="app.ts", line_start=1, line_end=1)
    queue.import_findings([finding("sast-1", "semgrep")], "sast")
    queue.import_findings([finding("dast-1", "any-scanner")], "dast")
    assert len(queue.findings) == 1
    assert len(queue.raw) == 2
    assert set(queue.findings[0].provenance.aliases) == {"sast-1", "dast-1"}
    assert any(q.origin == "surface" and not q.is_candidate for q in queue.questions)
    assert any(q.origin == "surface" and q.finding.file == "app.ts" for q in queue.questions)
    selected = queue.next_question()
    queue.complete(selected)
    assert queue.next_question().id != selected.id
    assert queue.coverage([])["unread_files"] == ["app.ts", "unread.ts"]


def test_queue_schedules_other_routes_before_deeper_same_route_work(tmp_path):
    for name in ("server.ts", "route-a.ts", "route-b.ts"):
        (tmp_path / name).write_text("const value = 'source';\nconst other = 'sink';\n")
    profile = TargetProfile(id="breadth-test", environment="sandbox", repository_path=tmp_path)
    source_map = ExpressSourceMap(routes=[
        ExpressRouteRegistration(id="route-a", file="server.ts", receiver="app", method="get",
            path="/a", path_is_static=True, line_start=1, line_end=1, registration_order=0,
            handler_files=["route-a.ts"]),
        ExpressRouteRegistration(id="route-b", file="server.ts", receiver="app", method="get",
            path="/b", path_is_static=True, line_start=1, line_end=1, registration_order=1,
            handler_files=["route-b.ts"]),
    ])
    queue = ResearchQueue(profile=profile, source_map=source_map,
                          source_files=["server.ts", "route-a.ts", "route-b.ts"])
    candidates = [
        Finding(id="route-a-first", source="semgrep", rule_id="sql-injection", title="first",
                description="candidate", file="route-a.ts", line_start=1, line_end=1),
        Finding(id="route-a-second", source="semgrep", rule_id="sql-injection", title="second",
                description="distinct sink", file="route-a.ts", line_start=2, line_end=2),
        Finding(id="route-b-first", source="semgrep", rule_id="sql-injection", title="third",
                description="other route", file="route-b.ts", line_start=1, line_end=1),
    ]
    queue.import_findings(candidates, "sast")

    first = queue.next_question()
    second = queue.next_question()
    third = queue.next_question()

    assert first.finding.file == "route-a.ts"
    assert second.finding.file == "route-b.ts"
    assert third.finding.file == "route-a.ts"
    coverage = queue.coverage([])
    assert coverage["unique_candidate_verification_jobs"] == 3
    assert coverage["unique_candidate_jobs_by_status"] == {"pending": 3}
    assert coverage["scheduler_route_visits"] == {"route-a": 2, "route-b": 1}


def test_queue_coalesces_operator_bound_observations_by_property_and_snapshot(tmp_path, monkeypatch):
    from security import verification_binding as binding_module

    (tmp_path / "app.ts").write_text("const a = source;\nconst b = sink;\n")
    route = {
        "id": "search", "handler_id": "app.search", "family": "sql-injection",
        "service": "app", "endpoint": "/search", "method": "GET",
        "tool": "verify_sql_injection", "check": "sql_interpolation", "mode": "search",
        "registration": {"file": "server.ts", "anchor": "app.get('/search', search())"},
        "sources": [{"file": "app.ts", "anchor": "function search()"}],
    }
    profile = TargetProfile(id="job-key-test", environment="sandbox", repository_path=tmp_path,
        services={"app": {"type": "node", "runtime_endpoints": ["/search"]}},
        verification_routes=[route])
    primary = SimpleNamespace(target="job-key-test", source_snapshot="a" * 64, map_sha256="b" * 64,
        route_id="search", handler_id="app.search", family="sql-injection", service="app",
        method="GET", endpoint="/search", tool="verify_sql_injection",
        check="sql_interpolation", mode="search", source_file="app.ts", line_start=1, line_end=1,
        anchor_sha256="c" * 64)
    other = primary.model_copy(update={"source_snapshot": "c" * 64}) if hasattr(primary, "model_copy") else SimpleNamespace(
        **{**vars(primary), "source_snapshot": "c" * 64})

    def resolve(_profile, item):
        if item.rule_id == "other-snapshot":
            binding = other
        else:
            binding = SimpleNamespace(**{**vars(primary), "line_start": item.line_start,
                "line_end": item.line_end, "anchor_sha256": sha256(str(item.line_start).encode()).hexdigest()})
        return SimpleNamespace(status="bound", binding=binding)

    monkeypatch.setattr(binding_module, "resolve_binding", resolve)
    source_map = ExpressSourceMap()
    campaign_profile = TargetProfile(id="campaign-target", environment="sandbox", repository_path=tmp_path,
        services={"app": {"type": "node", "runtime_endpoints": ["/search"]}})
    queue = ResearchQueue(profile=campaign_profile, source_map=source_map, source_files=["app.ts"],
                          verification_profiles=(profile,))
    observations = [
        Finding(id="scanner-one", source="semgrep", rule_id="sql-injection", title="one",
                description="candidate", file="app.ts", line_start=1, line_end=1),
        Finding(id="scanner-two", source="model_scout", rule_id="sql-injection", title="two",
                description="same operator property", file="app.ts", line_start=1, line_end=1),
        Finding(id="scanner-three", source="semgrep", rule_id="sql-injection", title="three",
                description="different sink on same route", file="app.ts", line_start=2, line_end=2),
    ]
    queue.import_findings(observations, "sast")

    assert len(queue.raw) == 3
    assert len(queue.questions) == 2
    assert queue.work_key(queue.questions[0].finding) != queue.work_key(queue.questions[1].finding)
    assert set(queue.questions[0].finding.provenance.aliases) >= {"scanner-one", "scanner-two"}
    queue.complete(queue.questions[0])
    assert queue.questions[1].status == "pending"
    assert queue.work_key(queue.questions[0].finding) != queue.work_key(
        queue.questions[0].finding.model_copy(update={"rule_id": "other-snapshot"}))


def test_dast_without_source_location_remains_a_candidate(tmp_path):
    (tmp_path / "app.ts").write_text("const app = 'source';\n")
    profile = TargetProfile(id="queue-runtime", environment="sandbox", repository_path=tmp_path,
                            services={"app": {"internal_port": 8080}})
    queue = ResearchQueue(profile=profile, source_map=ExpressSourceMap(), source_files=["app.ts"])
    signal = RuntimeScannerObservation(id="runtime-1", source="zap", rule_id="access-control",
        title="Possible authorization gap", description="Unverified scanner observation",
        service="app", endpoint="/owned", artifact_ref="dast/raw.json")
    queue.import_findings([signal], "dast")
    assert len(queue.findings) == 1
    assert queue.questions[0].origin == "dast"
    assert queue.questions[0].runtime_observation.endpoint == "/owned"
    assert queue.findings[0].service == "app"
    assert queue.findings[0].provenance.anchor_status == "location_only"
    queue.import_candidates([])
    assert queue.findings[0].service == "app"


def test_source_choice_network_fields_are_corrected_before_action_generation():
    with pytest.raises(ValueError, match="service=null"):
        ResearchChoice(tool="read_source", parameters={"path": "app.ts"}, service="app",
                       purpose="Read source", expected_evidence="Numbered source")
    with pytest.raises(ValueError):
        ResearchChoice(tool="sandbox_command", parameters={"argv": ["sh", "-c", "echo invalid"]},
                       purpose="Invalid script runner", expected_evidence="No execution")
    assert ResearchChoice(tool="read_source", parameters={"path": "app.ts"},
                          purpose="Read source", expected_evidence="Numbered source").service is None


def test_directory_search_never_expands_beyond_projected_files(tmp_path):
    _, scope, _ = fixture_source(tmp_path)
    files = {"routes/a.ts": next(iter(scope.source_files.values())), "models/b.ts": next(iter(scope.source_files.values()))}
    scope = scope.model_copy(update={"source_files": files})
    assert expand_search_paths(scope, ["routes/", "models/"]) == ["models/b.ts", "routes/a.ts"]
    with pytest.raises(ValueError):
        expand_search_paths(scope, ["outside/"])
    with pytest.raises(ValueError):
        ResearchChoice(tool="search_source", parameters={"literal": "x", "paths": ["../"]},
                       purpose="Invalid directory", expected_evidence="No execution")
