"""R05–R06 positive, negative and unavailable proofs; no live LLM required."""
import json
from hashlib import sha256

import pytest

from agent.research import ResearchAgentModel
from evidence.research_http_replay import marker_trial
from evidence.research_review import review_source_claims
from evidence.research_source_reviewer import review
from pipeline.research_queue import ResearchQueue
from schemas.finding import Finding
from schemas.research import ResearchFile, ResearchScope
from schemas.research_agent import (
    ResearchObservation,
    ResearchProgress,
    SourceProofClaim,
)
from schemas.research_campaign import RuntimeScannerObservation
from schemas.research_review import HttpMarkerSpec
from schemas.source_map import ExpressRouteRegistration, ExpressSourceMap
from schemas.target import TargetProfile


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
    surface = ExpressSourceMap(routes=[ExpressRouteRegistration(id="route", file="app.ts", receiver="app",
        method="get", path="/unread", path_is_static=True, line_start=1, line_end=1,
        registration_order=0, handler_files=["unread.ts"])])
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
    selected = queue.next_question()
    queue.complete(selected)
    assert queue.next_question().id != selected.id
    assert queue.coverage([])["unread_files"] == ["app.ts", "unread.ts"]


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
