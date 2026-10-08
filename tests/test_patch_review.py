import difflib
import hashlib
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.demo import PATCH_FINDING, create_demo_app
from fix_verification.review import (
    prepare_patch_review,
    validate_review_diff,
    validate_sequelize_search_proposal,
)
from schemas.evidence import Evidence
from schemas.fix import ProposedPatch
from schemas.report import FinalReport, ReportFinding, VerificationSummary

SOURCE = "first\nunsafe() // vuln-code-snippet vuln-line trainingLabel\nlast\n"
DIFF = "--- a/app.ts\n+++ b/app.ts\n@@ -1,3 +1,3 @@\n first\n-unsafe() \n+safe()\n last\n"


def proposal(diff=DIFF, finding_id="finding-1"):
    return ProposedPatch(finding_id=finding_id, rationale="Защищенный вызов", unified_diff=diff)


def report(file="app.ts", finding_id="finding-1", source=SOURCE, status="confirmed"):
    return FinalReport(
        finding_id=finding_id, finding=ReportFinding(
            id=finding_id, source="semgrep", rule_id="sql", title="SQL", file=file,
            line_start=2,
        ), status=status, verification=VerificationSummary(),
        code_context="\n".join(f"{i}: {line}" for i, line in enumerate(source.splitlines(), 1)),
        evidence=[Evidence(
            id="e1", action_id="a1", type="check", summary="Observed", verdict="confirmed",
            source="runtime", sandbox_session_id="s1", hypothesis_id="h1", action={"id": "a1", "tool": "check"},
            observation={"kind": "check", "facts": {}},
            scope={"target": "demo", "environment": "sandbox", "description": "test"},
        )],
        explanation="Evidence-backed", next_step="Review",
    )


class Client:
    def __init__(self, result=None):
        self.calls = 0
        self.result = result or proposal()
        self.last_selected_route = SimpleNamespace(label="test/model")

    def complete_model(self, **kwargs):
        self.calls += 1
        assert kwargs["operation"] == "propose_patch"
        assert "trainingLabel" not in kwargs["user_payload"]["code_context"]
        assert not kwargs["user_payload"]["runtime_evidence"][0]["artifact_refs"]
        return self.result


def test_patch_review_is_read_only_and_rebuilds_exact_source_diff(tmp_path):
    target = tmp_path / "app.ts"
    target.write_text(SOURCE)
    artifact = prepare_patch_review(
        client=Client(), report=report(), repository=tmp_path, run_id="run-1",
        editable_start=2, editable_end=2,
    )
    assert artifact.status == "ready_for_review"
    assert artifact.applied is False and artifact.security_verified is False
    assert target.read_text() == SOURCE
    assert artifact.source_sha256 == hashlib.sha256(SOURCE.encode()).hexdigest()
    assert "-unsafe() // vuln-code-snippet" in artifact.proposal.unified_diff
    assert artifact.model == "test/model"


@pytest.mark.parametrize("diff", [
    DIFF.replace("a/app.ts", "a/../app.ts"),
    DIFF.replace("b/app.ts", "b/other.ts"),
    "old mode 100644\nnew mode 100755\n" + DIFF,
    DIFF.replace("-1,3", "-1,4"),
    DIFF.replace("+1,3", "+2,3"),
    DIFF.replace(" first", " stale"),
    DIFF + "--- a/other.ts\n+++ b/other.ts\n",
    DIFF.replace("+safe()", "+<redacted>"),
    DIFF.replace("+safe()", "+sk-" + "x" * 32),
    DIFF.replace(" first", "-first"),
])
def test_patch_review_rejects_paths_metadata_counts_secrets_and_scope(diff):
    with pytest.raises(ValueError):
        validate_review_diff(proposal(diff), file="app.ts", source=SOURCE, editable_start=2, editable_end=2)


@pytest.mark.parametrize("status", ["inconclusive", "rejected", "policy_blocked"])
def test_patch_review_requires_confirmed_evidence(tmp_path, status):
    client = Client()
    with pytest.raises(ValueError, match="evidence-backed"):
        prepare_patch_review(client=client, report=report(status=status), repository=tmp_path,
                             run_id="run-1", editable_start=2, editable_end=2)
    assert client.calls == 0


def test_patch_review_refuses_changed_source_before_model_call(tmp_path):
    (tmp_path / "app.ts").write_text(SOURCE.replace("unsafe()", "changed()"))
    client = Client()
    with pytest.raises(ValueError, match="changed"):
        prepare_patch_review(client=client, report=report(), repository=tmp_path,
                             run_id="run-1", editable_start=2, editable_end=2)
    assert client.calls == 0


def test_patch_review_refuses_symlink_source(tmp_path):
    outside = tmp_path / "outside"
    outside.write_text(SOURCE)
    (tmp_path / "app.ts").symlink_to(outside)
    with pytest.raises(ValueError, match="Linked"):
        prepare_patch_review(client=Client(), report=report(), repository=tmp_path,
                             run_id="run-1", editable_start=2, editable_end=2)


def test_rejected_model_patch_is_not_exposed(tmp_path):
    (tmp_path / "app.ts").write_text(SOURCE)
    candidate = proposal(DIFF.replace("+safe()", "+sk-" + "x" * 32))
    artifact = prepare_patch_review(client=Client(candidate), report=report(), repository=tmp_path,
                                    run_id="run-1", editable_start=2, editable_end=2)
    assert artifact.status == "rejected"
    assert artifact.proposal.unified_diff == ""
    assert "sk-" not in artifact.model_dump_json()


def test_demo_patch_endpoint_resolves_scope_and_reuses_saved_artifact(tmp_path):
    unsafe_query = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)"
    safe_query = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name`, { replacements: { criteria: `%${criteria}%` } })"
    source = "prefix\n" * 19 + "criteria = req.query.q\nlimit(criteria)\nprepare(criteria)\n" + unsafe_query + "\nsuffix\n"
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/search.ts").write_text(source)
    modified = source.replace(unsafe_query, safe_query)
    diff = "".join(difflib.unified_diff(source.splitlines(True), modified.splitlines(True),
                                      fromfile="a/routes/search.ts", tofile="b/routes/search.ts"))
    client = Client(proposal(diff, PATCH_FINDING))
    directory = tmp_path / "artifacts"
    directory.mkdir()
    fixture = report(file="routes/search.ts", finding_id=PATCH_FINDING, source=source)
    service = SimpleNamespace(
        close=lambda: None,
        get_run=lambda _: SimpleNamespace(target_id="juice-presentation", status="completed"),
        get_report=lambda _, finding: fixture if finding == PATCH_FINDING else None,
        store=SimpleNamespace(artifact_dir=lambda _: directory),
        registry=SimpleNamespace(get=lambda _: SimpleNamespace(profile=SimpleNamespace(repository_path=tmp_path))),
    )
    with TestClient(create_demo_app(service, patch_client_factory=lambda _: client)) as api:
        assert api.get("/demo/runs/run-1/patch-proposal").json() is None
        result = api.post("/demo/runs/run-1/patch-proposal")
        assert result.status_code == 200, result.text
        assert result.json()["status"] == "ready_for_review"
        assert api.get("/demo/runs/run-1/patch-proposal").json() == result.json()
        assert api.post("/demo/runs/run-1/patch-proposal").json() == result.json()
        assert client.calls == 1
        service.get_run = lambda _: SimpleNamespace(target_id="other", status="completed")
        assert api.post("/demo/runs/run-1/patch-proposal").status_code == 409
    assert (tmp_path / "routes/search.ts").read_text() == source
    assert (directory / "proposal.patch").read_text() == result.json()["proposal"]["unified_diff"]


@pytest.mark.parametrize("option,placeholder", [("replacements", ":criteria"), ("bind", "$criteria")])
def test_sequelize_review_accepts_matching_api_forms(option, placeholder):
    query = f"SELECT * FROM Products WHERE ((name LIKE {placeholder} OR description LIKE {placeholder}) AND deletedAt IS NULL) ORDER BY name"
    diff = "-models.sequelize.query(`unsafe`)\n+models.sequelize.query(`" + query + "`, { " + option + ": { criteria: `%${criteria}%` } })\n"
    validate_sequelize_search_proposal(diff)


@pytest.mark.parametrize("option,placeholder", [("bind", ":criteria"), ("replacements", "$criteria")])
def test_sequelize_review_rejects_mixed_parameter_apis(option, placeholder):
    query = f"SELECT * FROM Products WHERE ((name LIKE {placeholder} OR description LIKE {placeholder}) AND deletedAt IS NULL) ORDER BY name"
    diff = "-models.sequelize.query(`unsafe`)\n+models.sequelize.query(`" + query + "`, { " + option + ": { criteria: `%${criteria}%` } })\n"
    with pytest.raises(ValueError, match="mismatch"):
        validate_sequelize_search_proposal(diff)


def test_sequelize_review_rejects_deleting_query_or_changing_filter():
    with pytest.raises(ValueError):
        validate_sequelize_search_proposal("-models.sequelize.query(`unsafe`)\n+return []\n")
