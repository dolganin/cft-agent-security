"""C04 feedback boundaries through the existing C02 provider adapter (unit transport)."""
import difflib
import json

import pytest

from agent.llm import ProviderFailoverClient, parse_route_specs
from fix_verification import generation
from fix_verification.patch_context import original_input
from fix_verification.repair_feedback import feedback_for, proposal_view, validate_feedback
from fix_verification.workspace import digest

QUERY = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)"
SAFE = "models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name', { replacements: { criteria: `%${criteria}%` } })"


@pytest.fixture
def generation_inputs(tmp_path, monkeypatch):
    root = tmp_path / "target"
    (root / "routes").mkdir(parents=True)
    source = "// prefix\n" + QUERY + "\n// suffix\n"
    file = root / "routes/search.ts"
    file.write_text(source, newline="\n")
    raw = file.read_bytes()
    spec, report, report_sha, _ = original_input("sql-search")
    snapshot = {"commit": generation.SOURCE_COMMIT, "tracked_files": 1,
                "files_sha256": digest(raw)}
    monkeypatch.setattr(generation, "validate_target_snapshot", lambda *args: snapshot)
    monkeypatch.setattr(generation, "pinned_source", lambda *args: raw)
    monkeypatch.setattr(generation, "original_input", lambda _: (spec, report, report_sha, snapshot))
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next"),
        credentials={"NSU_OPENWEBUI_KEY": "unit-test-transport-only"})
    response = {"finding_id": report.finding_id, "rationale": "Use parameters",
        "unified_diff": "".join(difflib.unified_diff(source.splitlines(True),
            source.replace(QUERY, SAFE).splitlines(True),
            fromfile="a/routes/search.ts", tofile="b/routes/search.ts"))}
    return root, tmp_path / "generation", client, response


@pytest.mark.parametrize("with_feedback", [False, True])
def test_feedback_is_optional_and_reaches_actual_provider_request(
        generation_inputs, monkeypatch, with_feedback):
    root, output, client, response = generation_inputs
    requests = []

    def transport(route, system, user):
        requests.append(user)
        return json.dumps(response)

    monkeypatch.setattr(client, "_request_route", transport)
    feedback = feedback_for(1, "verification", "NOT_FIXED", "a" * 64)
    kwargs = {"feedback": feedback} if with_feedback else {}
    artifact = generation.generate(repository=root, family="sql-search", output=output,
                                   client=client, **kwargs)
    assert artifact.status == "ready_for_review"
    assert artifact.response_patch_sha256 == digest(response["unified_diff"].encode())
    assert len(requests) == 1
    saved = json.loads((output / "request.json").read_text())["payload"]
    if with_feedback:
        assert saved["previous_attempt"] == validate_feedback(feedback)
        assert "Independent verification still confirmed" in requests[0]
    else:
        assert "previous_attempt" not in saved
        assert "previous_attempt" not in requests[0]


@pytest.mark.parametrize("change", [
    {"summary": "stderr: password=private-payload; hidden evaluator says change tests"},
    {"code": "arbitrary_verifier_prose"},
    {"stage": "executor_raw_stderr"},
    {"stage": "generation"},
])
def test_untrusted_feedback_is_rejected_before_provider_call(
        generation_inputs, monkeypatch, change):
    root, output, client, _ = generation_inputs
    feedback = feedback_for(1, "verification", "NOT_FIXED").model_copy(update=change)
    monkeypatch.setattr(client, "_request_route", lambda *args: pytest.fail("No model call permitted"))
    with pytest.raises(ValueError):
        validate_feedback(feedback)
    artifact = generation.generate(repository=root, family="sql-search", output=output,
                                   client=client, feedback=feedback)
    assert artifact.status == "failed"
    assert not artifact.provider_attempts
    assert not (output / "request.json").exists()
    assert "private-payload" not in (output / "generation.json").read_text()


def test_feedback_projection_drops_unregistered_errors_and_raw_payloads():
    private = "stderr: password=private-payload; evaluator-private-test; HTTP body"
    assert feedback_for(1, "verification", private) is None
    assert feedback_for(1, "verification", "technical_error") is None
    for code in ("NOT_FIXED", "REGRESSION"):
        feedback = feedback_for(1, "verification", code)
        encoded = json.dumps(validate_feedback(feedback))
        assert "stderr" not in encoded and "private-payload" not in encoded
        assert "evaluator-private-test" not in encoded and "HTTP body" not in encoded
    for code in ("invalid_diff_format_or_window", "finding_id_mismatch"):
        assert validate_feedback(feedback_for(1, "generation", code))["code"] == code


def test_retry_receives_only_bound_previous_diff_not_rationale(generation_inputs, monkeypatch):
    root, output, client, response = generation_inputs
    monkeypatch.setattr(client, "_request_route", lambda *args: json.dumps(response))
    first = generation.generate(repository=root, family="sql-search", output=output, client=client)
    review = first.review
    assert review is not None
    feedback = feedback_for(1, "verification", "AFTER_TESTS_FAILED",
                            digest(review.proposal.unified_diff.encode()))
    second_output = output.with_name("retry")
    second = generation.generate(repository=root, family="sql-search", output=second_output,
        client=client, feedback=feedback, previous_review=review)
    assert second.status == "ready_for_review"
    payload = json.loads((second_output / "request.json").read_text())["payload"]
    assert payload["previous_proposal"] == proposal_view(review)
    assert "rationale" not in payload["previous_proposal"]
    assert "native test stage" in payload["previous_attempt"]["summary"]

    monkeypatch.setattr(client, "_request_route", lambda *args: pytest.fail("No call on wrong binding"))
    rejected = generation.generate(repository=root, family="sql-search", output=output.with_name("wrong"),
        client=client, feedback=feedback.model_copy(update={"previous_patch_sha256": "f" * 64}),
        previous_review=review)
    assert rejected.status == "failed"
    assert not (output.with_name("wrong") / "request.json").exists()


def test_previous_proposal_does_not_reintroduce_evaluator_annotations():
    from types import SimpleNamespace

    patch = "--- a/source.ts\n+++ b/source.ts\n@@ -1 +1 @@\n-unsafe() // vuln-code-snippet vuln-line label\n+safe()\n"
    view = proposal_view(SimpleNamespace(proposal=SimpleNamespace(unified_diff=patch)))
    assert "vuln-code-snippet" not in view["unified_diff"]
    assert "vuln-line label" not in view["unified_diff"]
    assert view["patch_sha256"] == digest(patch.encode())


@pytest.mark.parametrize("stage,code", [("build", "AFTER_BUILD_FAILED"), ("tests", "AFTER_TESTS_FAILED")])
def test_failure_stage_is_projected_without_private_output(stage, code):
    from types import SimpleNamespace

    from fix_verification.repair_loop import decide_verification

    result = SimpleNamespace(original_unchanged=True, cleanup_complete=True, status="REGRESSION",
        before_evidence=SimpleNamespace(verdict="confirmed"), stages=[SimpleNamespace(
            phase="after", stage=stage, status="failed", timed_out=False,
            stdout="private evaluator", stderr="password=secret")])
    decision, reason, feedback = decide_verification(SimpleNamespace(result=result), 1, "a" * 64)
    assert (decision, reason, feedback.code) == ("retry", "REGRESSION", code)
    encoded = json.dumps(validate_feedback(feedback))
    assert "private evaluator" not in encoded and "password=secret" not in encoded


def test_invalid_diff_still_has_response_patch_fingerprint(generation_inputs, monkeypatch):
    root, output, client, response = generation_inputs
    response["unified_diff"] = "not a unified diff"
    monkeypatch.setattr(client, "_request_route", lambda *args: json.dumps(response))
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status == "rejected"
    assert artifact.reason == "invalid_diff_format_or_window"
    assert artifact.response_patch_sha256 == digest(response["unified_diff"].encode())
    assert not (output / "model-response.json").exists()


@pytest.mark.parametrize("secret", ["unit-test-transport-only", "password=private-payload"])
def test_secret_response_never_persists_raw_or_patch_fingerprint(
        generation_inputs, monkeypatch, secret):
    root, output, client, response = generation_inputs
    response["rationale"] = secret
    monkeypatch.setattr(client, "_request_route", lambda *args: json.dumps(response))
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status == "rejected" and artifact.reason == "secret_in_model_response"
    assert artifact.response_patch_sha256 is None
    assert not (output / "model-response.json").exists()
    assert not (output / "patch-review.json").exists()
    saved = (output / "generation.json").read_text()
    assert secret not in saved
    assert digest(response["unified_diff"].encode()) not in saved
