import difflib
import json
import subprocess

import pytest
from pydantic import ValidationError

from agent.llm import ProviderFailoverClient, parse_route_specs
from fix_verification import generation
from fix_verification.patch_context import original_input, source_view
from fix_verification.patch_guard import defensive_shape
from fix_verification.workspace import digest
from schemas.patch_generation import BoundedPatchResponse

QUERY = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)"
SAFE = "models.sequelize.query('SELECT * FROM Products WHERE ((name LIKE :criteria OR description LIKE :criteria) AND deletedAt IS NULL) ORDER BY name', { replacements: { criteria: `%${criteria}%` } })"


@pytest.fixture
def setup(tmp_path, monkeypatch):
    root = tmp_path / "target"
    (root / "routes").mkdir(parents=True)
    source = "// prefix\n" + QUERY + "\n// suffix\n"
    (root / "routes/search.ts").write_text(source, newline="\n")
    spec, report, report_sha, _ = original_input("sql-search")

    def snapshot(*args):
        return {"commit": generation.SOURCE_COMMIT, "tracked_files": 1,
                "files_sha256": digest((root / "routes/search.ts").read_bytes())}

    original = snapshot()
    pinned = (root / "routes/search.ts").read_bytes()
    monkeypatch.setattr(generation, "validate_target_snapshot", snapshot)
    monkeypatch.setattr(generation, "pinned_source", lambda *args: pinned)
    monkeypatch.setattr(generation, "original_input", lambda family: (spec, report, report_sha, original))
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next"),
        credentials={"NSU_OPENWEBUI_KEY": "unit-test-transport-only"})
    response = {"finding_id": report.finding_id, "rationale": "Use parameters",
        "unified_diff": "".join(difflib.unified_diff(source.splitlines(True),
            source.replace(QUERY, SAFE).splitlines(True),
            fromfile="a/routes/search.ts", tofile="b/routes/search.ts"))}
    return root, tmp_path / "output", client, response


def test_real_adapter_roundtrip_is_proposal_only_with_redacted_request(setup, monkeypatch):
    root, output, client, response = setup
    before = (root / "routes/search.ts").read_bytes()
    captured = []

    def transport(route, system, user):
        captured.append((system, user))
        return json.dumps(response)

    monkeypatch.setattr(client, "_request_route", transport)
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status == "ready_for_review"
    assert artifact.original_unchanged and artifact.model_response_received
    assert not artifact.applied and not artifact.security_verified
    assert not artifact.review.applied and not artifact.review.security_verified
    assert artifact.review.proposal.unified_diff == response["unified_diff"]
    assert (root / "routes/search.ts").read_bytes() == before
    assert len(captured) == 1 and artifact.provider_attempts[0]["status"] == "ok"
    request = (output / "request.json").read_text()
    assert "unit-test-transport-only" not in request
    assert "artifact_refs" not in request and "trials" not in request.replace("independent_trials", "")
    assert "ground_truth" not in request and "reference.patch" not in request
    assert (output / "patch-review.json").is_file()
    saved_response = BoundedPatchResponse.model_validate_json((output / "model-response.json").read_text())
    assert digest(saved_response.model_dump_json().encode()) == artifact.response_sha256


@pytest.mark.parametrize("change", ["outside", "secret", "disable", "oversized", "id", "extra"])
def test_unsafe_or_invalid_model_output_never_becomes_patch(setup, monkeypatch, change):
    root, output, client, response = setup
    if change == "outside":
        response["unified_diff"] = response["unified_diff"].replace("routes/search.ts", "test/evaluator.ts")
    elif change == "secret":
        response["unified_diff"] = response["unified_diff"].replace(SAFE, "const password='never-persist-this-secret'")
        response["rationale"] = "never-persist-this-secret"
    elif change == "disable":
        response["unified_diff"] = response["unified_diff"].replace(SAFE, "return []")
    elif change == "oversized":
        response["unified_diff"] += "x" * 17000
    elif change == "id":
        response["finding_id"] = "other"
    else:
        response["command"] = "arbitrary"
    monkeypatch.setattr(client, "_request_route", lambda *args: json.dumps(response))
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status in {"rejected", "failed"}
    assert artifact.review is None and artifact.original_unchanged
    assert not (output / "patch-review.json").exists()
    assert "never-persist-this-secret" not in (output / "generation.json").read_text()


def test_source_mutation_during_model_call_invalidates_proposal(setup, monkeypatch):
    root, output, client, response = setup

    def mutate(*args):
        (root / "routes/search.ts").write_text("changed\n")
        return json.dumps(response)

    monkeypatch.setattr(client, "_request_route", mutate)
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status == "failed" and artifact.reason == "input_integrity_changed"
    assert not artifact.original_unchanged and artifact.review is None
    assert not (output / "patch-review.json").exists()


def test_no_credentials_is_visible_failed_attempt(setup):
    root, output, _, _ = setup
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next"))
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status == "failed" and not artifact.model_response_received
    assert not artifact.provider_attempts and (output / "generation.json").is_file()


def test_output_cannot_overwrite_or_enter_target(setup):
    root, output, client, _ = setup
    output.mkdir()
    with pytest.raises(FileExistsError):
        generation.generate(repository=root, family="sql-search", output=output, client=client)
    with pytest.raises(ValueError, match="outside"):
        generation.generate(repository=root, family="sql-search", output=root / "output", client=client)


def test_integration_client_is_not_an_enabled_generation_route(setup):
    root, output, _, _ = setup
    with pytest.raises(TypeError, match="IntegrationPatchClient"):
        generation.generate(repository=root, family="sql-search", output=output, client=object())


def test_redirect_view_excludes_seeded_keys_and_relocates_lines(tmp_path):
    (tmp_path / "lib").mkdir()
    file = tmp_path / "lib/insecurity.ts"
    file.write_text("const privateKey='never-send-this-secret';\n" + "\n"*5 +
        "export const isRedirectAllowed = (url: string) => {\n  let allowed = false\n"
        "  for (const allowedUrl of redirectAllowlist) {\n"
        "    allowed = allowed || url.includes(allowedUrl)\n  }\n  return allowed\n}\n")
    _, _, start, _, context = source_view(tmp_path, "redirect-allowlist")
    assert start == 7 and "never-send" not in context and "privateKey" not in context
    file.write_text("\n" + file.read_text())
    assert source_view(tmp_path, "redirect-allowlist")[2] == 8


@pytest.mark.parametrize("replacement", ["allowed = true", "allowed = false", "return true",
    "allowed = allowed || url.startsWith(allowedUrl)", "allowed = eval(url)"])
def test_redirect_guard_rejects_disabled_or_unsafe_protection(replacement):
    diff = "-    allowed = allowed || url.includes(allowedUrl)\n+    " + replacement
    with pytest.raises(ValueError):
        defensive_shape("redirect-allowlist", diff)


def test_redirect_exact_equality_is_a_bounded_allowed_shape():
    defensive_shape("redirect-allowlist", "-allowed = allowed || url.includes(allowedUrl)\n"
                    "+allowed = allowed || url === allowedUrl")


def test_response_schema_rejects_nonstring_or_execution_fields():
    with pytest.raises(ValidationError):
        BoundedPatchResponse(finding_id=1, rationale="why", unified_diff="diff")
    with pytest.raises(ValidationError):
        BoundedPatchResponse(finding_id="f", rationale="why", unified_diff="diff", argv=[])


def test_secret_context_is_not_sent(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "routes/search.ts").write_text("const password='never-send';\n" + QUERY + "\n")
    with pytest.raises(ValueError, match="secret"):
        source_view(tmp_path, "sql-search")


@pytest.mark.parametrize("rationale", ["unit-test-transport-only", 'Notes: "password": "never-persist"'])
def test_secrets_in_rationale_are_rejected_before_raw_response_persistence(setup, monkeypatch, rationale):
    root, output, client, response = setup
    response["rationale"] = rationale
    monkeypatch.setattr(client, "_request_route", lambda *args: json.dumps(response))
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status == "rejected" and artifact.reason == "secret_in_model_response"
    assert not (output / "model-response.json").exists()
    assert not (output / "patch-review.json").exists()
    assert rationale not in (output / "generation.json").read_text()


@pytest.mark.parametrize("failure_call", [1, 2])
def test_snapshot_timeout_never_loses_failed_artifact_or_preserves_ready(setup, monkeypatch, failure_call):
    root, output, client, response = setup
    previous = generation.validate_target_snapshot
    count = 0

    def snapshot(*args):
        nonlocal count
        count += 1
        if count == failure_call:
            raise subprocess.TimeoutExpired(["git", "status"], 30)
        return previous(*args)

    monkeypatch.setattr(generation, "validate_target_snapshot", snapshot)
    monkeypatch.setattr(client, "_request_route", lambda *args: json.dumps(response))
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status == "failed" and artifact.review is None
    assert not artifact.original_unchanged and (output / "generation.json").exists()
    assert not (output / "patch-review.json").exists()


def test_changed_context_cannot_be_sent_even_if_tree_is_restored(setup, monkeypatch):
    root, output, client, _ = setup
    # Simulate a source read racing with another writer. Whole-tree preflight
    # alone sees the original tree, but the extracted bytes are not its blob.
    previous = generation.source_view

    def raced(*args):
        file, raw, start, end, context = previous(*args)
        return file, raw + b"// different read\n", start, end, context + "\nprivate-read"

    monkeypatch.setattr(generation, "source_view", raced)
    monkeypatch.setattr(client, "_request_route", lambda *args: pytest.fail("No model request allowed"))
    artifact = generation.generate(repository=root, family="sql-search", output=output, client=client)
    assert artifact.status == "failed" and artifact.original_unchanged
    assert not (output / "request.json").exists()
    assert not artifact.provider_attempts
