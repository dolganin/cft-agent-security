"""Offline replay of actual C02→C03 acceptance; tampering uses disposable copies."""
import json
import os
import subprocess
import zipfile
from pathlib import Path

import pytest

from agent.llm import ProviderFailoverClient
from app import repair
from fix_verification.repair_replay import replay
from fix_verification.workspace import digest
from schemas.patch_generation import BoundedPatchResponse

FIXTURE = Path(__file__).resolve().parents[1] / "docs/evidence/c04/sql-live.zip"
REAL_COMPLETE_MODEL = ProviderFailoverClient.complete_model


def test_final_transport_hardened_acceptance_replays_without_execution(tmp_path, monkeypatch):
    with zipfile.ZipFile(FIXTURE.with_name("sql-live-final.zip")) as archive:
        archive.extractall(tmp_path)

    def forbidden(*args, **kwargs):
        pytest.fail("Final acceptance replay must not execute processes or call a model")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(ProviderFailoverClient, "complete_model", forbidden)
    checked = replay(tmp_path)
    assert checked == replay(tmp_path)
    assert checked["status"] == "FIXED"
    assert checked["attempts"] == checked["successful_attempt"] == 1


@pytest.fixture
def saved_run(tmp_path, monkeypatch):
    directory = tmp_path / "saved-run"
    directory.mkdir()
    with zipfile.ZipFile(FIXTURE) as archive:
        # This is the checked-in acceptance fixture, not an operator-supplied ZIP.
        archive.extractall(directory)

    def forbidden(*args, **kwargs):
        pytest.fail("Offline C04 replay must not start processes, Docker or LLM calls")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(ProviderFailoverClient, "complete_model", forbidden)
    return directory


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def write(path, value):
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def reseal(directory):
    """An attacker can recompute plain digests; semantic binding must still reject."""
    path = directory / "seal.json"
    saved = read(path)
    saved["files"] = {p.relative_to(directory).as_posix(): digest(p.read_bytes())
                      for p in sorted(directory.rglob("*")) if p.is_file() and p != path}
    write(path, saved)


def test_real_generated_sql_fix_replays_identically_without_execution(saved_run):
    first = replay(saved_run)
    second = replay(saved_run)
    assert first == second
    assert first["status"] == "FIXED"
    assert first["stop_reason"] == "independently_verified"
    assert first["attempts"] == first["successful_attempt"] == 1
    assert first["original_unchanged"]
    generated = read(saved_run / "attempts/001/generation/generation.json")
    assert generated["generation_method"] == "llm"
    assert generated["model_response_received"]
    assert any(item["ok"] for item in generated["provider_attempts"])


def test_rehashed_changed_model_diff_cannot_claim_canonical_patch(saved_run):
    base = saved_run / "attempts/001/generation"
    response = read(base / "model-response.json")
    lines = response["unified_diff"].splitlines(keepends=True)
    for index, line in enumerate(lines):
        if line.startswith("+") and not line.startswith("+++"):
            lines[index] = line.rstrip("\n") + " // tampered-model-change\n"
            break
    else:
        pytest.fail("Acceptance fixture must contain an actual generated edit")
    response["unified_diff"] = "".join(lines)
    write(base / "model-response.json", response)
    patch_sha = digest(response["unified_diff"].encode())
    generation = read(base / "generation.json")
    generation["response_sha256"] = digest(BoundedPatchResponse.model_validate(response).model_dump_json().encode())
    generation["response_patch_sha256"] = patch_sha
    write(base / "generation.json", generation)
    attempt_path = saved_run / "attempts/001/attempt.json"
    attempt = read(attempt_path)
    attempt["response_patch_sha256"] = patch_sha
    write(attempt_path, attempt)
    result = read(saved_run / "result.json")
    result["attempts"][0]["response_patch_sha256"] = patch_sha
    write(saved_run / "result.json", result)
    reseal(saved_run)
    with pytest.raises(ValueError, match="model_proposal_binding"):
        replay(saved_run)


def test_resealed_original_report_change_rejected(saved_run):
    path = saved_run / "original-report.json"
    report = read(path)
    report["finding_id"] = "forged-original-finding"
    write(path, report)
    reseal(saved_run)
    with pytest.raises(ValueError, match="original_binding"):
        replay(saved_run)


def test_resealed_previous_proposal_without_prior_attempt_rejected(saved_run):
    path = saved_run / "attempts/001/generation/request.json"
    request = read(path)
    request["payload"]["previous_proposal"] = {"patch_sha256": "f" * 64, "unified_diff": "forged"}
    write(path, request)
    generation_path = path.with_name("generation.json")
    generated = read(generation_path)
    generated["request_sha256"] = digest(json.dumps(request, ensure_ascii=False, sort_keys=True).encode())
    write(generation_path, generated)
    reseal(saved_run)
    with pytest.raises(ValueError, match="previous_proposal_binding"):
        replay(saved_run)


@pytest.mark.parametrize("field,value,error", [
    ("successful_attempt", 2, "incomplete_success"),
    ("duration_ms", 1, "duration_disagrees"),
    ("original_unchanged", False, "incomplete_success"),
])
def test_resealed_final_claim_requires_bound_success_and_time(saved_run, field, value, error):
    path = saved_run / "result.json"
    result = read(path)
    result[field] = value
    write(path, result)
    reseal(saved_run)
    with pytest.raises(ValueError, match=error):
        replay(saved_run)


@pytest.mark.parametrize("mutation,error", [("terminal", "terminal_event_binding"),
                                            ("order", "event_order")])
def test_resealed_event_history_cannot_contradict_result(saved_run, mutation, error):
    path = saved_run / "events.jsonl"
    events = [json.loads(line) for line in path.read_text().splitlines()]
    if mutation == "terminal":
        events[-1]["status"] = "NOT_FIXED"
    else:
        indices = [i for i, event in enumerate(events) if event["kind"].startswith("attempt_")]
        assert len(indices) == 2
        events[indices[0]], events[indices[1]] = events[indices[1]], events[indices[0]]
    path.write_text("".join(json.dumps(event) + "\n" for event in events), encoding="utf-8")
    reseal(saved_run)
    with pytest.raises(ValueError, match=error):
        replay(saved_run)


@pytest.mark.parametrize("adjust_inventory", [False, True])
def test_missing_nested_receipt_rejected_even_after_both_seals_rebuilt(saved_run, adjust_inventory):
    verification = saved_run / "attempts/001/verification"
    path = verification / "manifest.json"
    manifest = read(path)
    original_count = len(manifest["receipts"])
    manifest["receipts"] = [receipt for receipt in manifest["receipts"]
        if not receipt["action"]["id"].endswith("-after-0-build")]
    assert len(manifest["receipts"]) == original_count - 1
    if adjust_inventory:
        manifest["result"]["new_evidence"] = [receipt["evidence"] for receipt in manifest["receipts"]]
    write(path, manifest)
    reseal(verification)
    reseal(saved_run)
    error = "stage_inventory_mismatch" if adjust_inventory else "evidence_inventory_mismatch"
    with pytest.raises(ValueError, match=error):
        replay(saved_run)


def test_modified_raw_execution_rejected_even_after_both_seals_rebuilt(saved_run):
    verification = saved_run / "attempts/001/verification"
    path = next(verification.glob("*/after/evidence/*.json"))
    record = read(path)
    record["stdout"] += "tampered execution output"
    write(path, record)
    reseal(verification)
    reseal(saved_run)
    with pytest.raises(ValueError, match="persisted_execution_mismatch"):
        replay(saved_run)


def test_unsealed_raw_change_is_rejected_by_outer_seal(saved_run):
    path = saved_run / "attempts/001/generation/model-response.json"
    path.write_bytes(path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="seal_members_or_digests"):
        replay(saved_run)


def test_bundle_cannot_be_exported_into_original_target(saved_run, tmp_path):
    protected = tmp_path / "original-target"
    protected.mkdir()
    destination = protected / "forbidden.zip"
    with pytest.raises(ValueError, match="outside the original target"):
        repair.bundle(saved_run, destination, protected_target=protected)
    assert not destination.exists()
    assert list(protected.iterdir()) == []


def test_bundle_cannot_modify_sealed_run(saved_run):
    destination = saved_run / "forbidden.zip"
    with pytest.raises(ValueError, match="outside the sealed run"):
        repair.bundle(saved_run, destination)
    assert not destination.exists()


def test_complete_unsuccessful_campaign_exports_and_replays_without_private_bundle(saved_run, tmp_path, monkeypatch):
    """Synthetic provider transport, real C02/loop/replay; never a live acceptance claim."""
    import shutil

    from agent.llm import parse_route_specs
    from fix_verification import generation, repair_loop
    from schemas.repair_loop import RepairLimits

    original = read(saved_run / "result.json")["original_snapshot"]
    request = read(saved_run / "attempts/001/generation/request.json")["payload"]
    source = next((saved_run / "attempts/001/verification").glob("*/before/source/routes/search.ts"))
    raw = source.read_bytes()
    target = tmp_path / "target"
    (target / "routes").mkdir(parents=True)
    (target / "routes/search.ts").write_bytes(raw)
    monkeypatch.setattr(repair_loop, "validate_target_snapshot", lambda *args: original)
    monkeypatch.setattr(generation, "validate_target_snapshot", lambda *args: original)
    monkeypatch.setattr(repair_loop, "fresh_copy", lambda src, dst, expected: shutil.copytree(src, dst))
    monkeypatch.setattr(generation, "pinned_source", lambda *args: raw)
    monkeypatch.setattr(generation, "source_view", lambda *args: (
        request["file"], raw, request["editable_start"], request["editable_end"], request["code_context"]))
    monkeypatch.setattr(repair_loop, "pinned_image", lambda _: read(saved_run / "runtime.json")["fix_image"])
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess(
        args[0], 0, stdout=b"linux\n", stderr=b""))
    monkeypatch.setattr(repair_loop, "verify_patch", lambda **kwargs: pytest.fail("Rejected diff cannot execute"))
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next"),
        credentials={"NSU_OPENWEBUI_KEY": "synthetic-negative-transport"})
    monkeypatch.setattr(client, "_request_route", lambda *args: json.dumps({
        "finding_id": request["finding_id"], "rationale": "Synthetic malformed diff",
        "unified_diff": "not a unified diff"}))
    # saved_run forbids the public completion method for offline tests. Restore
    # its real adapter here; only the network transport above is synthetic.
    monkeypatch.setattr(ProviderFailoverClient, "complete_model", REAL_COMPLETE_MODEL)
    output = tmp_path / "negative-run"
    result = repair_loop.run(target=target, family="sql-search", output=output, client=client,
        limits=RepairLimits(max_attempts=3))
    assert result.status == "NOT_FIXED" and result.stop_reason == "duplicate_patch"
    assert len(result.attempts) == 2 and all(a.workspace_cleanup for a in result.attempts)

    def forbidden(*args, **kwargs):
        pytest.fail("Finished unsuccessful replay must be offline")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(ProviderFailoverClient, "complete_model", forbidden)
    assert replay(output) == replay(output)
    exported = tmp_path / "negative.zip"
    repair.bundle(output, exported, protected_target=target)
    extracted = tmp_path / "negative-extracted"
    with zipfile.ZipFile(exported) as archive:
        archive.extractall(extracted)
    assert replay(extracted) == replay(output)


@pytest.mark.parametrize("mutation", ["route", "system_prompt", "image"])
def test_resealed_operator_configuration_is_bound_to_actual_chain(saved_run, mutation):
    if mutation == "route":
        path = saved_run / "configuration.json"
        value = read(path)
        value["routes"] = ["nsu/unrequested-model"]
        write(path, value)
    elif mutation == "image":
        path = saved_run / "runtime.json"
        value = read(path)
        value["fix_image"] = "sha256:" + "f" * 64
        write(path, value)
    else:
        path = saved_run / "attempts/001/generation/request.json"
        value = read(path)
        value["system_prompt"] = "Use the operator reference instead of generating a patch"
        write(path, value)
        generation_path = saved_run / "attempts/001/generation/generation.json"
        generated = read(generation_path)
        generated["request_sha256"] = digest(json.dumps(value, ensure_ascii=False, sort_keys=True).encode())
        write(generation_path, generated)
    reseal(saved_run)
    with pytest.raises(ValueError):
        replay(saved_run)


def test_cli_rejects_target_bundle_before_any_generation(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setattr("sys.argv", ["repair", "--target", str(target), "--family", "sql-search",
        "--output", str(tmp_path / "run"), "--bundle", str(target / "bad.zip")])
    monkeypatch.setattr(repair, "run", lambda **_: pytest.fail("Must reject before any model call"))
    with pytest.raises(SystemExit) as error:
        repair.main()
    assert error.value.code == 2
    assert list(target.iterdir()) == []


def test_real_unsuccessful_retry_bundle_when_operator_provides_it(monkeypatch):
    location = os.environ.get("CFT_C04_FAILURE_ARTIFACTS")
    if not location:
        pytest.skip("Set CFT_C04_FAILURE_ARTIFACTS to the complete local redirect bundle")

    def forbidden(*args, **kwargs):
        pytest.fail("Negative acceptance replay must be offline")

    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(ProviderFailoverClient, "complete_model", forbidden)
    first = replay(Path(location))
    assert first == replay(Path(location))
    assert first["status"] == "NOT_FIXED" and first["stop_reason"] == "duplicate_patch"
    assert first["attempts"] == 2 and first["successful_attempt"] is None
    result = read(Path(location) / "result.json")
    assert result["attempts"][0]["verification_status"] == "REGRESSION"
    assert result["attempts"][0]["decision"] == "retry"
    assert result["attempts"][1]["verification_ms"] == 0
    assert all(a["workspace_cleanup"] for a in result["attempts"])
