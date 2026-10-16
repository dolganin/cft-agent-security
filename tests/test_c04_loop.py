"""Synthetic orchestration tests; no test double claims real C03 acceptance."""
import difflib
import json
import shutil
import subprocess
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from agent.llm import ProviderFailoverClient, parse_route_specs
from fix_verification import repair_loop as loop
from fix_verification.workspace import digest
from schemas.fix import PatchReviewArtifact, ProposedPatch
from schemas.patch_generation import PatchGenerationArtifact
from schemas.repair_loop import RepairLimits


@pytest.fixture
def campaign(tmp_path, monkeypatch):
    target = tmp_path / "target"
    (target / "routes").mkdir(parents=True)
    raw = (b"// prefix0\n// prefix1\n// prefix2\n// prefix3\nconst unsafe = true\n"
           b"// suffix1\n// suffix2\n// suffix3\n// suffix4\n")
    (target / "routes/search.ts").write_bytes(raw)
    _, report, report_sha, _ = loop.original_input("sql-search")

    def snapshot(root, commit):
        return {"commit": commit, "tracked_files": 1,
                "files_sha256": digest((root / "routes/search.ts").read_bytes())}

    original = snapshot(target, loop.SOURCE_COMMIT)
    copies = []

    def copy(source, destination, expected):
        assert snapshot(source, loop.SOURCE_COMMIT) == expected
        shutil.copytree(source, destination)
        copies.append(destination)

    monkeypatch.setattr(loop, "validate_target_snapshot", snapshot)
    monkeypatch.setattr(loop, "fresh_copy", copy)
    monkeypatch.setattr(loop, "original_input", lambda _: (None, report, report_sha, original))
    monkeypatch.setattr(loop, "load_scope", lambda: None)
    monkeypatch.setattr(loop, "pinned_image", lambda _: "sha256:" + "a" * 64)
    real_run = subprocess.run

    def docker_preflight_only(argv, *args, **kwargs):
        if argv[0] == "docker":
            return subprocess.CompletedProcess(argv, 0, stdout=b"linux\n", stderr=b"")
        return real_run(argv, *args, **kwargs)

    monkeypatch.setattr(loop.subprocess, "run", docker_preflight_only)
    client = ProviderFailoverClient(routes=parse_route_specs("nsu:qwen3.8-flash-next"),
        credentials={"NSU_OPENWEBUI_KEY": "unit-transport-never-called"})
    return SimpleNamespace(target=target, output=tmp_path / "run", client=client, report=report,
                           copies=copies, raw=raw, snapshot=original)


def fake_generation(campaign, *, ready=False, reason="invalid_diff_format_or_window", raw_patch=None):
    """Synthetic C02 output for loop transitions, not an actual provider response."""
    raw = campaign.raw.decode()
    patch = "".join(difflib.unified_diff(raw.splitlines(True),
        raw.replace("unsafe = true", "unsafe = false").splitlines(True),
        fromfile="a/routes/search.ts", tofile="b/routes/search.ts"))
    proposal = ProposedPatch(finding_id=campaign.report.finding_id, rationale="unit fixture",
                             unified_diff=patch)
    review = PatchReviewArtifact(id="unit-review", run_id="unit-run",
        finding_id=proposal.finding_id, file="routes/search.ts", status="ready_for_review",
        source_sha256=digest(campaign.raw), proposal_sha256=digest(proposal.model_dump_json().encode()),
        model="nsu:qwen3.8-flash-next", generated_at=datetime.now(UTC), proposal=proposal,
        validation_detail="synthetic orchestration fixture", editable_start=1,
        editable_end=len(raw.splitlines()))
    return PatchGenerationArtifact(family_id="sql-search",
        status="ready_for_review" if ready else "rejected",
        reason="bounded_proposal_validated" if ready else reason,
        provider_route=review.model, provider_attempts=[{"ok": True, "route": review.model}],
        model_response_received=True, source_snapshot_sha256=campaign.snapshot["files_sha256"],
        source_file_sha256=digest(campaign.raw), request_sha256="b" * 64,
        response_sha256="c" * 64, response_patch_sha256=digest((raw_patch or patch).encode()),
        original_unchanged=True, review=review if ready else None)


def saved_generator(campaign, outputs, calls):
    values = iter(outputs)

    def generate(**kwargs):
        calls.append(kwargs)
        assert (kwargs["repository"] / "routes/search.ts").read_bytes() == campaign.raw
        artifact = next(values)
        kwargs["output"].mkdir()
        loop.write_json(kwargs["output"] / "generation.json", artifact.model_dump(mode="json"))
        if artifact.review:
            loop.write_json(kwargs["output"] / "patch-review.json", artifact.review.model_dump(mode="json"))
        return artifact

    return generate


def run(campaign, **kwargs):
    return loop.run(target=campaign.target, family="sql-search", output=campaign.output,
                    client=campaign.client, **kwargs)


def test_retry_feedback_clean_copies_explicit_review_then_duplicate_stops(campaign, monkeypatch):
    generated = [fake_generation(campaign, raw_patch="invalid diff"),
                 fake_generation(campaign, ready=True), fake_generation(campaign, ready=True)]
    calls, verified = [], []
    monkeypatch.setattr(loop, "generate", saved_generator(campaign, generated, calls))

    def verify(**kwargs):
        verified.append(kwargs)
        assert kwargs["report"] is campaign.report
        assert kwargs["review"] is generated[1].review
        assert kwargs["review"] is not None  # No C03 reference-patch fallback.
        assert (kwargs["target"] / "routes/search.ts").read_bytes() == campaign.raw
        kwargs["output"].mkdir()
        return SimpleNamespace(result=SimpleNamespace(status="NOT_FIXED", original_unchanged=True,
            cleanup_complete=True, proposal_sha256=kwargs["review"].proposal_sha256,
            before_evidence=SimpleNamespace(verdict="confirmed"), stages=[]))

    monkeypatch.setattr(loop, "verify_patch", verify)
    monkeypatch.setattr(loop, "replay_verification", lambda _: {"status": "NOT_FIXED"})
    result = run(campaign)
    assert result.status == "NOT_FIXED" and result.stop_reason == "duplicate_patch"
    assert [a.decision for a in result.attempts] == ["retry", "retry", "duplicate"]
    assert calls[0]["feedback"] is None
    assert calls[1]["feedback"].code == "invalid_diff_format_or_window"
    assert calls[2]["feedback"].code == "NOT_FIXED"
    assert calls[1]["previous_review"] is None
    assert calls[2]["previous_review"] is generated[1].review
    assert len(verified) == 1 and len(campaign.copies) == 3
    assert len(set(campaign.copies)) == 3
    assert all(not path.exists() for path in campaign.copies)
    assert all(a.workspace_cleanup for a in result.attempts)
    assert result.original_unchanged
    assert (campaign.target / "routes/search.ts").read_bytes() == campaign.raw
    assert (campaign.output / "seal.json").is_file()
    assert (campaign.output / "attempts/002/feedback.json").is_file()
    events = [json.loads(line) for line in (campaign.output / "events.jsonl").read_text().splitlines()]
    assert sum(e["kind"] == "attempt_finished" for e in events) == 3
    assert events[-1]["kind"] == "run_finished"


def test_attempt_limit_is_terminal_and_persists_last_feedback(campaign, monkeypatch):
    calls = []
    values = [fake_generation(campaign, raw_patch="invalid first"),
              fake_generation(campaign, raw_patch="invalid second")]
    monkeypatch.setattr(loop, "generate", saved_generator(campaign, values, calls))
    monkeypatch.setattr(loop, "verify_patch", lambda **_: pytest.fail("Invalid proposal cannot execute"))
    result = run(campaign, limits=RepairLimits(max_attempts=2))
    assert result.status == "NOT_FIXED" and result.stop_reason == "attempts_exhausted"
    assert len(calls) == len(result.attempts) == 2
    assert result.attempts[-1].feedback.code == "invalid_diff_format_or_window"
    assert result.finished_at is not None and result.duration_ms >= 0
    assert all(a.finished_at is not None and a.workspace_cleanup for a in result.attempts)


@pytest.mark.parametrize("reason,status,stop", [
    ("unsupported_defensive_shape", "NOT_FIXED", "proposal_rejected"),
    ("secret_in_model_response", "NOT_FIXED", "proposal_rejected"),
    ("model_unavailable_or_invalid_response", "TECHNICAL_ERROR", "generation_failed"),
])
def test_terminal_generation_failure_never_executes(campaign, monkeypatch, reason, status, stop):
    artifact = fake_generation(campaign, reason=reason)
    if status == "TECHNICAL_ERROR":
        artifact = artifact.model_copy(update={"status": "failed"})
    monkeypatch.setattr(loop, "generate", saved_generator(campaign, [artifact], []))
    monkeypatch.setattr(loop, "verify_patch", lambda **_: pytest.fail("No verifier on failed generation"))
    result = run(campaign)
    assert (result.status, result.stop_reason) == (status, stop)
    assert len(result.attempts) == 1 and result.attempts[0].workspace_cleanup
    assert result.successful_attempt is None


def test_original_mutation_blocks_run_and_retains_history(campaign, monkeypatch):
    def generate(**kwargs):
        (campaign.target / "routes/search.ts").write_bytes(b"externally changed\n")
        return fake_generation(campaign, reason="unsupported_defensive_shape")

    monkeypatch.setattr(loop, "generate", generate)
    result = run(campaign)
    assert result.status == "TECHNICAL_ERROR" and result.stop_reason == "original_integrity_failed"
    assert not result.original_unchanged and result.successful_attempt is None
    assert len(result.attempts) == 1 and result.attempts[0].workspace_cleanup
    assert (campaign.output / "attempts/001/attempt.json").is_file()


def test_verifier_failure_cleans_attempt_and_seals_technical_result(campaign, monkeypatch):
    monkeypatch.setattr(loop, "generate", saved_generator(campaign,
        [fake_generation(campaign, ready=True)], []))

    def failed(**kwargs):
        assert kwargs["review"] is not None
        raise RuntimeError("password=private-error-must-not-be-persisted")

    monkeypatch.setattr(loop, "verify_patch", failed)
    result = run(campaign)
    assert result.status == "TECHNICAL_ERROR" and result.successful_attempt is None
    assert result.attempts[0].workspace_cleanup and result.original_unchanged
    assert all(not p.exists() for p in campaign.copies)
    for name in ("result.json", "events.jsonl", "report.md"):
        assert "private-error" not in (campaign.output / name).read_text()


def test_output_cannot_overwrite_or_enter_target(campaign):
    campaign.output.mkdir()
    with pytest.raises(FileExistsError):
        run(campaign)
    for output in (campaign.target / "artifacts", campaign.target.parent):
        with pytest.raises(ValueError, match="outside"):
            loop.run(target=campaign.target, family="sql-search", output=output,
                     client=campaign.client)


@pytest.mark.parametrize("status,before,cleanup,unchanged,stages,decision", [
    ("FIXED", "confirmed", True, True, [], "fixed"),
    ("FIXED", "confirmed", False, True, [], "stop"),
    ("FIXED", "confirmed", True, False, [], "stop"),
    ("NOT_FIXED", "confirmed", True, True, [], "retry"),
    ("NOT_FIXED", "inconclusive", True, True, [], "stop"),
    ("INCONCLUSIVE", "confirmed", True, True, [], "stop"),
    ("REGRESSION", "confirmed", True, True, [("build", False)], "retry"),
    ("REGRESSION", "confirmed", True, True, [("tests", True)], "stop"),
    ("REGRESSION", "confirmed", True, True, [("start", False)], "stop"),
])
def test_verification_decision_uses_conclusive_cause_and_cleanup(
        status, before, cleanup, unchanged, stages, decision):
    # Decision helper only: this synthetic object is never accepted as a sealed C03 package.
    result = SimpleNamespace(status=status, before_evidence=SimpleNamespace(verdict=before),
        cleanup_complete=cleanup, original_unchanged=unchanged,
        stages=[SimpleNamespace(phase="after", stage=name, status="failed", timed_out=timeout)
                for name, timeout in stages])
    actual, _, feedback = loop.decide_verification(SimpleNamespace(result=result), 1, "a" * 64)
    assert actual == decision
    assert (feedback is not None) == (decision == "retry")


def test_replayed_status_must_match_verifier_result(campaign, monkeypatch):
    monkeypatch.setattr(loop, "generate", saved_generator(campaign,
        [fake_generation(campaign, ready=True)], []))
    monkeypatch.setattr(loop, "verify_patch", lambda **kwargs: SimpleNamespace(result=SimpleNamespace(
        status="NOT_FIXED", proposal_sha256=kwargs["review"].proposal_sha256)))
    monkeypatch.setattr(loop, "replay_verification", lambda _: {"status": "FIXED"})
    result = run(campaign)
    assert result.status == "TECHNICAL_ERROR" and result.successful_attempt is None
    assert result.attempts[0].workspace_cleanup


def test_equivalent_patch_effect_stops_before_second_verification(campaign, monkeypatch):
    first = fake_generation(campaign, ready=True)
    source = campaign.raw.decode()
    alternative = "".join(difflib.unified_diff(source.splitlines(True),
        source.replace("unsafe = true", "unsafe = false").splitlines(True),
        fromfile="a/routes/search.ts", tofile="b/routes/search.ts", n=1))
    assert alternative != first.review.proposal.unified_diff
    proposal = first.review.proposal.model_copy(update={"unified_diff": alternative})
    review = first.review.model_copy(update={"proposal": proposal,
        "proposal_sha256": digest(proposal.model_dump_json().encode())})
    second = first.model_copy(update={"review": review,
        "response_patch_sha256": digest(alternative.encode())})
    monkeypatch.setattr(loop, "generate", saved_generator(campaign, [first, second], []))
    verified = []

    def verify(**kwargs):
        verified.append(kwargs)
        return SimpleNamespace(result=SimpleNamespace(status="NOT_FIXED", original_unchanged=True,
            cleanup_complete=True, proposal_sha256=kwargs["review"].proposal_sha256,
            before_evidence=SimpleNamespace(verdict="confirmed"), stages=[]))

    monkeypatch.setattr(loop, "verify_patch", verify)
    monkeypatch.setattr(loop, "replay_verification", lambda _: {"status": "NOT_FIXED"})
    result = run(campaign)
    assert result.stop_reason == "duplicate_patch" and len(verified) == 1
    first_attempt, second_attempt = result.attempts
    assert first_attempt.patch_sha256 != second_attempt.patch_sha256
    assert first_attempt.patched_file_sha256 == second_attempt.patched_file_sha256
    assert second_attempt.decision == "duplicate"


def test_deadline_reached_during_generation_never_starts_verifier(campaign, monkeypatch):
    now = [0.0]
    monkeypatch.setattr(loop, "monotonic", lambda: now[0])
    artifact = fake_generation(campaign, ready=True)

    def generate(**kwargs):
        now[0] = 5.0
        return artifact

    monkeypatch.setattr(loop, "generate", generate)
    monkeypatch.setattr(loop, "verify_patch", lambda **_: pytest.fail("Expired run cannot execute"))
    result = run(campaign, limits=RepairLimits(wall_clock_seconds=1))
    assert result.stop_reason == "wall_clock_exhausted" and result.status != "FIXED"
    assert len(result.attempts) == 1 and result.attempts[0].workspace_cleanup
    assert result.duration_ms == 5000


def test_keyboard_interrupt_preserves_partial_result_and_cleans_copy(campaign, monkeypatch):
    def generate(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(loop, "generate", generate)
    with pytest.raises(KeyboardInterrupt):
        run(campaign)
    saved = json.loads((campaign.output / "result.json").read_text())
    assert saved["status"] == "INTERRUPTED" and saved["stop_reason"] == "operator_interrupted"
    assert saved["attempts"][0]["workspace_cleanup"]
    assert saved["successful_attempt"] is None
    assert (campaign.output / "seal.json").is_file()
    assert all(not p.exists() for p in campaign.copies)


def test_wrong_proposal_binding_never_produces_fixed(campaign, monkeypatch):
    monkeypatch.setattr(loop, "generate", saved_generator(campaign,
        [fake_generation(campaign, ready=True)], []))
    monkeypatch.setattr(loop, "verify_patch", lambda **_: SimpleNamespace(result=SimpleNamespace(
        status="NOT_FIXED", proposal_sha256="d" * 64)))
    monkeypatch.setattr(loop, "replay_verification", lambda _: {"status": "NOT_FIXED"})
    result = run(campaign)
    assert result.status == "TECHNICAL_ERROR" and result.successful_attempt is None
    assert result.attempts[0].workspace_cleanup


@pytest.mark.parametrize("status,retry", [
    ("schema_validation_failed", True), ("invalid_structured_output", True),
    ("auth_or_access", False), ("payment_required", False), ("network_error", False),
])
def test_only_structural_provider_errors_can_request_a_new_patch(campaign, status, retry):
    generated = fake_generation(campaign).model_copy(update={
        "status": "failed", "reason": "model_unavailable_or_invalid_response",
        "provider_attempts": [{"route": "nsu/qwen3.8-flash-next", "ok": False, "status": status}],
    })
    decision, _, feedback = loop.decide_generation(generated, 1)
    assert (decision == "retry") == retry
    assert (feedback is not None) == retry
    if retry:
        assert feedback.code == "invalid_structured_output"
