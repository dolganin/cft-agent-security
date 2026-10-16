"""Offline C04 replay: sealed files, actual model edits and C03 receipts; no execution."""
from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path

from fix_verification.independent_replay import replay as replay_verification
from fix_verification.repair_feedback import proposal_view, validate_feedback
from fix_verification.workspace import digest, safe_file
from schemas.fix import PatchReviewArtifact
from schemas.independent_fix import C03Artifact
from schemas.patch_generation import BoundedPatchResponse, PatchGenerationArtifact
from schemas.repair_loop import RepairAttempt, RepairRun
from tools.repository_source import _safe_line


def read(root, name):
    return json.loads(safe_file(root, name).read_bytes())


def edit_operations(diff: str, file: str):
    """Compare model and canonical edits while allowing C02's restored source comments."""
    lines = diff.splitlines()
    if lines and lines[0] == f"diff --git a/{file} b/{file}":
        lines.pop(0)
    if lines[:2] != [f"--- a/{file}", f"+++ b/{file}"]:
        raise ValueError("response_diff_path_mismatch")
    operations = []
    old = new = old_count = new_count = used_old = used_new = None
    for line in lines[2:]:
        match = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?", line)
        if match:
            if old is not None and (used_old, used_new) != (old_count, new_count):
                raise ValueError("response_hunk_counts")
            old, old_count, new, new_count = (int(match[1]), int(match[2] or 1),
                                               int(match[3]), int(match[4] or 1))
            used_old = used_new = 0
            continue
        if old is None or not line or line[0] not in " +-":
            raise ValueError("response_diff_metadata")
        if line[0] == "-":
            operations.append(("remove", old, _safe_line(line[1:])))
        elif line[0] == "+":
            operations.append(("add", old, line[1:]))
        if line[0] in " -":
            old += 1
            used_old += 1
        if line[0] in " +":
            new += 1
            used_new += 1
    if not operations or (used_old, used_new) != (old_count, new_count):
        raise ValueError("response_hunk_counts")
    return operations


def check_generation(root: Path, attempt: RepairAttempt, result: RepairRun, previous, previous_review=None):
    base = attempt.directory + "/generation/"
    generated = PatchGenerationArtifact.model_validate(read(root, base + "generation.json"))
    if (generated.family_id != result.family or generated.status != attempt.generation_status
            or generated.reason != attempt.generation_reason
            or generated.response_patch_sha256 != attempt.response_patch_sha256
            or (not generated.original_unchanged and result.status == "FIXED")
            or (generated.source_snapshot_sha256 and generated.source_snapshot_sha256 != result.original_snapshot["files_sha256"])
            or (not generated.source_snapshot_sha256 and result.status == "FIXED")):
        raise ValueError("generation_attempt_binding")
    if generated.request_sha256:
        request = read(root, base + "request.json")
        from fix_verification.generation import SYSTEM
        payload = request["payload"]
        if request["system_prompt"] != SYSTEM or payload["family_id"] != result.family:
            raise ValueError("request_operator_contract")
        if digest(json.dumps(request, ensure_ascii=False, sort_keys=True).encode()) != generated.request_sha256:
            raise ValueError("request_digest")
        if request["payload"].get("previous_attempt") != (
                validate_feedback(previous) if previous is not None else None):
            raise ValueError("feedback_request_binding")
        if "previous_proposal" in payload:
            if previous_review is None or previous is None or previous.stage != "verification":
                raise ValueError("previous_proposal_binding")
            patch = previous_review.proposal.unified_diff
            if (payload["previous_proposal"] != proposal_view(previous_review)
                    or previous.previous_patch_sha256 != digest(patch.encode())):
                raise ValueError("previous_proposal_binding")
    if generated.status != "ready_for_review":
        return generated
    response = BoundedPatchResponse.model_validate(read(root, base + "model-response.json"))
    review = PatchReviewArtifact.model_validate(read(root, base + "patch-review.json"))
    if (review != generated.review or response.finding_id != review.finding_id
            or response.finding_id != read(root, "original-report.json")["finding_id"]
            or digest(response.model_dump_json().encode()) != generated.response_sha256
            or digest(response.unified_diff.encode()) != generated.response_patch_sha256
            or digest(review.proposal.model_dump_json().encode()) != review.proposal_sha256
            or edit_operations(response.unified_diff, review.file) != edit_operations(
                review.proposal.unified_diff, review.file)):
        raise ValueError("model_proposal_binding")
    if (payload["file"] != review.file or payload["finding_id"] != review.finding_id
            or payload["editable_start"] != review.editable_start
            or payload["editable_end"] != review.editable_end):
        raise ValueError("request_review_binding")
    return generated


def check_timing_and_events(root: Path, result: RepairRun):
    if result.finished_at < result.started_at:
        raise ValueError("c04_negative_time")
    if abs(result.duration_ms - (result.finished_at - result.started_at).total_seconds() * 1000) > 5000:
        raise ValueError("c04_duration_disagrees")
    previous = result.started_at
    expected = []
    for attempt in result.attempts:
        if (attempt.finished_at is None or not previous <= attempt.started_at <= attempt.finished_at <= result.finished_at
                or attempt.generation_ms + attempt.verification_ms > attempt.duration_ms + 5
                or abs(attempt.duration_ms - (attempt.finished_at - attempt.started_at).total_seconds() * 1000) > 5000):
            raise ValueError("c04_attempt_timing")
        expected.extend([("attempt_started", attempt.number), ("attempt_finished", attempt.number)])
        previous = attempt.finished_at
    events = [json.loads(line) for line in safe_file(root, "events.jsonl").read_text().splitlines()]
    if not events or events[-1].get("kind") != "run_finished":
        raise ValueError("c04_missing_terminal_event")
    if (events[-1].get("status"), events[-1].get("reason")) != (result.status, result.stop_reason):
        raise ValueError("c04_terminal_event_binding")
    actual = [(e.get("kind"), e.get("attempt")) for e in events
              if e.get("kind") in {"attempt_started", "attempt_finished"}]
    if actual != expected:
        raise ValueError("c04_event_order")
    times = [datetime.fromisoformat(e["time"]) for e in events]
    if times != sorted(times) or any(not result.started_at <= t <= result.finished_at for t in times[:-1]):
        raise ValueError("c04_event_timing")
    for event in events:
        if event["kind"] == "attempt_finished":
            attempt = result.attempts[event["attempt"] - 1]
            if (event.get("decision"), event.get("reason")) != (attempt.decision, attempt.reason):
                raise ValueError("c04_attempt_event_binding")


def replay(directory: Path) -> dict:
    root = directory.resolve(strict=True)
    seal = read(root, "seal.json")
    if seal.get("schema_version") != "cft.c04.seal.v1":
        raise ValueError("c04_seal_schema")
    members = {}
    total = 0
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("c04_linked_member")
        if not path.is_file() or path == root / "seal.json":
            continue
        total += path.stat().st_size
        if path.stat().st_size > 32 * 1024 * 1024 or total > 256 * 1024 * 1024 or len(members) >= 10000:
            raise ValueError("c04_bundle_budget")
        relative = path.relative_to(root).as_posix()
        members[relative] = digest(safe_file(root, relative).read_bytes())
    if members != seal.get("files"):
        raise ValueError("c04_seal_members_or_digests")
    result = RepairRun.model_validate(read(root, "result.json"))
    config = read(root, "configuration.json")
    if (config["family"] != result.family or config["limits"] != result.limits.model_dump(mode="json")
            or len(config.get("routes", [])) != 1):
        raise ValueError("c04_configuration_binding")
    if config.get("feedback_contract") not in {None, "cft.c04.feedback.v2"}:
        raise ValueError("c04_feedback_contract")
    if len(result.attempts) > result.limits.max_attempts or result.finished_at is None:
        raise ValueError("c04_attempt_budget_or_unfinished")
    check_timing_and_events(root, result)
    if result.original_snapshot and read(root, "original-snapshot.json") != result.original_snapshot:
        raise ValueError("c04_original_snapshot")
    archived_report_sha = None
    if result.attempts:
        from fix_verification.patch_context import original_input
        from fix_verification.scope import BASELINE, SCOPE, SOURCE_COMMIT
        _, report, archived_report_sha, archived_snapshot = original_input(result.family)
        if (read(root, "original-report.json") != report.model_dump(mode="json")
                or result.original_snapshot != archived_snapshot
                or config["source_commit"] != SOURCE_COMMIT):
            raise ValueError("c04_archived_original_binding")
        expected_lock = digest((SCOPE / "lock.json").read_bytes().replace(b"\r\n", b"\n"))
        expected_baseline = digest(BASELINE.read_bytes())
        runtime = read(root, "runtime.json")
        from executor.c03_runtime import TARGET_IMAGE, WORKER_IMAGE
        if (runtime["original_report_sha256"] != archived_report_sha
                or runtime["worker_image"] != WORKER_IMAGE or runtime["target_image"] != TARGET_IMAGE):
            raise ValueError("c04_runtime_binding")
    seen_response, seen_patch, seen_effect = set(), set(), set()
    previous = None
    previous_review = None
    from fix_verification.repair_loop import decide_generation, decide_verification
    for index, attempt in enumerate(result.attempts, 1):
        if attempt.number != index or attempt.directory != f"attempts/{index:03d}":
            raise ValueError("c04_attempt_order")
        saved = RepairAttempt.model_validate(read(root, attempt.directory + "/attempt.json"))
        if saved != attempt or attempt.finished_at is None:
            raise ValueError("c04_attempt_summary")
        if ((not attempt.workspace_cleanup or attempt.source_snapshot != result.original_snapshot)
                and result.status not in {"TECHNICAL_ERROR", "INTERRUPTED"}):
            raise ValueError("c04_workspace_integrity")
        generation_file = root / attempt.directory / "generation/generation.json"
        if not generation_file.is_file() or attempt.generation_status is None:
            if index != len(result.attempts) or result.status not in {"TECHNICAL_ERROR", "INTERRUPTED"}:
                raise ValueError("c04_missing_generation")
            break
        generated = check_generation(root, attempt, result, previous, previous_review)
        if (config.get("feedback_contract") == "cft.c04.feedback.v2" and previous_review is not None
                and generated.request_sha256
                and "previous_proposal" not in read(root, attempt.directory + "/generation/request.json")["payload"]):
            raise ValueError("previous_proposal_missing")
        if (any(a.get("route") not in config["routes"] for a in generated.provider_attempts)
                or (generated.provider_route and generated.provider_route not in config["routes"])):
            raise ValueError("c04_provider_route_binding")
        if (generated.original_report_sha256 != archived_report_sha
                or generated.source_commit != config["source_commit"]
                or generated.c01_lock_sha256 != expected_lock
                or generated.baseline_archive_sha256 != expected_baseline) and result.status not in {"TECHNICAL_ERROR", "INTERRUPTED"}:
            raise ValueError("c04_generation_original_provenance")
        duplicate = bool(generated.response_patch_sha256 and generated.response_patch_sha256 in seen_response)
        expected = None
        if duplicate:
            expected = ("duplicate", "duplicate_patch", None)
        elif generated.status != "ready_for_review":
            expected = decide_generation(generated, index)
        else:
            if not (root / attempt.directory / "candidate.json").is_file():
                if index == len(result.attempts) and result.status in {"TECHNICAL_ERROR", "INTERRUPTED"}:
                    break
                raise ValueError("c04_missing_candidate")
            candidate = read(root, attempt.directory + "/candidate.json")
            review = generated.review
            if (candidate["proposal_sha256"] != review.proposal_sha256
                    or candidate["source_sha256"] != review.source_sha256
                    or candidate["file"] != review.file
                    or candidate["patch_sha256"] != digest(review.proposal.unified_diff.encode())
                    or candidate["patch_sha256"] != attempt.patch_sha256
                    or candidate["patched_file_sha256"] != attempt.patched_file_sha256):
                raise ValueError("c04_candidate_binding")
            request = read(root, attempt.directory + "/generation/request.json")["payload"]
            if generated.source_file_sha256 != review.source_sha256 or request["source_sha256"] != review.source_sha256:
                raise ValueError("c04_source_file_binding")
            duplicate = attempt.patch_sha256 in seen_patch or attempt.patched_file_sha256 in seen_effect
            if duplicate:
                expected = ("duplicate", "duplicate_patch", None)
            elif attempt.verification_status is not None:
                verified_root = root / attempt.directory / "verification"
                verified = replay_verification(verified_root)
                package = C03Artifact.model_validate(read(verified_root, "manifest.json"))
                actual = package.result
                if (package.inputs.get("profile", {}).get("fix_verification", {}).get("image") != runtime["fix_image"]
                        or verified["status"] != attempt.verification_status
                        or package.family != result.family
                        or actual.proposal_sha256 != review.proposal_sha256
                        or actual.patch_sha256 != attempt.patch_sha256
                        or actual.proposed_patch != review.proposal
                        or (actual.applied and actual.patched_file_sha256 != attempt.patched_file_sha256)):
                    raise ValueError("c04_verifier_proposal_binding")
                expected = decide_verification(package, index, attempt.patch_sha256,
                    detailed=config.get("feedback_contract") == "cft.c04.feedback.v2"
                    or attempt.feedback is None or attempt.feedback.code != "REGRESSION")
        budget_stop = (attempt.decision == "stop" and attempt.reason == "wall_clock_exhausted"
                       and result.status == "TECHNICAL_ERROR"
                       and result.duration_ms >= result.limits.wall_clock_seconds * 1000)
        if expected is not None and not budget_stop and expected != (attempt.decision, attempt.reason, attempt.feedback):
            raise ValueError("c04_decision_disagrees")
        if expected is None and result.status not in {"TECHNICAL_ERROR", "INTERRUPTED"}:
            raise ValueError("c04_missing_verifier")
        if (attempt.feedback is not None
                and read(root, attempt.directory + "/feedback.json") != validate_feedback(attempt.feedback)):
            raise ValueError("c04_feedback_binding")
        if index < len(result.attempts) and attempt.decision != "retry":
            raise ValueError("c04_retry_after_terminal")
        seen_response.add(attempt.response_patch_sha256)
        seen_patch.add(attempt.patch_sha256)
        seen_effect.add(attempt.patched_file_sha256)
        previous = attempt.feedback
        previous_review = generated.review if attempt.verification_status is not None else None
    last = result.attempts[-1] if result.attempts else None
    if result.status == "FIXED":
        if (not result.original_unchanged or last is None or last.decision != "fixed"
                or result.successful_attempt != last.number
                or result.stop_reason != "independently_verified"):
            raise ValueError("c04_incomplete_success")
    elif result.successful_attempt is not None:
        raise ValueError("c04_false_successful_attempt")
    if result.status == "NOT_FIXED":
        if not result.original_unchanged or last is None:
            raise ValueError("c04_incomplete_failure")
        if result.stop_reason == "attempts_exhausted":
            if len(result.attempts) != result.limits.max_attempts or last.decision != "retry":
                raise ValueError("c04_false_exhaustion")
        elif result.stop_reason == "duplicate_patch":
            if last.decision != "duplicate":
                raise ValueError("c04_false_duplicate")
        elif result.stop_reason != "proposal_rejected" or last.reason != "proposal_rejected":
            raise ValueError("c04_false_failure_reason")
    return {"status": result.status, "stop_reason": result.stop_reason,
            "attempts": len(result.attempts), "successful_attempt": result.successful_attempt,
            "original_unchanged": result.original_unchanged,
            "seal_sha256": digest(safe_file(root, "seal.json").read_bytes())}
