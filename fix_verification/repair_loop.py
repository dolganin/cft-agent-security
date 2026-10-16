"""Bounded C02 -> C03 orchestration. Target code executes only inside C03 Docker."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from agent.budget import provider_deadline
from agent.llm import ProviderFailoverClient
from app.independent_fix import run as verify_patch
from app.stage1_e2e import pinned_image
from executor.access_fixture import TARGET_IMAGE
from executor.c03_runtime import WORKER_IMAGE
from fix_verification.generation import generate, write_json
from fix_verification.independent_replay import replay as replay_verification
from fix_verification.patch_context import original_input
from fix_verification.repair_feedback import feedback_for
from fix_verification.scope import SOURCE_COMMIT, load_scope
from fix_verification.workspace import apply_patch, digest, safe_file, snapshot
from sast.profiles import validate_target_snapshot
from schemas.repair_loop import RepairAttempt, RepairLimits, RepairRun


def event(directory: Path, kind: str, **fields):
    value = {"time": datetime.now(UTC).isoformat(), "kind": kind, **fields}
    with (directory / "events.jsonl").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def seal(directory: Path):
    members = {}
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("Linked bundle member")
        if path.is_file() and path != directory / "seal.json":
            members[path.relative_to(directory).as_posix()] = digest(path.read_bytes())
    write_json(directory / "seal.json", {"schema_version": "cft.c04.seal.v1", "files": members})


def fresh_copy(source: Path, destination: Path, expected: dict):
    """Clone objects without checkout hooks/filters; copy verified source as data."""
    environment = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    environment.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
                       GIT_TERMINAL_PROMPT="0")
    subprocess.run(["git", "clone", "--local", "--no-hardlinks", "--no-checkout",
                    "--config", "core.autocrlf=false", "--config", "core.hooksPath=" + os.devnull,
                    str(source), str(destination)], env=environment, capture_output=True,
                   check=True, timeout=60)
    snapshot(source, destination)
    # Operator provisioning keeps its Compose file in the local excludes. The
    # data snapshot copies that file too; preserve only ignore data, never Git
    # hooks/configuration, so a prepared clean source remains clean in the clone.
    exclude = source / ".git/info/exclude"
    if exclude.exists():
        raw = safe_file(source, ".git/info/exclude").read_bytes()
        if len(raw) > 65536:
            raise ValueError("Local exclude data exceeds budget")
        (destination / ".git/info/exclude").write_bytes(raw)
    subprocess.run(["git", "-C", str(destination), "read-tree", SOURCE_COMMIT],
                   env=environment, capture_output=True, check=True, timeout=30)
    if validate_target_snapshot(destination, SOURCE_COMMIT) != expected:
        raise ValueError("Attempt copy does not match frozen source")


def candidate_fingerprint(source: Path, review, directory: Path):
    """Data-only patch on a second scratch file; never change the attempt's source."""
    original = safe_file(source, review.file).read_bytes()
    with tempfile.TemporaryDirectory(prefix="cft-c04-fingerprint-") as temporary:
        root = Path(temporary)
        file = root / review.file
        file.parent.mkdir(parents=True)
        file.write_bytes(original)
        patched = apply_patch(root, review.proposal.unified_diff, review.file)
    candidate = {"file": review.file, "source_sha256": review.source_sha256,
                 "patch_sha256": digest(review.proposal.unified_diff.encode()),
                 "patched_file_sha256": patched, "proposal_sha256": review.proposal_sha256}
    write_json(directory / "candidate.json", candidate)
    return candidate


def decide_generation(generation, number):
    statuses = {a.get("status") for a in generation.provider_attempts}
    if generation.status == "failed" and statuses and statuses <= {"schema_validation_failed", "invalid_structured_output"}:
        return "retry", "invalid_structured_output", feedback_for(number, "generation", "invalid_structured_output")
    feedback = feedback_for(number, "generation", generation.reason)
    if generation.status == "rejected" and feedback is not None:
        return "retry", generation.reason, feedback
    if generation.status == "rejected":
        return "stop", "proposal_rejected", None
    return "stop", "generation_failed", None


def decide_verification(package, number, patch_sha256, *, detailed=True):
    result = package.result
    if not result.original_unchanged or not result.cleanup_complete:
        return "stop", "verification_integrity_or_cleanup_failed", None
    if result.status == "FIXED":
        return "fixed", "independently_verified", None
    # BEFORE failure and technical AFTER failures must not train the next patch.
    conclusive_before = result.before_evidence and result.before_evidence.verdict == "confirmed"
    functional_regression = result.status == "REGRESSION" and any(
        s.phase == "after" and s.status == "failed" and not s.timed_out
        and s.stage in {"build", "tests"} for s in result.stages)
    if conclusive_before and (result.status == "NOT_FIXED" or functional_regression):
        code = result.status
        if functional_regression and detailed:
            failed = next(s for s in result.stages if s.phase == "after" and s.status == "failed"
                          and not s.timed_out and s.stage in {"build", "tests"})
            code = "AFTER_BUILD_FAILED" if failed.stage == "build" else "AFTER_TESTS_FAILED"
        feedback = feedback_for(number, "verification", code, patch_sha256)
        return "retry", result.status, feedback
    return "stop", "verification_incomplete", None


def run(*, target: Path, family: str, output: Path, client: ProviderFailoverClient,
        limits: RepairLimits | None = None, fix_image: str = "cft-fix-juice:stage1") -> RepairRun:
    if not isinstance(client, ProviderFailoverClient):
        raise TypeError("C04 requires ProviderFailoverClient")
    if len(client.routes) != 1:
        raise ValueError("C04 requires one operator-selected provider route")
    limits = limits or RepairLimits()
    source, directory = target.resolve(strict=True), output.resolve()
    if directory.is_relative_to(source) or source.is_relative_to(directory):
        raise ValueError("C04 artifacts must be outside the original target")
    directory.mkdir(parents=True, exist_ok=False)
    result = RepairRun(family=family, limits=limits, started_at=datetime.now(UTC))
    started = monotonic()
    deadline = started + limits.wall_clock_seconds
    # Cleanup has existing fixed transport timeouts and must run even after this work deadline.
    feedback = None
    previous_review = None
    seen_response, seen_patch, seen_effect = set(), set(), set()
    active_copy = None
    current = None
    try:
        write_json(directory / "configuration.json", {
            "family": family, "limits": limits.model_dump(mode="json"),
            "routes": [r.label for r in client.routes], "source_commit": SOURCE_COMMIT,
            "feedback_contract": "cft.c04.feedback.v2",
            "python_version": sys.version.split()[0],
            "original_path": str(source),
        })
        result.original_snapshot = validate_target_snapshot(source, SOURCE_COMMIT)
        write_json(directory / "original-snapshot.json", result.original_snapshot)
        _spec, report, report_sha, archived = original_input(family)
        if result.original_snapshot != archived:
            raise ValueError("Source differs from eligible finding snapshot")
        write_json(directory / "original-report.json", report.model_dump(mode="json"))
        image = pinned_image(fix_image)
        engine = subprocess.run(["docker", "info", "--format", "{{.OSType}}"], capture_output=True,
                                check=True, timeout=20)
        if engine.stdout.strip() not in {"linux", b"linux"}:
            raise ValueError("Linux Docker engine is required")
        for required in (WORKER_IMAGE, TARGET_IMAGE):
            subprocess.run(["docker", "image", "inspect", required], capture_output=True,
                           check=True, timeout=20)
        write_json(directory / "runtime.json", {"fix_image": image, "worker_image": WORKER_IMAGE,
                                                "target_image": TARGET_IMAGE,
                                                "original_report_sha256": report_sha})
        event(directory, "preflight_passed")
        for number in range(1, limits.max_attempts + 1):
            if monotonic() >= deadline:
                result.stop_reason = "wall_clock_exhausted"
                break
            if validate_target_snapshot(source, SOURCE_COMMIT) != result.original_snapshot:
                raise ValueError("Original changed between attempts")
            load_scope()
            attempt_directory = directory / "attempts" / f"{number:03d}"
            attempt_directory.mkdir(parents=True)
            current = RepairAttempt(number=number, directory=f"attempts/{number:03d}",
                                    started_at=datetime.now(UTC))
            result.attempts.append(current)
            attempt_started = monotonic()
            event(directory, "attempt_started", attempt=number)
            try:
                with tempfile.TemporaryDirectory(prefix="cft-c04-") as temporary:
                    active_copy = Path(temporary) / "source"
                    fresh_copy(source, active_copy, result.original_snapshot)
                    current.source_snapshot = validate_target_snapshot(active_copy, SOURCE_COMMIT)
                    phase = monotonic()
                    with provider_deadline(deadline):
                        generated = generate(repository=active_copy, family=family,
                                             output=attempt_directory / "generation", client=client,
                                             feedback=feedback, previous_review=previous_review)
                    current.generation_ms = int((monotonic() - phase) * 1000)
                    current.generation_status = generated.status
                    current.generation_reason = generated.reason
                    current.response_patch_sha256 = generated.response_patch_sha256
                    if not generated.original_unchanged:
                        raise ValueError("Generation lost source integrity")
                    if monotonic() >= deadline:
                        current.decision, current.reason = "stop", "wall_clock_exhausted"
                    elif generated.response_patch_sha256 and generated.response_patch_sha256 in seen_response:
                        current.decision, current.reason = "duplicate", "duplicate_patch"
                    elif generated.status != "ready_for_review":
                        current.decision, current.reason, current.feedback = decide_generation(generated, number)
                    else:
                        review = generated.review
                        if review is None:
                            raise ValueError("Ready generation is missing its review")
                        candidate = candidate_fingerprint(active_copy, review, attempt_directory)
                        current.patch_sha256 = candidate["patch_sha256"]
                        current.patched_file_sha256 = candidate["patched_file_sha256"]
                        if current.patch_sha256 in seen_patch or current.patched_file_sha256 in seen_effect:
                            current.decision, current.reason = "duplicate", "duplicate_patch"
                        elif monotonic() >= deadline:
                            current.decision, current.reason = "stop", "wall_clock_exhausted"
                        else:
                            phase = monotonic()
                            package = verify_patch(family=family, target=active_copy,
                                output=attempt_directory / "verification", fix_image=image,
                                report=report, review=review, deadline_monotonic=deadline)
                            current.verification_ms = int((monotonic() - phase) * 1000)
                            # Replay the persisted receipt chain, never trust status alone.
                            checked = replay_verification(attempt_directory / "verification")
                            if checked["status"] != package.result.status:
                                raise ValueError("Verifier replay disagrees")
                            if package.result.proposal_sha256 != review.proposal_sha256:
                                raise ValueError("Verifier checked a different proposal")
                            current.verification_status = checked["status"]
                            current.decision, current.reason, current.feedback = decide_verification(
                                package, number, current.patch_sha256)
                            if monotonic() >= deadline:
                                current.decision, current.reason, current.feedback = "stop", "wall_clock_exhausted", None
                    seen_response.add(generated.response_patch_sha256)
                    seen_patch.add(current.patch_sha256)
                    seen_effect.add(current.patched_file_sha256)
                    if validate_target_snapshot(active_copy, SOURCE_COMMIT) != result.original_snapshot:
                        raise ValueError("Attempt source was modified")
            except KeyboardInterrupt:
                current.decision, current.reason = "stop", "operator_interrupted"
                raise
            except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
                current.decision, current.reason = "stop", "attempt_failed"
                raise
            finally:
                current.workspace_cleanup = active_copy is not None and not active_copy.exists()
                current.finished_at = datetime.now(UTC)
                current.duration_ms = int((monotonic() - attempt_started) * 1000)
                if not current.workspace_cleanup:
                    current.decision, current.reason = "stop", "workspace_cleanup_failed"
                if current.feedback is not None:
                    write_json(attempt_directory / "feedback.json", current.feedback.model_dump(mode="json"))
                write_json(attempt_directory / "attempt.json", current.model_dump(mode="json"))
                event(directory, "attempt_finished", attempt=number, decision=current.decision,
                      reason=current.reason)
            if current.decision == "fixed":
                result.status, result.stop_reason = "FIXED", current.reason
                result.successful_attempt = number
                break
            if current.decision == "duplicate":
                result.status, result.stop_reason = "NOT_FIXED", "duplicate_patch"
                break
            if current.decision == "stop":
                result.status = "NOT_FIXED" if current.reason == "proposal_rejected" else "TECHNICAL_ERROR"
                result.stop_reason = current.reason
                break
            feedback = current.feedback
            previous_review = generated.review if current.verification_status is not None else None
        else:
            result.status, result.stop_reason = "NOT_FIXED", "attempts_exhausted"
    except KeyboardInterrupt:
        result.status, result.stop_reason = "INTERRUPTED", "operator_interrupted"
        raise
    except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
        # Raw exceptions can include private paths/credentials. Persist only a fixed category.
        result.status = "TECHNICAL_ERROR"
        result.stop_reason = ("wall_clock_exhausted" if monotonic() >= deadline
                              else "preflight_or_integrity_failure")
    finally:
        try:
            result.original_unchanged = bool(result.original_snapshot) and (
                validate_target_snapshot(source, SOURCE_COMMIT) == result.original_snapshot)
            load_scope()
        except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
            result.original_unchanged = False
        if not result.original_unchanged:
            result.status, result.stop_reason = "TECHNICAL_ERROR", "original_integrity_failed"
            result.successful_attempt = None
        if result.status != "FIXED":
            result.successful_attempt = None
        result.finished_at = datetime.now(UTC)
        result.duration_ms = int((monotonic() - started) * 1000)
        event(directory, "run_finished", status=result.status, reason=result.stop_reason)
        write_json(directory / "result.json", result.model_dump(mode="json"))
        lines = [f"C04: {result.status}", f"Stop reason: {result.stop_reason}",
                 f"Attempts: {len(result.attempts)}; duration_ms: {result.duration_ms}",
                 f"Original unchanged: {result.original_unchanged}", ""]
        lines += [f"{a.number}: {a.generation_status} -> {a.verification_status or 'not run'}; "
                  f"{a.decision}: {a.reason}" for a in result.attempts]
        (directory / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
        seal(directory)
    return result
