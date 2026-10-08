"""Evidence-backed fix verification through the canonical Validator and Executor."""
from __future__ import annotations

import tempfile
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic
from uuid import uuid4

from agent.verification import register_source_artifacts
from evidence.audit import JsonlAuditLog
from evidence.guard import evaluate_evidence
from evidence.interpreter import _bounded_result_matches_action, build_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.approvals import InMemoryApprovalStore, proposal_digest
from executor.executor import SafeExecutor
from executor.fix_runtime import DockerFixRuntime
from executor.sandbox_audit import calculate_sha256_digest
from fix_verification.workspace import (
    apply_patch,
    check_review,
    digest,
    original_commit,
    snapshot,
    tree_digest,
)
from schemas.action import ActionProposal
from schemas.fix import (
    FixStageResult,
    FixVerificationArtifact,
    PatchApplicationResult,
    PatchReviewArtifact,
    ProposedPatch,
)
from schemas.report import FinalReport
from schemas.security_tools import BoundedVerificationResult
from schemas.target import TargetProfile
from security.error_redaction import redact_error_message
from validator.validator import PolicyValidator

ROOT = Path(__file__).resolve().parents[1]


def trusted_action(finding, profile: TargetProfile, capability: str) -> ActionProposal:
    """Application/operator fields only; no endpoint inferred from source/model."""
    file, line = finding.file, finding.line_start
    key = f"verification.{file}:{line}"
    if capability not in {"verify_sql_injection", "verify_sensitive_directory"}:
        raise ValueError("Original runtime capability is not supported for fix verification")
    service = profile.resolve_service(file)
    endpoint = profile.metadata.get(key + ".endpoint")
    if service not in profile.services or endpoint not in profile.services[service].runtime_endpoints:
        raise ValueError("Original endpoint/service lacks an operator binding")
    parameters = {"artifact_id": profile.artifact_id_for_path(file, kind="javascript"),
                  "line": line, "check": profile.metadata.get(key + ".check", "source_metadata")}
    if capability == "verify_sql_injection":
        parameters["mode"] = profile.metadata.get(key + ".mode")
    return ActionProposal(
        id="original", tool=capability,
        target=profile.id, environment=profile.environment, parameters=parameters,
        service=service, endpoint=endpoint, purpose="Repeat original bounded verification",
        expected_evidence="Persisted structured capability evidence",
    )


def original_binding(report: FinalReport, profile: TargetProfile) -> ActionProposal:
    """Reconstruct operator bindings and match the original observed facts."""
    action = trusted_action(report.finding, profile, report.verification.capability)
    action = action.model_copy(update={"id": report.verification.action_id or "original"})
    if (report.verification.target != profile.id or report.verification.environment != profile.environment
            or report.verification.validator_decision != "approved"):
        raise ValueError("Completed report does not match the approved target")
    for item in report.evidence:
        if (item.action_id != action.id or item.action.tool != action.tool
                or item.verdict != "confirmed" or item.source != "runtime"
                or item.reliability != "high" or item.scope.target != profile.id
                or item.scope.service != action.service or item.scope.environment != profile.environment):
            continue
        payload = BoundedVerificationResult(
            schema="cft.bounded_verification.v1",
            scope=item.scope.description, verdict=item.verdict, explanation=item.summary,
            facts=item.observation.facts.get("facts", {}),
        )
        if _bounded_result_matches_action(payload, action):
            return action
    raise ValueError("Original confirmed Evidence does not match the trusted binding")


class FixVerificationService:
    def confirm_original(self, *, report: FinalReport, profile: TargetProfile,
                         run_id: str, artifact_directory: Path,
                         policy_file: Path = ROOT / "policies/default.yaml") -> FinalReport:
        """Integration bootstrap using exactly the same bounded phase machinery."""
        from schemas.report import VerificationSummary
        if profile.repository_path is None or profile.fix_verification is None:
            raise ValueError("Integration requires the operator-owned fix profile")
        if original_commit(profile.repository_path) != profile.fix_verification.source_commit:
            raise ValueError("Baseline commit differs from the trusted fix profile")
        profile = register_source_artifacts(profile, [report.finding], profile.repository_path)
        action = trusted_action(report.finding, profile, "verify_sql_injection")
        artifact = FixVerificationArtifact(
            id="baseline-" + uuid4().hex, run_id=run_id, original_finding=report.finding,
            original_status="inconclusive", proposed_patch=ProposedPatch(
                finding_id=report.finding_id, rationale="Baseline confirmation, no patch", unified_diff=""),
            patch_application=PatchApplicationResult(status="rejected", detail="No patch during confirmation"),
            verdict="inconclusive", explanation="Baseline only", started_at=datetime.now(UTC),
        )
        try:
            with tempfile.TemporaryDirectory(prefix="cft-baseline-") as temporary:
                copy = Path(temporary) / "target"
                copy.mkdir()
                manifest = snapshot(profile.repository_path, copy)
                if snapshot(copy) != manifest or snapshot(profile.repository_path) != manifest:
                    raise ValueError("Baseline source changed during snapshot")
                isolated = profile.model_copy(update={"repository_path": copy})
                evidence = self._phase(isolated, action, "before", artifact, artifact_directory, policy_file)
                if snapshot(profile.repository_path) != manifest:
                    raise ValueError("Original source changed during baseline confirmation")
        finally:
            artifact.finished_at = datetime.now(UTC)
            artifact.duration_ms = int((artifact.finished_at - artifact.started_at).total_seconds() * 1000)
            directory = Path(artifact_directory)
            directory.mkdir(parents=True, exist_ok=True)
            (directory / "baseline-environment.json").write_text(artifact.model_dump_json(indent=2), encoding="utf-8")
        if evidence is None or evidence.verdict != "confirmed" or not artifact.cleanup_complete:
            failed = [s for s in artifact.stages if s.status != "passed"]
            detail = f"{failed[-1].stage}: {failed[-1].stderr or failed[-1].stdout}" if failed else "Security Evidence or cleanup was insufficient"
            raise RuntimeError("Original confirmation failed: " + detail)
        return report.model_copy(update={
            "status": "confirmed", "evidence": [evidence],
            "verification": VerificationSummary(action_id=evidence.action_id, capability=action.tool,
                target=profile.id, environment=profile.environment, validator_decision="approved",
                evidence_count=1, evidence_types=[evidence.type], decision_basis="capability_specific_evidence"),
            "explanation": evidence.summary,
        })

    def verify(self, *, report: FinalReport, review: PatchReviewArtifact,
               profile: TargetProfile, artifact_directory: Path,
               policy_file: Path = ROOT / "policies/default.yaml") -> FixVerificationArtifact:
        if report.status != "confirmed":
            raise ValueError("Fix verification requires a CONFIRMED finding")
        # Freeze caller-owned models across the long BEFORE phase. A concurrent
        # proposal replacement must never change the patch that passed review.
        report = report.model_copy(deep=True)
        review = review.model_copy(deep=True)
        profile = profile.model_copy(deep=True)
        started = monotonic()
        artifact = FixVerificationArtifact(
            id="fix-" + uuid4().hex, run_id=review.run_id,
            original_finding=report.finding, original_status=report.status,
            proposed_patch=review.proposal, proposal_sha256=review.proposal_sha256,
            patch_sha256=digest(review.proposal.unified_diff.encode()),
            original_file_sha256=review.source_sha256,
            patch_application=PatchApplicationResult(status="rejected", detail="Not applied"),
            verdict="inconclusive", explanation="Verification not completed",
            started_at=datetime.now(UTC), policy_sha256=digest(policy_file.read_bytes()),
        )
        original_manifest = None
        source = profile.repository_path
        try:
            if source is None or not source.is_dir():
                raise ValueError("Original target checkout is unavailable")
            check_review(review, source, report.finding_id, review.run_id, report.finding.file)
            if profile.fix_verification is None:
                raise RuntimeError("Configure a digest-pinned fix image in TargetProfile.fix_verification")
            artifact.original_commit = original_commit(source)
            if artifact.original_commit != profile.fix_verification.source_commit:
                raise ValueError("Target commit differs from the trusted fix profile")
            profile = register_source_artifacts(profile, [report.finding], source)
            action = original_binding(report, profile)
            artifact.trusted_binding = {k: v for k, v in action.model_dump().items()
                                        if k in {"tool", "target", "environment", "parameters", "service", "endpoint"}}
            with tempfile.TemporaryDirectory(prefix="cft-fix-") as temporary:
                workspace = Path(temporary) / "target"
                workspace.mkdir()
                artifact.workspace_id = artifact.id
                original_manifest = snapshot(source, workspace)
                artifact.original_tree_sha256 = tree_digest(original_manifest)
                if snapshot(source) != original_manifest or snapshot(workspace) != original_manifest:
                    raise ValueError("Source changed while creating the isolated snapshot")
                isolated = profile.model_copy(update={"repository_path": workspace})
                check_review(review, workspace, report.finding_id, review.run_id, report.finding.file)
                before = self._phase(isolated, action, "before", artifact, artifact_directory, policy_file)
                artifact.before_evidence = before
                artifact.before_evidence_sha256 = digest(before.model_dump_json().encode()) if before else None
                if before is None or before.verdict != "confirmed":
                    artifact.explanation = "Original vulnerability was not reproduced; no fix claim is possible"
                else:
                    check_review(review, workspace, report.finding_id, review.run_id, report.finding.file)
                    artifact.patched_file_sha256 = apply_patch(workspace, review.proposal.unified_diff, review.file)
                    artifact.applied = True
                    artifact.patch_application = PatchApplicationResult(status="applied", detail="Applied only in disposable snapshot")
                    after = self._phase(isolated, action, "after", artifact, artifact_directory, policy_file)
                    artifact.after_evidence = after
                    artifact.after_evidence_sha256 = digest(after.model_dump_json().encode()) if after else None
                    if after and after.verdict == "rejected":
                        artifact.status = "FIXED"
                        artifact.explanation = "Original bounded probe is rejected after patch; build, tests and functional checks passed"
                    elif after and after.verdict == "confirmed":
                        artifact.status = "NOT_FIXED"
                        artifact.explanation = "The exact original capability still confirms the vulnerability"
                    else:
                        failed = [s for s in artifact.stages if s.phase == "after" and s.status == "failed"]
                        artifact.status = "REGRESSION" if failed else "INCONCLUSIVE"
                        artifact.explanation = "Required build/tests/startup failed" if failed else "After verification did not produce conclusive Evidence"
                expected = dict(original_manifest)
                if artifact.applied:
                    expected[review.file] = (artifact.patched_file_sha256, original_manifest[review.file][1])
                if snapshot(workspace) != expected:
                    raise ValueError("Unexpected changes in the isolated patch scope")
        except ValueError as exc:
            artifact.status = "REJECTED"
            artifact.explanation = redact_error_message(str(exc))
        except (RuntimeError, OSError, TimeoutError) as exc:
            artifact.status = "INCONCLUSIVE"
            artifact.explanation = redact_error_message(str(exc))
        finally:
            if original_manifest is not None and source is not None:
                try:
                    artifact.original_unchanged = snapshot(source) == original_manifest
                except (OSError, ValueError):
                    artifact.original_unchanged = False
            if artifact.status == "FIXED" and not (artifact.original_unchanged and artifact.cleanup_complete):
                artifact.status = "INCONCLUSIVE"
                artifact.explanation = "Original snapshot integrity or runtime cleanup could not be proven"
            artifact.security_verified = artifact.status == "FIXED"
            artifact.verdict = "verified" if artifact.security_verified else "not_verified" if artifact.status in {"REJECTED", "NOT_FIXED", "REGRESSION"} else "inconclusive"
            artifact.finished_at = datetime.now(UTC)
            artifact.duration_ms = int((monotonic() - started) * 1000)
        return FixVerificationArtifact.model_validate(artifact.model_dump())

    def _phase(self, profile, original_action, phase, artifact, directory, policy_file):
        runtime = DockerFixRuntime(profile)
        elapsed = (datetime.now(UTC) - artifact.started_at).total_seconds()
        runtime.deadline = monotonic() + profile.fix_verification.wall_clock_budget_seconds - elapsed
        approvals = InMemoryApprovalStore()
        directory = Path(directory) / artifact.id / phase
        store = JsonExecutionEvidenceStore(directory / "evidence")
        audit = JsonlAuditLog(directory / "audit.jsonl")
        executor = SafeExecutor.from_config(
            approvals=approvals, policy_file=policy_file, target_profile=profile,
            evidence_directory=store.directory, audit_log_path=audit.path,
            workspace_directory=directory / "workspaces", backend_override="docker",
        )
        validator = PolicyValidator.from_yaml(policy_file, target_profile=profile)
        try:
            runtime.open()
            executor.bind_fix_runtime(runtime)
            for stage in ("prepare", "build", "tests", "start", "smoke"):
                if monotonic() >= runtime.deadline:
                    raise TimeoutError("Fix verification wall-clock budget exhausted")
                action = ActionProposal(id=f"{artifact.id}-{phase}-{stage}", tool="fix_target_stage",
                    target=profile.id, environment=profile.environment,
                    parameters={"adapter": profile.fix_verification.adapter, "stage": stage},
                    purpose="Run the registered isolated fix stage", expected_evidence="Persisted bounded stage result")
                execution, evidence = self._execute(action, executor, approvals, validator, store, audit)
                status = "timed_out" if execution.timed_out else "passed" if evidence.reliability == "high" and execution.status == "completed" else "failed" if execution.exit_code not in {124, 126, 127} else "error"
                result = FixStageResult(phase=phase, stage=stage, profile_id=profile.fix_verification.adapter,
                    status=status, exit_code=execution.exit_code, timed_out=execution.timed_out,
                    stdout=execution.stdout, stderr=execution.stderr, duration_ms=execution.duration_ms,
                    execution_ref=execution.evidence_ref, audit_ref=execution.audit_ref,
                    network_mode=audit.records()[-1]["network_mode"])
                artifact.stages.append(result)
                artifact.new_evidence.append(evidence)
                if result.status != "passed":
                    return None
            action = original_action.model_copy(update={"id": f"{artifact.id}-{phase}-security", "iteration": 1})
            if monotonic() >= runtime.deadline:
                raise TimeoutError("Fix verification wall-clock budget exhausted")
            execution, evidence = self._execute(action, executor, approvals, validator, store, audit,
                                                runtime.runtime_services())
            artifact.new_evidence.append(evidence)
            guard = evaluate_evidence({"proposed_action": action, "execution": execution,
                                       "evidence": [evidence], "max_steps": 1, "iteration_count": 1})
            return evidence if guard and guard.status in {"confirmed", "rejected"} else None
        finally:
            clean = runtime.close()
            artifact.cleanup_complete = clean and (artifact.cleanup_complete or phase == "before")

    @staticmethod
    def _execute(action, executor, approvals, validator, store, audit, runtime_services=None):
        validation = validator.validate(action)
        if not validation.approved:
            raise ValueError("Validator denied fix action: " + validation.reason)
        approvals.record(action, validation)
        execution = executor.execute_sequence([action], runtime_services=runtime_services).results[0].execution
        record = store.get_execution(execution.evidence_ref)
        events = [event for event in audit.records() if event.get("run_id") == execution.run_id]
        valid = (
            execution.action_id == action.id and record.get("action_id") == action.id
            and record.get("run_id") == execution.run_id and record.get("tool") == action.tool
            and record.get("target") == action.target and record.get("action_digest") == proposal_digest(action)
            and record.get("status") == execution.status and record.get("exit_code") == execution.exit_code
            and record.get("stdout") == execution.stdout and record.get("stderr") == execution.stderr
            and len(events) == 1 and events[0].get("proposal_digest") == proposal_digest(action)
            and events[0].get("evidence_ref") == execution.evidence_ref
            and events[0].get("evidence_digest") == calculate_sha256_digest({k: v for k, v in record.items() if k not in {"id", "type", "created_at"}})
            and events[0].get("runtime_backend") == "docker"
        )
        if not valid:
            raise RuntimeError("Executor/Evidence/audit binding mismatch")
        evidence = build_evidence(action=action, execution=execution, record=record,
            evidence_loaded=valid, artifact_refs=[execution.evidence_ref, execution.audit_ref],
            hypothesis_id="fix:" + action.id, sandbox_session_id=record.get("session_id"))
        return execution, evidence
