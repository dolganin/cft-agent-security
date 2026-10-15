"""C03 specialization of FixVerificationService; no model or alternate executor."""
from __future__ import annotations

import json
import re
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from time import monotonic

from agent.verification import register_source_artifacts
from evidence.audit import JsonlAuditLog
from evidence.guard import evaluate_evidence
from evidence.store import JsonExecutionEvidenceStore
from executor.access_fixture import TARGET_IMAGE
from executor.approvals import InMemoryApprovalStore
from executor.c03_runtime import WORKER_IMAGE, C03FixRuntime, C03RedirectRuntime
from executor.executor import SafeExecutor
from fix_verification.patch_guard import defensive_shape
from fix_verification.review import validate_sequelize_search_proposal
from fix_verification.scope import (
    BASELINE,
    SOURCE_COMMIT,
    assess_scope,
    load_scope,
    validate_candidate,
)
from fix_verification.service import ROOT, FixVerificationService
from fix_verification.workspace import check_review, digest, original_commit, safe_file, snapshot
from sast.profiles import validate_target_snapshot
from schemas.action import ActionProposal
from schemas.b06_verification import profile_digest
from schemas.finding import Finding
from schemas.fix import FixStageResult, FixVerificationArtifact, ProposedPatch
from schemas.report import FinalReport
from schemas.target import TargetFixConfig, TargetProfile, TargetRuntimeConfig
from security.error_redaction import redact_observation
from security.verification_binding import resolve_binding, source_snapshot
from validator.validator import PolicyValidator

POLICY = ROOT / 'policies/c03.yaml'


def validate_defensive_shape(family, review):
    """Conservative C03 source grammar, in addition to C01 scope.

    A one-file allowlist alone would allow process.exit/VM escapes that forge
    target test output. C03 accepts minimal data-binding/comparison rewrites;
    unsupported larger rewrites are rejected rather than executed as evaluators.
    """
    lines = review.proposal.unified_diff.splitlines()
    removed = [s[1:].split(' //', 1)[0].strip() for s in lines if s.startswith('-') and not s.startswith('---')]
    added = [s[1:].split(' //', 1)[0].strip() for s in lines if s.startswith('+') and not s.startswith('+++')]
    if family == 'sql-search':
        stripped = '\n'.join(s.split(' //', 1)[0] if s.startswith(('+', '-')) else s for s in lines)
        try:
            validate_sequelize_search_proposal(stripped)
        except ValueError as error:
            raise ValueError('unsupported_defensive_sql_shape: ' + str(error)) from error
    elif (family == 'redirect-allowlist' and (removed, added) == (
        ['if (security.isRedirectAllowed(toUrl)) {'], ['if (security.redirectAllowlist.has(toUrl)) {']
    )):
        return
    else:
        # Share C02's exact helper grammar: operand order, whitespace and an
        # optional semicolon cannot change eligibility at the C03 boundary.
        # The route-only alternative remains subject to the independent oracle.
        try:
            defensive_shape(family, review.proposal.unified_diff)
        except ValueError as error:
            raise ValueError('unsupported_defensive_redirect_shape') from error



def registered_profile(family, source, image):
    if family not in {'sql-search', 'redirect-allowlist'}:
        raise ValueError('unknown_family')
    sql = TargetProfile.from_yaml(ROOT / 'targets/juice-verification.yaml', repository_path_override=source)
    redirect = TargetProfile.from_yaml(ROOT / 'targets/juice-b06-verification.yaml')
    route = next(r for r in (sql.verification_routes if family == 'sql-search' else redirect.verification_routes)
                 if r.tool == ('verify_sql_injection' if family == 'sql-search' else 'verify_redirect_destination')
                 and r.endpoint == ('/rest/products/search' if family == 'sql-search' else '/redirect'))
    service = sql.services['juice'].model_copy(update={
        'compose_service': None, 'runtime_endpoints': ['/', route.endpoint]})
    return TargetProfile(id='c03-' + family, name='C03 independent patch verification',
        repository_path=source, environment='sandbox',
        runtime=TargetRuntimeConfig(type='operator_c03_fix'), services={'juice': service},
        b06_verification=redirect.b06_verification if family == 'redirect-allowlist' else None,
        verification_routes=[route], fix_verification=TargetFixConfig(
            family=family, image=image, service='juice', source_commit=SOURCE_COMMIT,
            timeout_seconds=300, wall_clock_budget_seconds=3600))


def archived_reports(family):
    """The C01 lock authenticates the exact archive before any member is read."""
    load_scope()
    eligibility = next(e for e in assess_scope().entries if e.family_id == family)
    if eligibility.status != 'eligible':
        raise ValueError('c01_ineligible_finding')
    with zipfile.ZipFile(BASELINE) as zipped:
        result = []
        for name in zipped.namelist():
            if name.startswith('b09-single-2026-10-15-final/pipeline/reports/') and name.endswith('.json'):
                report = FinalReport.model_validate_json(zipped.read(name))
                if report.finding_id in eligibility.finding_ids and report.status == 'confirmed':
                    result.append(report)
        return result


def bound_action(profile, finding, *, expected=None):
    # Re-resolve the real handler AST. AFTER deliberately has a new anchor/hash,
    # justified only by the checked one-file patch applied by the base service.
    item = Finding(id=finding.id, source=finding.source, rule_id=finding.rule_id,
        title=finding.title, description=finding.description or '', file=finding.file,
        line_start=finding.line_start, line_end=finding.line_end)
    resolution = resolve_binding(profile, item)
    binding = resolution.binding
    if binding is None:
        raise ValueError('b01_binding_failed: ' + resolution.reason)
    if expected is not None and any(getattr(binding, k) != getattr(expected, k)
            for k in ('route_id', 'handler_id', 'target', 'finding_id', 'family', 'source_file',
                      'map_sha256', 'service', 'endpoint', 'method', 'tool', 'check', 'mode')):
        raise ValueError('b01_semantics_changed')
    parameters = {'artifact_id': profile.artifact_id_for_path(finding.file, kind='javascript'),
                  'line': binding.line_start, 'check': binding.check}
    if binding.mode is not None:
        parameters['mode'] = binding.mode
    return ActionProposal(id='original', tool=binding.tool, target=profile.id,
        environment=profile.environment, service=binding.service, endpoint=binding.endpoint,
        parameters=parameters, verification_binding=binding,
        purpose='Repeat the exact C01 family security hypothesis',
        expected_evidence='Independent persisted runtime observation with B01 provenance')


class IndependentPatchVerificationService(FixVerificationService):
    """One instance per run. Stage 1's snapshot/apply/integrity loop is reused."""
    def __init__(self, family_id):
        self.family_id = family_id
        self.receipts = []
        self.lifecycle = []
        self.inputs = {}
        self.reason_codes = []
        self.workspaces = set()

    def verify(self, **kwargs):
        if self.inputs:
            raise ValueError('c03_service_is_single_use')
        kwargs.setdefault('policy_file', POLICY)
        self.inputs = {'family': self.family_id}
        result = super().verify(**kwargs)
        try:
            load_scope()
            locks = True
        except (ValueError, OSError):
            locks = False
        if result.status == 'FIXED' and not locks:
            result = result.model_copy(update={'status': 'INCONCLUSIVE', 'security_verified': False,
                'verdict': 'inconclusive', 'explanation': 'c01_lock_changed'})
        self.inputs['locks_unchanged'] = locks
        if not self.inputs.get('scope_valid'):
            # Rejected untrusted prose/diffs must not become a secret archive.
            result = result.model_copy(update={'proposed_patch': ProposedPatch(
                finding_id=report_id if (report_id := result.original_finding.id) else 'rejected',
                rationale='Rejected input; only the original proposal digest is retained', unified_diff='')})
        if self.inputs.get('scope_valid'):
            self.inputs['workspace_cleanup'] = bool(self.workspaces) and all(not p.exists() for p in self.workspaces)
            try:
                self.inputs['original_after_manifest'] = snapshot(kwargs['profile'].repository_path)
            except (OSError, ValueError):
                self.inputs['original_after_manifest'] = None
            from fix_verification.independent_replay import evaluate
            from schemas.independent_fix import C03Artifact
            package = C03Artifact(family=self.family_id, inputs=self.inputs, result=result,
                                  receipts=self.receipts, lifecycle=self.lifecycle)
            try:
                status, reason = evaluate(package, Path(kwargs['artifact_directory']))
            except (ValueError, KeyError, TypeError, OSError) as error:
                status, reason = 'INCONCLUSIVE', 'replay_consistency_failed:' + str(error)
            self.reason_codes = [reason]
            if status == 'FIXED' and result.status != 'FIXED':
                status, reason = 'INCONCLUSIVE', 'verification_state_disagrees'
                self.reason_codes = [reason]
            if status != result.status:
                result = result.model_copy(update={'status': status, 'security_verified': status == 'FIXED',
                    'verdict': 'verified' if status == 'FIXED' else 'inconclusive', 'explanation': reason})
        if result.status == 'FIXED' and self.family_id == 'redirect-allowlist':
            result.explanation = (
                'Canonical AFTER rejected and independent source/HTTP checks passed. '
                'All native tests ran; the protected contract separately accounts for '
                'the two obsolete vulnerability-expectation assertions without hiding failures.'
            )
        return FixVerificationArtifact.model_validate(result.model_dump())

    def _check_review(self, review, source, report):
        # Scope is family-owned; redirect findings may anchor the caller while
        # the allowed patch changes its explicitly registered helper.
        if redact_observation(review.proposal.rationale) != review.proposal.rationale:
            raise ValueError('proposal_contains_sensitive_material')
        canonical = check_review(review, source, report.finding_id, review.run_id, review.file)
        checked = validate_candidate(family_id=self.family_id, proposal=review.proposal,
                                     source_root=source, source_sha256=review.source_sha256)
        if checked != canonical:
            raise ValueError('noncanonical_patch')
        validate_defensive_shape(self.family_id, review)
        return canonical

    def _check_scope(self, profile, review, report):
        specs, _ = load_scope()
        spec = next((s for s in specs if s.id == self.family_id), None)
        if spec is None:
            raise ValueError('unknown_family')
        eligibility = assess_scope()
        eligible = next(e for e in eligibility.entries if e.family_id == self.family_id)
        if eligible.status != 'eligible' or report.finding_id not in eligible.finding_ids:
            raise ValueError('c01_ineligible_finding')
        matches = [r for r in archived_reports(self.family_id) if r == report]
        if not matches or report.verification.capability != spec.capability:
            raise ValueError('original_evidence_not_archived_family')
        if review.file not in spec.allowed_files or report.finding.file not in spec.allowed_files:
            raise ValueError('patch_file_outside_family')
        source = profile.repository_path
        if profile.fix_verification is None:
            raise ValueError('c03_fix_profile_required')
        expected = registered_profile(self.family_id, source, profile.fix_verification.image)
        if profile_digest(expected) != profile_digest(profile):
            raise ValueError('operator_profile_mismatch')
        if original_commit(source) != SOURCE_COMMIT:
            raise ValueError('source_commit_mismatch')
        actual_snapshot = validate_target_snapshot(source, SOURCE_COMMIT)
        with zipfile.ZipFile(BASELINE) as zipped:
            baseline = json.loads(zipped.read(
                'b09-single-2026-10-15-final/run-result.json'))['target_snapshot_after']
        if actual_snapshot != baseline:
            raise ValueError('source_snapshot_mismatch')
        status = subprocess.run(['git', '-C', str(source), 'status', '--porcelain', '--untracked-files=all'],
                                capture_output=True, text=True, timeout=15, check=True)
        if status.stdout.strip():
            raise ValueError('original_checkout_not_clean')
        manifest = snapshot(source)
        if any(Path(name).name.startswith('.env') for name in manifest):
            raise ValueError('sensitive_source_material_requires_operator_exclusion')
        # Prove applicability before Docker mutation using only a tiny data copy.
        import tempfile

        from fix_verification.workspace import apply_patch
        with tempfile.TemporaryDirectory(prefix='cft-c03-preflight-') as temporary:
            root = Path(temporary)
            output = root / review.file
            output.parent.mkdir(parents=True)
            output.write_bytes(safe_file(source, review.file).read_bytes())
            apply_patch(root, review.proposal.unified_diff, review.file)
        self.inputs.update(eligibility=eligibility.model_dump(mode='json'),
            profile=profile.model_dump(mode='json'), review=review.model_dump(mode='json'),
            source_manifest=manifest, source_commit=SOURCE_COMMIT,
            policy_sha256=digest(POLICY.read_bytes()))
        info = subprocess.run(['docker', 'info', '--format', '{{.OSType}}'], capture_output=True,
                              text=True, timeout=20, check=True)
        if info.stdout.strip() != 'linux':
            raise RuntimeError('linux_docker_engine_required')
        for image in (profile.fix_verification.image, WORKER_IMAGE, TARGET_IMAGE):
            subprocess.run(['docker', 'image', 'inspect', image], capture_output=True, timeout=20, check=True)
        from fix_verification.native_contract import CONTRACT_SHA256, load_native_contract
        load_native_contract()
        self.inputs['native_contract_sha256'] = CONTRACT_SHA256
        self.inputs['scope_valid'] = True

    def _original_binding(self, report, profile):
        action = bound_action(profile, report.finding)
        self.inputs['before_binding'] = action.verification_binding.model_dump(mode='json')
        return action

    def _execute(self, action, executor, approvals, validator, store, audit, runtime_services=None):
        validation = validator.validate(action)
        execution, evidence = super()._execute(action, executor, approvals, validator, store, audit, runtime_services)
        record = store.get_execution(execution.evidence_ref)
        event = next(e for e in audit.records() if e['run_id'] == execution.run_id)
        self.receipts.append({'action': action.model_dump(mode='json'),
            'validation': validation.model_dump(mode='json'), 'execution': execution.model_dump(mode='json'),
            'record': record, 'audit': event, 'evidence': evidence.model_dump(mode='json')})
        return execution, evidence

    def _phase(self, profile, original_action, phase, artifact, directory, policy_file):
        self.workspaces.add(profile.repository_path)
        if Path(policy_file).resolve() != POLICY.resolve():
            raise ValueError('c03_requires_registered_policy')
        profile = register_source_artifacts(profile, [artifact.original_finding], profile.repository_path)
        action = bound_action(profile, artifact.original_finding, expected=original_action.verification_binding)
        directory = Path(directory) / artifact.id / phase
        raw_sources, _ = source_snapshot(profile)
        for name, raw in raw_sources.items():
            saved = directory / 'source' / name
            saved.parent.mkdir(parents=True, exist_ok=True)
            saved.write_bytes(raw)
        approvals = InMemoryApprovalStore()
        store = JsonExecutionEvidenceStore(directory / 'evidence')
        audit = JsonlAuditLog(directory / 'audit.jsonl')
        executor = SafeExecutor.from_config(approvals=approvals, policy_file=policy_file,
            target_profile=profile, evidence_directory=store.directory, audit_log_path=audit.path,
            workspace_directory=directory / 'workspaces', backend_override='docker')
        validator = PolicyValidator.from_yaml(policy_file, target_profile=profile)
        count = 2 if self.family_id == 'redirect-allowlist' else 1
        runtimes, redirect = [], None
        canonical_cleanup = True
        try:
            for generation in range(count):
                runtime = C03FixRuntime(profile)
                runtime.phase = phase
                runtimes.append(runtime)  # cleanup even when open/provisioning fails
                runtime.deadline = monotonic() + profile.fix_verification.wall_clock_budget_seconds - (
                    datetime.now(UTC) - artifact.started_at).total_seconds()
                runtime.open()
                executor.bind_fix_runtime(runtime)
                stages = ['prepare', 'build', 'tests', 'start', 'smoke']
                if self.family_id == 'sql-search':
                    stages += ['c03_fixture']
                if phase == 'after':
                    stages += ['c03_source', 'c03_http']
                for stage in stages:
                    if monotonic() >= runtime.deadline:
                        raise TimeoutError('c03_wall_clock_budget_exhausted')
                    proposal = ActionProposal(id=f'{artifact.id}-{phase}-{generation}-{stage}',
                        tool='fix_target_stage', target=profile.id, environment=profile.environment,
                        parameters={'adapter': profile.fix_verification.adapter, 'stage': stage},
                        purpose='Run the operator C03 isolated stage', expected_evidence='Persisted stage observation')
                    execution, evidence = self._execute(proposal, executor, approvals, validator, store, audit)
                    status = ('timed_out' if execution.timed_out else 'passed'
                              if execution.status == 'completed' and execution.exit_code == 0
                              and evidence.reliability == 'high' else 'failed')
                    artifact.stages.append(FixStageResult(phase=phase, stage=stage,
                        profile_id=profile.fix_verification.adapter, status=status,
                        exit_code=execution.exit_code, timed_out=execution.timed_out,
                        stdout=execution.stdout, stderr=execution.stderr, duration_ms=execution.duration_ms,
                        execution_ref=execution.evidence_ref, audit_ref=execution.audit_ref,
                        network_mode=audit.records()[-1]['network_mode']))
                    artifact.new_evidence.append(evidence)
                    if status != 'passed':
                        return None
            action = action.model_copy(update={'id': f'{artifact.id}-{phase}-security'})
            if count == 2:
                redirect = C03RedirectRuntime(profile, runtimes, directory / 'b06')
                redirect.open()
                executor.bind_verification_runtime(redirect)
                validator.fixture_bindings[profile.id] = redirect.binding
                action = action.model_copy(update={'fixture_binding': redirect.binding})
                services = redirect.runtime_map()
            else:
                services = runtimes[0].runtime_services()
            execution, evidence = self._execute(action, executor, approvals, validator, store, audit, services)
            if count == 1:
                record = store.get_execution(execution.evidence_ref)
                worker_id = record.get('workspace_id', '')
                if re.fullmatch(r'[a-f0-9]{64}', worker_id):
                    checked = runtimes[0]._control(['docker', 'ps', '-aq', '--filter', 'id=' + worker_id])
                    canonical_cleanup = checked.exit_code == 0 and not checked.stdout.strip()
                else:
                    canonical_cleanup = False
            artifact.new_evidence.append(evidence)
            if execution.status != 'completed':
                diagnostic = runtimes[0]._control(['docker', 'exec', runtimes[0].id, 'python3', '-c',
                    "from pathlib import Path; print(Path('/workspace/startup.log').read_bytes()[-4096:].decode(errors='replace'))"])
                self.inputs['runtime_diagnostic'] = diagnostic.stdout
            guard = evaluate_evidence({'proposed_action': action, 'execution': execution,
                                      'evidence': [evidence], 'max_steps': 1, 'iteration_count': 1})
            return evidence if guard and guard.status in {'confirmed', 'rejected'} else None
        finally:
            results = [canonical_cleanup]
            for runtime in ([redirect] if redirect is not None else []) + runtimes:
                try:
                    results.append(runtime.close())
                except (OSError, RuntimeError, subprocess.SubprocessError):
                    results.append(False)
            # Completeness of the required generations is separate from actual
            # cleanup. An early mandatory-test failure must still prove that
            # every container it did create has been removed.
            clean = bool(runtimes) and all(results)
            worker_proofs = redirect.worker_cleanup_proofs if redirect is not None else []
            if redirect is not None:
                canonical_cleanup = bool(worker_proofs) and all(p['absent'] for p in worker_proofs)
                clean &= canonical_cleanup
            self.lifecycle.append({'phase': phase, 'generations': [r.id for r in runtimes],
                                   'cleanup_complete': clean, 'canonical_worker_cleanup': canonical_cleanup,
                                   'worker_cleanup_proofs': worker_proofs,
                                   'cleanup_proofs': [r.cleanup_proof for r in runtimes]})
            artifact.cleanup_complete = clean and (artifact.cleanup_complete or phase == 'before')
