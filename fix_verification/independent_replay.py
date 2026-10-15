"""Offline C03 consistency replay. Never runs target code or reapplies a patch."""
from __future__ import annotations

import difflib
import json
import re
from pathlib import Path

from agent.verification import register_source_artifacts
from executor.approvals import proposal_digest
from executor.b06_verdicts import evaluate as evaluate_b06
from executor.c03_http_worker import evaluate as evaluate_http
from executor.sandbox_audit import calculate_sha256_digest
from fix_verification.independent import (
    POLICY,
    archived_reports,
    bound_action,
    registered_profile,
    validate_defensive_shape,
)
from fix_verification.scope import SOURCE_COMMIT, load_scope, validate_candidate
from fix_verification.workspace import digest, safe_file, tree_digest
from schemas.b06_verification import B06VerificationResult, profile_digest
from schemas.fix import PatchReviewArtifact
from schemas.independent_fix import C03Artifact
from schemas.security_tools import BoundedVerificationResult
from schemas.target import TargetProfile
from validator.validator import PolicyValidator


def validate_receipt(receipt):
    action, validation, execution = receipt.action, receipt.validation, receipt.execution
    record, event, evidence = receipt.record, receipt.audit, receipt.evidence
    if not validation.approved or validation.action_id != action.id:
        raise ValueError('validator_receipt_mismatch')
    if (record.get('id') != execution.evidence_ref
            or execution.audit_ref != 'audit:' + execution.run_id
            or evidence.sandbox_session_id != record.get('session_id')
            or not {execution.evidence_ref, execution.audit_ref} <= set(evidence.artifact_refs)):
        raise ValueError('receipt_provenance_mismatch')
    for field, expected in {'action_id': action.id, 'tool': action.tool, 'target': action.target,
                            'run_id': execution.run_id, 'status': execution.status,
                            'exit_code': execution.exit_code, 'stdout': execution.stdout,
                            'stderr': execution.stderr, 'timed_out': execution.timed_out,
                            'endpoint': action.endpoint}.items():
        if record.get(field) != expected:
            raise ValueError('execution_record_mismatch:' + field)
    if execution.action_id != action.id or record.get('action_digest') != proposal_digest(action):
        raise ValueError('action_digest_mismatch')
    stored = {k: v for k, v in record.items() if k not in {'id', 'type', 'created_at'}}
    for field, expected in {'action_id': action.id, 'tool': action.tool, 'target': action.target,
                            'run_id': execution.run_id, 'status': execution.status,
                            'exit_code': execution.exit_code, 'evidence_ref': execution.evidence_ref,
                            'session_id': record.get('session_id'), 'runtime_backend': 'docker',
                            'proposal_digest': proposal_digest(action),
                            'policy_digest': calculate_sha256_digest(record.get('policy')),
                            'evidence_digest': calculate_sha256_digest(stored)}.items():
        if event.get(field) != expected:
            raise ValueError('audit_receipt_mismatch:' + field)
    if (evidence.action_id != action.id or evidence.action.id != action.id
            or evidence.action.run_id != execution.run_id
            or evidence.action.tool != action.tool or evidence.scope.target != action.target
            or evidence.scope.service != action.service
            or evidence.scope.environment != action.environment):
        raise ValueError('evidence_receipt_mismatch')
    binding = action.verification_binding
    if binding is not None:
        if record.get('verification_binding') != binding.model_dump(mode='json'):
            raise ValueError('source_binding_record_mismatch')
        if (action.tool != binding.tool or action.endpoint != binding.endpoint
                or action.service != binding.service):
            raise ValueError('source_binding_action_mismatch')


def canonical_verdict(receipt):
    """Reinterpret the original registered capability, never a saved verdict."""
    action, execution, record = receipt.action, receipt.execution, receipt.record
    if execution.status != 'completed' or execution.exit_code != 0 or execution.timed_out:
        return 'inconclusive'
    if receipt.evidence.source != 'runtime' or receipt.evidence.reliability != 'high':
        return 'inconclusive'
    if action.tool == 'verify_sql_injection':
        from evidence.interpreter import _bounded_result_matches_action
        payload = BoundedVerificationResult.model_validate_json(record['stdout'])
        if not _bounded_result_matches_action(payload, action):
            return 'inconclusive'
        return payload.verdict
    if action.tool == 'verify_redirect_destination':
        payload = B06VerificationResult.model_validate_json(record['stdout'])
        if (payload.binding != action.fixture_binding or payload.action_digest != proposal_digest(action)
                or record.get('fixture_binding') != payload.binding.model_dump(mode='json')
                or record['session_id'] != payload.binding.session_id
                or payload.binding.source_snapshot != action.verification_binding.source_snapshot):
            return 'inconclusive'
        return evaluate_b06(payload)[0]
    raise ValueError('unexpected_canonical_capability')


def evaluate(package: C03Artifact, directory: Path):
    """Return deterministic status/reason, or reject inconsistent evidence."""
    inputs, result = package.inputs, package.result
    if not inputs.get('scope_valid'):
        if package.receipts or result.applied:
            raise ValueError('runtime_without_scope')
        return result.status, 'preflight_failed'
    load_scope()
    profile = TargetProfile.model_validate(inputs['profile'])
    if profile_digest(profile) != profile_digest(registered_profile(
            package.family, profile.repository_path, profile.fix_verification.image)):
        raise ValueError('operator_profile_mismatch')
    if inputs['policy_sha256'] != digest(POLICY.read_bytes()) or result.policy_sha256 != inputs['policy_sha256']:
        raise ValueError('policy_changed')
    review = PatchReviewArtifact.model_validate(inputs['review'])
    validate_defensive_shape(package.family, review)
    historical = [r for r in archived_reports(package.family) if r.finding_id == result.original_finding.id
                  and r.finding == result.original_finding]
    if not historical or inputs['source_commit'] != SOURCE_COMMIT or result.original_commit != SOURCE_COMMIT:
        raise ValueError('original_family_or_commit_mismatch')
    if (digest(review.proposal.model_dump_json().encode()) != review.proposal_sha256
            or review.proposal != result.proposed_patch or review.proposal_sha256 != result.proposal_sha256
            or digest(review.proposal.unified_diff.encode()) != result.patch_sha256
            or review.source_sha256 != result.original_file_sha256):
        raise ValueError('proposal_digest_mismatch')
    if inputs['source_manifest'] != inputs.get('original_after_manifest'):
        return 'INCONCLUSIVE', 'original_changed'
    if tree_digest(inputs['source_manifest']) != result.original_tree_sha256:
        raise ValueError('original_manifest_mismatch')
    if not inputs.get('locks_unchanged') or not result.original_unchanged:
        return 'INCONCLUSIVE', 'integrity_not_proven'
    if not package.receipts:
        return 'INCONCLUSIVE', 'missing_independent_evidence'
    by_id, executions = {}, set()
    for receipt in package.receipts:
        validate_receipt(receipt)
        if receipt.action.id in by_id or receipt.execution.run_id in executions:
            raise ValueError('duplicate_execution')
        by_id[receipt.action.id] = receipt
        executions.add(receipt.execution.run_id)
        # Cross-check the original persisted files, not only manifest duplicates.
        copies = list(directory.glob(f'{result.id}/*/evidence/{receipt.execution.evidence_ref}.json'))
        if len(copies) != 1 or json.loads(copies[0].read_text(encoding='utf-8')) != receipt.record:
            raise ValueError('persisted_execution_mismatch')
        audit_path = copies[0].parent.parent / 'audit.jsonl'
        events = [json.loads(line) for line in audit_path.read_text(encoding='utf-8').splitlines()]
        if sum(e == receipt.audit for e in events) != 1:
            raise ValueError('persisted_audit_mismatch')
    count = 2 if package.family == 'redirect-allowlist' else 1
    before_id, after_id = f'{result.id}-before-security', f'{result.id}-after-security'
    before = by_id.get(before_id)
    if before is None or canonical_verdict(before) != 'confirmed':
        if result.applied:
            raise ValueError('patch_applied_without_confirmed_before')
        return 'INCONCLUSIVE', 'before_not_confirmed'
    if (result.before_evidence is None
            or result.before_evidence.model_dump(mode='json') != before.evidence.model_dump(mode='json')
            or result.before_evidence_sha256 != digest(before.evidence.model_dump_json().encode())):
        raise ValueError('before_evidence_digest_mismatch')
    if ([e.model_dump(mode='json') for e in result.new_evidence]
            != [receipt.evidence.model_dump(mode='json') for receipt in package.receipts]):
        raise ValueError('evidence_inventory_mismatch')
    stage_refs = [r.execution.evidence_ref for r in package.receipts if r.action.tool == 'fix_target_stage']
    if ([s.execution_ref for s in result.stages] != stage_refs or len(set(stage_refs)) != len(stage_refs)):
        raise ValueError('stage_inventory_mismatch')
    for phase in ('before', 'after'):
        source = directory / result.id / phase / 'source'
        if not source.exists():
            return 'INCONCLUSIVE', 'missing_source_snapshot'
        bound_profile = profile.model_copy(update={'repository_path': source})
        bound_profile = register_source_artifacts(bound_profile, [result.original_finding], source)
        expected = bound_action(bound_profile, result.original_finding,
                                expected=before.action.verification_binding if phase == 'after' else None)
        canonical = by_id.get(before_id if phase == 'before' else after_id)
        if canonical is not None and canonical.action.verification_binding != expected.verification_binding:
            raise ValueError('b01_binding_mismatch')
        validator = PolicyValidator.from_yaml(POLICY, target_profile=bound_profile)
        if canonical and canonical.action.fixture_binding:
            validator.fixture_bindings[profile.id] = canonical.action.fixture_binding
        for receipt in package.receipts:
            if (receipt.action.id.startswith(f'{result.id}-{phase}-')
                    and validator.validate(receipt.action) != receipt.validation):
                raise ValueError('validator_replay_mismatch')
        if phase == 'before':
            validate_candidate(family_id=package.family, proposal=review.proposal,
                               source_root=source, source_sha256=review.source_sha256)
        else:
            original = directory / result.id / 'before/source'
            changed = {p.relative_to(source).as_posix() for p in source.rglob('*') if p.is_file()
                       and p.read_bytes() != safe_file(original, p.relative_to(source).as_posix()).read_bytes()}
            # A changed helper may not be the finding's caller; it is still the
            # exact one C01 allowlisted file and must match the reviewed diff.
            if changed != {review.file}:
                raise ValueError('patch_scope_mismatch')
            old = safe_file(original, review.file).read_bytes().decode()
            new = safe_file(source, review.file).read_bytes().decode()
            actual = ''.join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                fromfile='a/' + review.file, tofile='b/' + review.file, n=3))
            if actual != review.proposal.unified_diff or digest(new.encode()) != result.patched_file_sha256:
                raise ValueError('applied_patch_mismatch')
        for generation in range(count):
            stages = ['prepare', 'build', 'tests', 'start', 'smoke']
            if package.family == 'sql-search':
                stages += ['c03_fixture']
            if phase == 'after':
                stages += ['c03_source', 'c03_http']
            for stage in stages:
                receipt = by_id.get(f'{result.id}-{phase}-{generation}-{stage}')
                if receipt is None:
                    return 'INCONCLUSIVE', 'missing_stage:' + phase + ':' + stage
                if receipt.action.parameters != {'adapter': profile.fix_verification.adapter, 'stage': stage}:
                    raise ValueError('stage_command_identity_mismatch')
                if receipt.action.tool != 'fix_target_stage':
                    raise ValueError('stage_capability_mismatch')
                stage_results = [s for s in result.stages if s.execution_ref == receipt.execution.evidence_ref]
                execution = receipt.execution
                expected_status = ('timed_out' if execution.timed_out else 'passed'
                                   if execution.status == 'completed' and execution.exit_code == 0
                                   and receipt.evidence.reliability == 'high' else 'failed')
                if (len(stage_results) != 1 or stage_results[0].stdout != receipt.execution.stdout
                        or stage_results[0].stderr != receipt.execution.stderr
                        or stage_results[0].exit_code != receipt.execution.exit_code
                        or stage_results[0].timed_out != receipt.execution.timed_out
                        or stage_results[0].stage != stage or stage_results[0].phase != phase
                        or stage_results[0].status != expected_status or not stage_results[0].attempted
                        or stage_results[0].profile_id != profile.fix_verification.adapter
                        or stage_results[0].audit_ref != receipt.execution.audit_ref):
                    raise ValueError('stage_receipt_mismatch')
                execution = receipt.execution
                if execution.timed_out:
                    return 'INCONCLUSIVE', 'runtime_timeout:' + stage
                if execution.status != 'completed' or execution.exit_code != 0:
                    return ('REGRESSION' if phase == 'after' else 'INCONCLUSIVE'), 'stage_failed:' + stage
                if stage == 'tests':
                    from fix_verification.native_contract import CONTRACT_SHA256, assess_native
                    markers = [json.JSONDecoder().raw_decode(execution.stdout[m.end():].lstrip())[0]
                               for m in re.finditer('C03 NATIVE CONTRACT ', execution.stdout)]
                    if inputs.get('native_contract_sha256'):
                        if inputs['native_contract_sha256'] != CONTRACT_SHA256 or len(markers) != 1:
                            return 'INCONCLUSIVE', 'native_contract_missing_or_changed'
                        native_reports = [json.JSONDecoder().raw_decode(execution.stdout[m.end():].lstrip())[0]
                                          for m in re.finditer('C03 TEST REPORT ', execution.stdout)]
                        if len(native_reports) != 1:
                            return 'INCONCLUSIVE', 'native_report_missing'
                        accounting = assess_native('C03 TEST REPORT ' + json.dumps(native_reports[0]),
                            family=package.family, phase=phase,
                            files=inputs['source_manifest'], raw_exit_code=markers[0].get('raw_exit_code'))
                        if accounting is None or accounting != markers[0]:
                            return 'INCONCLUSIVE', 'native_contract_unproven'
                    else:
                        reports = [json.loads(text) for text in re.findall(r'C03 TEST REPORT (\{[^\n]+\})', execution.stdout)]
                        expected_files = sorted(name for name in inputs['source_manifest']
                                                if name.startswith('test/server/') and name.endswith('.unit.test.ts'))
                        summary = reports[0].get('summary') if len(reports) == 1 else None
                        counts = summary.get('counts', {}) if summary else {}
                        if (not summary or not summary.get('success') or counts.get('failed') != 0
                                or counts.get('cancelled') != 0 or counts.get('passed', 0) <= 0
                                or counts.get('skipped') != 2 or counts.get('todo') != 0
                                or counts.get('tests') != counts.get('passed', 0) + counts.get('skipped', 0)
                                or not expected_files or reports[0]['files'] != expected_files
                                or len(reports[0]['skipped']) != counts['skipped']):
                            return 'INCONCLUSIVE', 'test_summary_missing_or_failed'
                if stage == 'c03_http':
                    payload = json.loads(execution.stdout)
                    fixture = payload.get('fixture', {})
                    if package.family == 'sql-search':
                        original_fixture = json.loads(by_id[f'{result.id}-before-0-c03_fixture'].execution.stdout)
                        after_fixture = json.loads(by_id[f'{result.id}-after-0-c03_fixture'].execution.stdout)
                        if fixture != original_fixture or fixture != after_fixture:
                            return 'INCONCLUSIVE', 'fixture_dataset_changed'
                    tests = evaluate_http(package.family, payload['observations'], fixture.get('baseline_ids'))
                    if payload['family'] != package.family or payload['tests'] != tests:
                        raise ValueError('independent_http_result_mismatch')
                    if payload['redirect_followed'] or payload['destination_dns']:
                        raise ValueError('external_destination_observed')
                    if any(not t['passed'] for t in tests):
                        return ('REGRESSION' if any(not t['passed'] and t['kind'] == 'functional' for t in tests)
                                else 'NOT_FIXED'), 'independent_http_failed'
                if stage == 'c03_source':
                    payload = json.loads(execution.stdout)
                    prefix = 'sql-' if package.family == 'sql-search' else 'redirect-'
                    tests = [t for t in payload['tests'] if t['id'].startswith(prefix)]
                    if (payload.get('error') or len(tests) != (6 if prefix == 'sql-' else 7)
                            or any(t['status'] != 'passed' for t in tests)):
                        return 'INCONCLUSIVE', 'independent_source_failed'
    after = by_id.get(after_id)
    if after is None:
        return 'INCONCLUSIVE', 'after_missing'
    if (result.after_evidence is None
            or result.after_evidence.model_dump(mode='json') != after.evidence.model_dump(mode='json')
            or result.after_evidence_sha256 != digest(after.evidence.model_dump_json().encode())):
        raise ValueError('after_evidence_digest_mismatch')
    verdict = canonical_verdict(after)
    if verdict == 'confirmed':
        return 'NOT_FIXED', 'after_confirmed'
    if verdict != 'rejected':
        return 'INCONCLUSIVE', 'after_inconclusive'
    if (not result.applied or not result.cleanup_complete or not inputs.get('workspace_cleanup')
            or len(package.lifecycle) != 2
            or {row['phase'] for row in package.lifecycle} != {'before', 'after'}
            or any(not row['cleanup_complete'] or len(row['generations']) != count for row in package.lifecycle)
            or len({g for row in package.lifecycle for g in row['generations']}) != count * 2):
        return 'INCONCLUSIVE', 'cleanup_or_generation_binding_failed'
    for row in package.lifecycle:
        if package.family == 'redirect-allowlist':
            canonical = before if row['phase'] == 'before' else after
            expected_workers = {'cft-c03-b06-' + g for g in canonical.action.fixture_binding.generations}
            workers = row.get('worker_cleanup_proofs', [])
            if (not workers or {p['name'] for p in workers} != expected_workers
                    or any(not p['absent'] or p['exit_code'] != 0 or p['remaining'] for p in workers)):
                return 'INCONCLUSIVE', 'canonical_workers_not_proven_absent'
        proofs = row.get('cleanup_proofs', [])
        if not row.get('canonical_worker_cleanup') or len(proofs) != count:
            return 'INCONCLUSIVE', 'cleanup_proof_missing'
        for generation, proof in zip(row['generations'], proofs, strict=True):
            if (not {generation, generation + '-net'} <= {p['name'] for p in proof}
                    or any(not p['absent'] or p['exit_code'] != 0 or p['remaining'] for p in proof)):
                return 'INCONCLUSIVE', 'owned_resources_not_proven_absent'
    return 'FIXED', 'complete_independent_chain'


def replay(directory):
    directory = Path(directory).resolve(strict=True)
    seal = json.loads(safe_file(directory, 'seal.json').read_text(encoding='utf-8'))
    if seal['schema_version'] != 'cft.c03.seal.v1':
        raise ValueError('seal_schema_mismatch')
    members = {p.relative_to(directory).as_posix() for p in directory.rglob('*') if p.is_file()
               and p != directory / 'seal.json'}
    if members != set(seal['files']) or len(members) > 2000:
        raise ValueError('seal_membership_mismatch')
    for name, expected in seal['files'].items():
        path = safe_file(directory, name)
        if path.stat().st_size > 32 * 1024 * 1024 or digest(path.read_bytes()) != expected:
            raise ValueError('seal_digest_mismatch:' + name)
    package = C03Artifact.model_validate_json(safe_file(directory, 'manifest.json').read_bytes())
    status, reason = evaluate(package, directory)
    if status != package.result.status:
        raise ValueError('saved_verdict_disagrees:' + status + ':' + reason)
    return {'status': status, 'reason': reason, 'seal_sha256': digest((directory / 'seal.json').read_bytes())}
