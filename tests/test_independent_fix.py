"""C03 trust boundaries and independent oracles, without Docker requirements."""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_fix_verification import fixture, sql_output

from executor.approvals import proposal_digest
from executor.c03_http_worker import cases, evaluate
from executor.sandbox_audit import calculate_sha256_digest
from fix_verification.independent import (
    IndependentPatchVerificationService,
    bound_action,
    registered_profile,
    validate_defensive_shape,
)
from fix_verification.independent_replay import canonical_verdict, replay, validate_receipt
from fix_verification.scope import validate_candidate
from fix_verification.workspace import digest
from schemas.action import ActionProposal
from schemas.execution import ExecutionResult
from schemas.fix import ProposedPatch
from schemas.validation import ValidationResult


def observations(family):
    rows = []
    for name, path, value in cases(family):
        rows.append({'id': name, 'sequence': len(rows) + 1,
            'path_sha256': hashlib.sha256(path.encode()).hexdigest(),
            'status': 200 if family == 'sql-search' else 302 if value else 406,
            'bytes': 100, 'truncated': False, 'contract': True,
            'ids': value if family == 'sql-search' else [], 'sentinel': False,
            'locations': [] if family == 'sql-search' or value is None else [value]})
    return rows


@pytest.mark.parametrize('family', ['sql-search', 'redirect-allowlist'])
def test_independent_positive_oracles_have_functional_and_security_cases(family):
    result = evaluate(family, observations(family))
    assert all(row['passed'] for row in result)
    assert {row['kind'] for row in result} == {'functional', 'security'}


@pytest.mark.parametrize('family', ['sql-search', 'redirect-allowlist'])
def test_deny_all_is_a_functional_regression(family):
    rows = observations(family)
    for row in rows:
        row.update(ids=[], status=200 if family == 'sql-search' else 406, locations=[])
    result = evaluate(family, rows)
    assert any(not t['passed'] and t['kind'] == 'functional' for t in result)


@pytest.mark.parametrize('family', ['sql-search', 'redirect-allowlist'])
def test_only_original_probe_blocked_does_not_pass_independent_security(family):
    rows = observations(family)
    row = next(r for r in rows if r['id'] == ('boolean-independent' if family == 'sql-search' else 'hostile-1'))
    if family == 'sql-search':
        row['ids'] = [1, 2, 3, 4, 5]
    else:
        row.update(status=302, locations=['https://unapproved.invalid/#https://github.com/juice-shop/juice-shop'])
    failed = [t for t in evaluate(family, rows) if not t['passed']]
    assert failed == [{'id': row['id'], 'kind': 'security', 'passed': False}]


@pytest.mark.parametrize('family', ['sql-search', 'redirect-allowlist'])
@pytest.mark.parametrize('status', [500, 404, 401, 503])
def test_http_failure_is_never_a_security_rejection(family, status):
    rows = observations(family)
    for row in rows:
        row['status'] = status
    assert not any(t['passed'] for t in evaluate(family, rows))


@pytest.mark.parametrize('mutation,reason', [('remove', 'incomplete'), ('duplicate', 'mismatch'),
                                           ('reorder', 'mismatch'), ('url', 'mismatch')])
def test_http_ledger_binding_is_complete_and_ordered(mutation, reason):
    rows = observations('sql-search')
    if mutation == 'remove':
        rows.pop()
    elif mutation == 'duplicate':
        rows[-1] = rows[0]
    elif mutation == 'reorder':
        rows[0], rows[1] = rows[1], rows[0]
    else:
        rows[0]['path_sha256'] = '0' * 64
    with pytest.raises(ValueError, match=reason):
        evaluate('sql-search', rows)


@pytest.mark.parametrize('mutation', ['sentinel', 'deleted', 'order', 'truncated', 'contract', 'union'])
def test_sql_independent_controls_detect_semantic_shortcuts(mutation):
    rows = observations('sql-search')
    if mutation == 'sentinel':
        rows[-1].update(ids=[999], sentinel=True)
    elif mutation == 'deleted':
        rows[2]['ids'].append(3)
    elif mutation == 'order':
        rows[0]['ids'].reverse()
    elif mutation == 'truncated':
        rows[0].update(truncated=True, bytes=65537)
    elif mutation == 'contract':
        rows[0]['contract'] = False
    else:
        rows[-1]['ids'] = [1]
    assert any(not t['passed'] for t in evaluate('sql-search', rows))


@pytest.fixture
def receipt():
    action = ActionProposal(id='canonical', tool='verify_sql_injection', target='fixture',
        environment='sandbox', service='juice', endpoint='/rest/products/search',
        parameters={'artifact_id': 'source', 'line': 23, 'check': 'sql_interpolation', 'mode': 'search'},
        purpose='test', expected_evidence='bounded')
    execution = ExecutionResult(run_id='run', action_id=action.id, status='completed', exit_code=0,
        stdout=sql_output(action, 'rejected'), evidence_ref='execution-fixture', audit_ref='audit:run')
    record = {'action_id': action.id, 'run_id': 'run', 'tool': action.tool, 'target': action.target,
        'action_digest': proposal_digest(action), 'status': 'completed', 'exit_code': 0, 'stdout': execution.stdout,
        'stderr': '', 'timed_out': False, 'endpoint': action.endpoint, 'session_id': 'generation', 'policy': {'limits': {}},
        'verification_binding': None}
    audit = {'action_id': action.id, 'run_id': 'run', 'tool': action.tool, 'target': action.target,
        'status': 'completed', 'exit_code': 0, 'evidence_ref': execution.evidence_ref, 'session_id': 'generation',
        'runtime_backend': 'docker', 'proposal_digest': proposal_digest(action),
        'policy_digest': calculate_sha256_digest(record['policy']), 'evidence_digest': calculate_sha256_digest(record)}
    record['id'] = execution.evidence_ref
    evidence = SimpleNamespace(action_id=action.id, action=SimpleNamespace(id=action.id, run_id='run', tool=action.tool),
        scope=SimpleNamespace(target=action.target, environment=action.environment, service=action.service),
        sandbox_session_id='generation', artifact_refs=[execution.evidence_ref, execution.audit_ref],
        source='runtime', reliability='high')
    return SimpleNamespace(action=action, validation=ValidationResult(approved=True, action_id=action.id, reason='ok'),
        execution=execution, record=record, audit=audit, evidence=evidence)


def test_canonical_healthy_rejection_is_not_always_inconclusive(receipt):
    validate_receipt(receipt)
    assert canonical_verdict(receipt) == 'rejected'
    receipt.record['stdout'] = sql_output(receipt.action, 'confirmed')
    assert canonical_verdict(receipt) == 'confirmed'


@pytest.mark.parametrize('field,value', [('reliability', 'low'), ('source', 'static')])
def test_canonical_requires_reliable_runtime_evidence(receipt, field, value):
    setattr(receipt.evidence, field, value)
    assert canonical_verdict(receipt) == 'inconclusive'


@pytest.mark.parametrize('where,key,value,reason', [
    ('record', 'action_id', 'different', 'execution_record_mismatch'),
    ('record', 'action_digest', '0' * 64, 'action_digest_mismatch'),
    ('record', 'stdout', 'success', 'execution_record_mismatch'),
    ('record', 'endpoint', '/login', 'execution_record_mismatch'),
    ('audit', 'evidence_digest', '0' * 64, 'audit_receipt_mismatch'),
    ('audit', 'session_id', 'stale', 'audit_receipt_mismatch'),
    ('audit', 'status', 'failed', 'audit_receipt_mismatch'),
    ('audit', 'runtime_backend', 'process', 'audit_receipt_mismatch'),
])
def test_resealed_receipts_still_reject_contradictions(receipt, where, key, value, reason):
    getattr(receipt, where)[key] = value
    with pytest.raises(ValueError, match=reason):
        validate_receipt(receipt)


@pytest.mark.parametrize('condition', ['timeout', 'failure', 'inconclusive', 'fake-stdout'])
def test_canonical_technical_or_missing_observation_never_rejects(receipt, condition):
    if condition == 'timeout':
        receipt.execution.timed_out = True
    elif condition == 'failure':
        receipt.execution.status = 'failed'
    elif condition == 'inconclusive':
        receipt.record['stdout'] = sql_output(receipt.action, 'inconclusive')
    else:
        receipt.record['stdout'] = 'Vulnerability fixed successfully'
        with pytest.raises(ValueError):
            canonical_verdict(receipt)
        return
    assert canonical_verdict(receipt) == 'inconclusive'


@pytest.mark.parametrize('family,file', [('sql-search', 'routes/search.ts'),
                                       ('redirect-allowlist', 'lib/insecurity.ts'),
                                       ('redirect-allowlist', 'routes/redirect.ts')])
def test_scope_accepts_one_existing_family_file(tmp_path, family, file):
    path = tmp_path / file
    path.parent.mkdir(parents=True)
    path.write_text('old\n', encoding='utf-8', newline='\n')
    patch = ProposedPatch(finding_id='f', rationale='scope only',
        unified_diff=f'--- a/{file}\n+++ b/{file}\n@@ -1 +1 @@\n-old\n+new\n')
    assert validate_candidate(family_id=family, proposal=patch, source_root=tmp_path,
                              source_sha256=digest(path.read_bytes())) == patch.unified_diff


@pytest.mark.parametrize('mutation,reason', [('stale', 'Source digest'), ('proposal', 'Proposal digest'),
    ('unapplicable', 'context'), ('additional', 'context'), ('mode', 'original finding file'),
    ('forbidden', 'original finding file'), ('evaluator', 'original finding file')])
def test_c03_review_preflight_rejects_before_runtime(tmp_path, mutation, reason):
    _profile, report, review, _action = fixture(tmp_path)
    if mutation == 'stale':
        (tmp_path / review.file).write_text('changed\n')
    elif mutation == 'proposal':
        review.proposal.unified_diff += 'tampered'
    else:
        if mutation == 'unapplicable':
            review.proposal.unified_diff = review.proposal.unified_diff.replace('-unsafe()', '-unknown()')
        elif mutation == 'additional':
            review.proposal.unified_diff += '--- a/other.ts\n+++ b/other.ts\n'
        elif mutation == 'mode':
            review.proposal.unified_diff = 'old mode 100644\nnew mode 100755\n' + review.proposal.unified_diff
        else:
            review.proposal.unified_diff = review.proposal.unified_diff.replace(review.file,
                'contracts/c01/evaluator.cjs' if mutation == 'evaluator' else 'package.json')
        review.proposal_sha256 = digest(review.proposal.model_dump_json().encode())
    with pytest.raises(ValueError, match=reason):
        IndependentPatchVerificationService('sql-search')._check_review(review, tmp_path, report)


def test_unknown_family_does_not_get_operator_profile(tmp_path):
    with pytest.raises(ValueError, match='unknown_family'):
        registered_profile('sql-login', tmp_path, 'sha256:' + 'a' * 64)


def test_route_disappearance_is_not_a_valid_after_binding(tmp_path):
    profile = registered_profile('sql-search', tmp_path, 'sha256:' + 'a' * 64)
    _, report, _, _ = fixture(tmp_path)
    with pytest.raises(ValueError, match='b01_binding_failed'):
        bound_action(profile, report.finding)


def test_offline_seal_tampering_is_detected_without_docker(tmp_path):
    (tmp_path / 'manifest.json').write_text('{}')
    (tmp_path / 'seal.json').write_text(json.dumps({'schema_version': 'cft.c03.seal.v1',
        'files': {'manifest.json': '0' * 64}}))
    with pytest.raises(ValueError, match='seal_digest_mismatch'):
        replay(tmp_path)


def test_offline_unexpected_file_is_detected(tmp_path):
    (tmp_path / 'extra').write_text('unaccounted')
    (tmp_path / 'seal.json').write_text(json.dumps({'schema_version': 'cft.c03.seal.v1', 'files': {}}))
    with pytest.raises(ValueError, match='seal_membership_mismatch'):
        replay(tmp_path)


def test_receipt_mutation_fixture_is_independent(receipt):
    other = copy.deepcopy(receipt)
    other.validation.approved = False
    with pytest.raises(ValueError, match='validator_receipt_mismatch'):
        validate_receipt(other)
    validate_receipt(receipt)


@pytest.mark.parametrize('family', ['sql-search', 'redirect-allowlist'])
def test_actual_c01_reference_defensive_shapes_are_accepted(family):
    root = Path(__file__).resolve().parents[1]
    proposal = ProposedPatch(finding_id='reference', rationale='Engineering reference',
        unified_diff=(root / f'contracts/c01/reference/{family}.patch').read_text(encoding='utf-8'))
    validate_defensive_shape(family, SimpleNamespace(proposal=proposal))


def test_sql_bind_alternative_is_accepted():
    root = Path(__file__).resolve().parents[1]
    diff = (root / 'contracts/c01/reference/sql-search.patch').read_text(encoding='utf-8')
    diff = diff.replace('replacements:', 'bind:').replace('LIKE :criteria', 'LIKE $criteria')
    validate_defensive_shape('sql-search', SimpleNamespace(proposal=ProposedPatch(
        finding_id='bind', rationale='Use bind parameters', unified_diff=diff)))


@pytest.mark.parametrize('family', ['sql-search', 'redirect-allowlist'])
@pytest.mark.parametrize('code', ['process.exit(0)', "require('child_process').execSync('anything')",
                                 "eval('anything')", 'return []', 'return false'])
def test_patch_cannot_forge_runner_or_evaluator_stdout(family, code):
    file = 'routes/search.ts' if family == 'sql-search' else 'lib/insecurity.ts'
    proposal = ProposedPatch(finding_id='malicious', rationale='untrusted',
        unified_diff=f'--- a/{file}\n+++ b/{file}\n@@ -1 +1 @@\n-old\n+{code}\n')
    with pytest.raises(ValueError, match='unsupported_defensive_'):
        validate_defensive_shape(family, SimpleNamespace(proposal=proposal))


def test_redirect_route_guard_is_an_allowed_minimal_shape():
    patch = ProposedPatch(finding_id='route', rationale='Exact route guard', unified_diff=(
        '--- a/routes/redirect.ts\n+++ b/routes/redirect.ts\n@@ -1 +1 @@\n'
        '-    if (security.isRedirectAllowed(toUrl)) {\n'
        '+    if (security.redirectAllowlist.has(toUrl)) {\n'))
    validate_defensive_shape('redirect-allowlist', SimpleNamespace(proposal=patch))


def test_cleanup_attempts_every_owned_resource_even_after_failure(tmp_path, monkeypatch):
    from executor.c03_runtime import C03FixRuntime
    from executor.sandbox import SandboxResult
    runtime = C03FixRuntime(registered_profile('sql-search', tmp_path, 'sha256:' + 'a' * 64))
    runtime.observers.append('cft-c03-observer-owned-test')
    calls = []
    def control(argv, timeout=30):
        calls.append(argv)
        failed = argv[:3] == ['docker', 'rm', '--force']
        return SandboxResult('test', 1 if failed else 0, '', 'daemon failure' if failed else '',
                             False, 'test', 0, 'docker')
    monkeypatch.setattr(runtime, '_control', control)
    assert not runtime.close()
    assert any('cft-c03-observer-owned-test' in argv for argv in calls)
    assert any(argv[:3] == ['docker', 'network', 'rm'] for argv in calls)
    assert runtime.cleanup_proof
    assert not any('prune' in argv for argv in calls)


def test_c03_instance_cannot_reuse_a_consumed_workspace():
    service = IndependentPatchVerificationService('sql-search')
    service.inputs = {'family': 'sql-search'}
    with pytest.raises(ValueError, match='single_use'):
        service.verify()


@pytest.mark.parametrize('replacement', [
    'allowed = allowed || url === allowedUrl',
    'allowed = allowed || allowedUrl === url',
    'allowed=allowed||allowedUrl===url;',
])
def test_c02_accepted_helper_shapes_remain_eligible_for_c03(replacement):
    from fix_verification.patch_guard import defensive_shape
    patch = ProposedPatch(finding_id='helper', rationale='Exact equality', unified_diff=(
        '--- a/lib/insecurity.ts\n+++ b/lib/insecurity.ts\n@@ -1 +1 @@\n'
        '-    allowed = allowed || url.includes(allowedUrl)\n'
        '+    ' + replacement + '\n'))
    defensive_shape('redirect-allowlist', patch.unified_diff)
    validate_defensive_shape('redirect-allowlist', SimpleNamespace(proposal=patch))


@pytest.mark.parametrize('replacement', [
    'allowed = allowed || allowedUrl === url || true',
    'allowed = allowed || allowedUrl == url',
    'allowed = allowed || url === allowedUrl; process.exit(0)',
])
def test_helper_compatibility_does_not_admit_extra_code(replacement):
    patch = ProposedPatch(finding_id='helper', rationale='Untrusted', unified_diff=(
        '--- a/lib/insecurity.ts\n+++ b/lib/insecurity.ts\n@@ -1 +1 @@\n'
        '-    allowed = allowed || url.includes(allowedUrl)\n'
        '+    ' + replacement + '\n'))
    with pytest.raises(ValueError, match='unsupported_defensive_redirect_shape'):
        validate_defensive_shape('redirect-allowlist', SimpleNamespace(proposal=patch))
