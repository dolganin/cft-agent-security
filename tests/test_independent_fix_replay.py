"""Replay real, sealed SQL reference evidence; no Docker, model or patch execution."""
import json
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from app.independent_fix import seal
from fix_verification.independent_replay import replay


@pytest.fixture
def package(tmp_path):
    source = Path(__file__).with_name('fixtures') / 'c03-sql-runtime.zip'
    with zipfile.ZipFile(source) as archive:
        assert sum(i.file_size for i in archive.infolist()) < 2 * 1024 * 1024
        for item in archive.infolist():
            path = PurePosixPath(item.filename)
            assert not path.is_absolute() and '..' not in path.parts and '\\' not in item.filename
            output = tmp_path / path
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(archive.read(item))
    return tmp_path


def rewrite(package, mutate):
    file = package / 'manifest.json'
    data = json.loads(file.read_text(encoding='utf-8'))
    mutate(data)
    file.write_text(json.dumps(data), encoding='utf-8', newline='\n')
    # Only this disposable fixture copy is resealed, never historical evidence.
    (package / 'seal.json').unlink()
    seal(package)


def test_real_reference_evidence_replays_fixed_without_docker(package, monkeypatch):
    import subprocess
    original = subprocess.Popen
    def only_git(argv, *args, **kwargs):
        assert Path(argv[0]).stem == 'git', 'offline replay executed target/Docker code'
        return original(argv, *args, **kwargs)
    monkeypatch.setattr(subprocess, 'Popen', only_git)
    assert replay(package)['status'] == 'FIXED'


@pytest.mark.parametrize('mutation', ['extra-stage', 'stage-profile', 'stage-attempt', 'audit-ref'])
def test_resealed_stage_and_receipt_provenance_cannot_claim_fixed(package, mutation):
    def change(data):
        if mutation == 'extra-stage':
            data['result']['stages'].append(dict(data['result']['stages'][0]))
        elif mutation == 'stage-profile':
            data['result']['stages'][0]['profile_id'] = 'unregistered'
        elif mutation == 'stage-attempt':
            data['result']['stages'][0]['attempted'] = False
        else:
            data['receipts'][0]['execution']['audit_ref'] = 'audit:unrelated'
    rewrite(package, change)
    with pytest.raises(ValueError, match='stage_inventory_mismatch|stage_receipt_mismatch|receipt_provenance_mismatch'):
        replay(package)


@pytest.mark.parametrize('mutation,reason', [
    ('source', 'seal_digest_mismatch'), ('missing', 'seal_membership_mismatch'),
    ('extra', 'seal_membership_mismatch'),
])
def test_seal_is_checked_before_interpretation(package, mutation, reason):
    if mutation == 'source':
        path = next(package.glob('*/after/source/routes/search.ts'))
        path.write_bytes(path.read_bytes() + b'// tampered\n')
    elif mutation == 'missing':
        next(package.glob('*/after/evidence/*.json')).unlink()
    else:
        (package / 'unaccounted.json').write_text('{}')
    with pytest.raises(ValueError, match=reason):
        replay(package)


@pytest.mark.parametrize('mutation,reason', [
    ('execution-action', 'execution_record_mismatch'),
    ('execution-output', 'execution_record_mismatch'),
    ('audit-digest', 'audit_receipt_mismatch'),
    ('audit-backend', 'audit_receipt_mismatch'),
    ('duplicate-run', 'execution_record_mismatch|duplicate_execution|receipt_provenance_mismatch'),
    ('family', 'operator_profile_mismatch'),
    ('proposal', 'proposal_digest_mismatch|unsupported_defensive'),
    ('source-digest', 'proposal_digest_mismatch'),
    ('cleanup', 'saved_verdict_disagrees:INCONCLUSIVE:owned_resources'),
    ('original', 'saved_verdict_disagrees:INCONCLUSIVE:original_changed'),
    ('workspace', 'saved_verdict_disagrees:INCONCLUSIVE:cleanup_or_generation'),
    ('independent-missing', 'stage_inventory_mismatch'),
    ('source-binding', 'action_digest_mismatch'),
    ('test-stdout', 'execution_record_mismatch'),
])
def test_resealed_contradictory_manifest_cannot_claim_fixed(package, mutation, reason):
    def change(data):
        receipts = data['receipts']
        if mutation == 'execution-action':
            receipts[0]['record']['action_id'] = 'not-approved'
        elif mutation == 'execution-output':
            receipts[-1]['record']['stdout'] = 'Vulnerability fixed successfully'
        elif mutation == 'audit-digest':
            receipts[-1]['audit']['evidence_digest'] = '0' * 64
        elif mutation == 'audit-backend':
            receipts[-1]['audit']['runtime_backend'] = 'process'
        elif mutation == 'duplicate-run':
            receipts[-1]['execution']['run_id'] = receipts[0]['execution']['run_id']
        elif mutation == 'family':
            data['family'] = 'redirect-allowlist'
        elif mutation == 'proposal':
            data['inputs']['review']['proposal']['rationale'] = 'changed proposal'
        elif mutation == 'source-digest':
            data['inputs']['review']['source_sha256'] = '0' * 64
        elif mutation == 'cleanup':
            data['lifecycle'][0]['cleanup_proofs'][0][0]['absent'] = False
        elif mutation == 'original':
            data['inputs']['original_after_manifest']['routes/search.ts'][0] = '0' * 64
        elif mutation == 'workspace':
            data['inputs']['workspace_cleanup'] = False
        elif mutation == 'independent-missing':
            removed = next(r for r in receipts if r['action']['parameters'].get('stage') == 'c03_http')
            receipts.remove(removed)
            data['result']['new_evidence'].remove(removed['evidence'])
        elif mutation == 'source-binding':
            receipts[-1]['action']['verification_binding']['route_id'] = 'wrong-route'
        else:
            receipt = next(r for r in receipts if r['action']['parameters'].get('stage') == 'tests')
            receipt['execution']['stdout'] = 'success'
    rewrite(package, change)
    with pytest.raises(ValueError, match=reason):
        replay(package)


def test_missing_persisted_record_is_not_replaced_by_manifest_success(package):
    next(package.glob('*/after/evidence/*.json')).unlink()
    (package / 'seal.json').unlink()
    seal(package)
    with pytest.raises(ValueError, match='persisted_execution_mismatch'):
        replay(package)


@pytest.mark.parametrize('mutation', ['missing-native-receipt', 'different-contract'])
def test_native_contract_marker_and_version_are_mandatory_when_enabled(package, mutation):
    from fix_verification.native_contract import CONTRACT_SHA256
    rewrite(package, lambda data: data['inputs'].update(native_contract_sha256=(
        CONTRACT_SHA256 if mutation == 'missing-native-receipt' else '0' * 64)))
    with pytest.raises(ValueError, match='native_contract_missing_or_changed'):
        replay(package)
