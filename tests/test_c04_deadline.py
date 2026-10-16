"""Composition deadlines shorten C03 without changing its permission profile."""
import json
import os
import subprocess
import sys
from datetime import UTC, datetime
from time import monotonic
from types import SimpleNamespace

import pytest
from test_fix_verification import COMMIT, fixture

from app import independent_fix
from executor.fix_runtime import DockerFixRuntime
from executor.sandbox import _communicate_bounded
from fix_verification.independent import registered_profile
from fix_verification.service import FixVerificationService
from pipeline.cancellation import RunCancelled, current_token
from schemas.b06_verification import profile_digest


@pytest.mark.parametrize('value', [float('nan'), float('inf'), -float('inf'), True, 'later'])
def test_deadline_rejects_nonfinite_and_non_numeric_values(tmp_path, value):
    source = tmp_path / 'source'
    source.mkdir()
    profile, report, review, _ = fixture(source)
    with pytest.raises(ValueError, match='deadline_monotonic must be finite'):
        FixVerificationService().verify(report=report, review=review, profile=profile,
            artifact_directory=tmp_path / 'output', deadline_monotonic=value)


def test_expired_deadline_stops_before_source_or_execution(tmp_path):
    source = tmp_path / 'source'
    source.mkdir()
    profile, report, review, _ = fixture(source)
    before = (source / review.file).read_bytes()
    result = FixVerificationService().verify(report=report, review=review, profile=profile,
        artifact_directory=tmp_path / 'output', deadline_monotonic=monotonic() - 1)
    assert result.status == 'INCONCLUSIVE'
    assert 'budget exhausted' in result.explanation
    assert not result.stages and not result.applied
    assert (source / review.file).read_bytes() == before


def test_runtime_budget_clamps_without_changing_profile(tmp_path):
    profile = registered_profile('sql-search', tmp_path, 'sha256:' + 'a' * 64)
    original_digest = profile_digest(profile)
    service = FixVerificationService()
    artifact = SimpleNamespace(started_at=datetime.now(UTC))
    service._deadline_monotonic = monotonic() + 2
    assert service._runtime_deadline(profile, artifact) == service._deadline_monotonic
    service._deadline_monotonic = monotonic() + 10000
    assert service._runtime_deadline(profile, artifact) < service._deadline_monotonic
    assert profile_digest(profile) == original_digest


def test_provisioning_control_timeout_is_clamped_but_cleanup_is_not():
    calls = []
    service = FixVerificationService()
    service._deadline_monotonic = monotonic() + 2
    runtime = SimpleNamespace(deadline=service._deadline_monotonic)
    runtime._control = lambda argv, timeout=30: calls.append((argv, timeout, current_token()))
    runtime.close = lambda: runtime._control(['cleanup']) or True
    service._bound_runtime_control(runtime)
    runtime._control(['provision'])
    assert 0 < calls[-1][1] <= 2
    assert calls[-1][2] is not None
    runtime.deadline = service._deadline_monotonic = monotonic() - 1
    with pytest.raises(TimeoutError):
        runtime._control(['provision'])
    assert runtime.close()
    assert calls[-1] == (['cleanup'], 30, None)


def test_transport_is_terminated_at_outer_deadline():
    service = FixVerificationService()
    service._deadline_monotonic = monotonic() + .15
    process = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    started = monotonic()
    try:
        with pytest.raises(RunCancelled), service._execution_budget():
            _communicate_bounded(process, b'', 30, 1024)
        assert process.poll() is not None
        assert monotonic() - started < 3
        assert current_token() is None
    finally:
        if process.poll() is None:
            process.kill()
        process.wait()


def test_default_deadline_does_not_change_existing_behavior(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    source.mkdir()
    profile, report, review, _ = fixture(source)
    monkeypatch.setattr('fix_verification.service.original_commit', lambda _: COMMIT)
    service = FixVerificationService()
    visited = []
    def phase(*args):
        visited.append(args[2])
    monkeypatch.setattr(service, '_phase', phase)
    result = service.verify(report=report, review=review, profile=profile,
        artifact_directory=tmp_path / 'output')
    assert visited == ['before']
    assert result.status == 'INCONCLUSIVE'


def test_runtime_transport_uses_separate_process_session(tmp_path, monkeypatch):
    profile = registered_profile('sql-search', tmp_path, 'sha256:' + 'a' * 64)
    runtime = DockerFixRuntime(profile)
    calls = []
    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0)
    monkeypatch.setattr('executor.fix_runtime.subprocess.Popen', popen)
    monkeypatch.setattr('executor.fix_runtime._communicate_bounded',
        lambda *args: (b'controlled', False, b'', False, False))
    assert runtime._control(['operator-command']).stdout == 'controlled'
    assert calls[0][1]['start_new_session'] == (os.name == 'posix')
    assert calls[0][1]['shell'] is False


def test_interruption_preserves_sealed_partial_c03_manifest(tmp_path, monkeypatch):
    # app.independent_fix sets its operator worker image; restore the caller's
    # environment after this unit test so opt-in integrations remain opt-in.
    monkeypatch.setenv('CFT_SANDBOX_IMAGE', 'c04-unit-test-placeholder')
    source = tmp_path / 'source'
    source.mkdir()
    profile, report, review, _ = fixture(source)
    service = FixVerificationService()
    service.inputs, service.receipts, service.lifecycle, service.reason_codes = {}, [], [], []
    workspaces = []
    def interrupted(*args):
        workspaces.append(args[0].repository_path)
        raise KeyboardInterrupt
    monkeypatch.setattr(service, '_phase', interrupted)
    monkeypatch.setattr('fix_verification.service.original_commit', lambda _: COMMIT)
    monkeypatch.setattr(independent_fix, 'pinned_image', lambda value: value)
    monkeypatch.setattr(independent_fix, 'registered_profile', lambda *args: profile)
    monkeypatch.setattr(independent_fix, 'IndependentPatchVerificationService', lambda _: service)
    output = tmp_path / 'output'
    with pytest.raises(KeyboardInterrupt):
        independent_fix.run(family='sql-search', target=source, output=output,
            fix_image='sha256:' + 'a' * 64, report=report, review=review)
    manifest = json.loads((output / 'manifest.json').read_text())
    result = manifest['result']
    assert result['status'] == 'INCONCLUSIVE'
    assert not result['security_verified'] and not result['applied']
    assert result['finished_at'] is not None and result['original_unchanged']
    assert manifest['reason_codes'] == ['operator_interrupted']
    seal = json.loads((output / 'seal.json').read_text())
    assert {'manifest.json', 'interruption.json'} <= set(seal['files'])
    assert workspaces and all(not path.exists() for path in workspaces)
