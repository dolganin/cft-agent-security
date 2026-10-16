"""C05 accounting cannot hide failed or unattempted eligible slots."""
import json
from pathlib import Path

import pytest

from fix_verification import measurement as m


@pytest.fixture
def series(tmp_path, monkeypatch):
    root = tmp_path / 'series'
    root.mkdir()
    plan = {'slots': [{'id': f'{r:02d}-{f}', 'family': f, 'repetition': r}
                      for r in range(1, 4) for f in m.FAMILIES],
            'limits': m.LIMITS.model_dump(mode='json'), 'fix_image': 'immutable',
            'population': {'confirmed_case_ids': ['sql', 'redirect', 'login', 'auth', 'file'],
                           'cases': [{'family': f, 'historical_confirmed_at': '2026-10-15T12:00:00+00:00'}
                                     for f in m.FAMILIES]}}
    m.write_json(root / 'protocol.json', plan)
    monkeypatch.setattr(m, 'protocol', lambda _: plan)
    return root, plan


def test_all_unattempted_cases_remain_in_denominator(series):
    root, _plan = series
    result = m.summarize(root)
    assert result['verified_eligible'] == {'verified': 0, 'eligible': 6, 'unit': 'case-run'}
    assert result['eligible_confirmed']['eligible'] == 2
    assert result['eligible_confirmed']['confirmed'] == 5
    assert result['statuses']['NOT_RUN'] == 6
    assert not result['complete']
    assert result['time_confirmed_input_to_verified']['mean_ms'] is None


def test_technical_failure_is_visible_and_not_excluded(series):
    root, plan = series
    slot = plan['slots'][0]
    m.write_json(root / 'receipts' / (slot['id'] + '.json'), {
        **slot, 'protocol_sha256': m.digest((root / 'protocol.json').read_bytes()),
        'error': 'technical_failure', 'replay': None, 'duration_ms': 123})
    result = m.summarize(root)
    assert result['statuses']['TECHNICAL_ERROR'] == 1
    assert result['statuses']['NOT_RUN'] == 5
    assert result['verified_eligible']['eligible'] == 6
    assert result['rows'][0]['duration_ms'] == 123
    assert result['historical_mttr'] is result['production_mttr'] is None


def test_started_but_interrupted_is_not_unattempted(series):
    root, plan = series
    m.write_json(root / 'starts' / (plan['slots'][0]['id'] + '.json'), plan['slots'][0])
    assert m.summarize(root)['statuses']['INTERRUPTED'] == 1


def test_all_started_without_terminal_receipts_is_not_a_complete_series(series):
    root, plan = series
    for slot in plan['slots']:
        m.write_json(root / 'starts' / (slot['id'] + '.json'), slot)
    result = m.summarize(root)
    assert result['statuses']['INTERRUPTED'] == 6
    assert not result['complete']


@pytest.mark.parametrize('mutation', ['family', 'protocol'])
def test_receipt_cannot_change_the_selected_case_or_protocol(series, mutation):
    root, plan = series
    row = {**plan['slots'][0], 'protocol_sha256': m.digest((root / 'protocol.json').read_bytes())}
    row['family' if mutation == 'family' else 'protocol_sha256'] = 'untrusted'
    m.write_json(root / 'receipts' / (plan['slots'][0]['id'] + '.json'), row)
    with pytest.raises(ValueError, match='frozen slot'):
        m.summarize(root)


def test_preflight_failure_without_runtime_remains_technical(series, monkeypatch):
    root, plan = series
    slot = plan['slots'][0]
    checked = {'status': 'TECHNICAL_ERROR', 'stop_reason': 'preflight_or_integrity_failure',
               'attempts': 0, 'seal_sha256': 'f' * 64}
    monkeypatch.setattr(m, 'replay', lambda _: checked)
    m.write_json(root / 'receipts' / (slot['id'] + '.json'), {
        **slot, 'protocol_sha256': m.digest((root / 'protocol.json').read_bytes()),
        'error': None, 'replay': checked, 'duration_ms': 12})
    m.write_json(root / 'runs' / slot['id'] / 'result.json', {
        'family': slot['family'], 'limits': plan['limits'], 'original_unchanged': True, 'attempts': []})
    m.write_json(root / 'runs' / slot['id'] / 'configuration.json', {'routes': [m.ROUTE.replace(':', '/', 1)]})
    result = m.summarize(root)
    assert result['statuses']['TECHNICAL_ERROR'] == 1


def test_outer_seal_rejects_changed_data_before_rescore(series):
    root, _plan = series
    m.write_json(root / 'measurement.json', m.summarize(root))
    m.seal(root)
    (root / 'protocol.json').write_text('{}', encoding='utf-8')
    with pytest.raises(ValueError, match='Series seal mismatch'):
        m.replay_series(root)


def test_resealed_forged_metrics_are_recomputed(series):
    root, _plan = series
    result = m.summarize(root)
    result['verified_eligible']['verified'] = 6
    m.write_json(root / 'measurement.json', result)
    m.seal(root)
    with pytest.raises(ValueError, match='metrics disagree'):
        m.replay_series(root)


def test_frozen_protocol_tampering_is_rejected(tmp_path):
    m.write_json(tmp_path / 'protocol.json', {'route': 'another-provider'})
    (tmp_path / 'protocol.sha256').write_text('0' * 64, encoding='ascii')
    with pytest.raises(ValueError, match='Frozen protocol changed'):
        m.protocol(tmp_path)


def test_existing_slot_cannot_be_replaced(series, monkeypatch):
    root, plan = series
    m.write_json(root / 'starts' / (plan['slots'][0]['id'] + '.json'), {})
    monkeypatch.setattr(m, 'run', lambda **_: pytest.fail('must not run'))
    with pytest.raises(ValueError, match='silently resume'):
        m.execute(Path('unused'), root)


def completed_slot(root, plan, slot, status):
    checked = {'status': status, 'stop_reason': 'independently_verified' if status == 'FIXED' else 'attempts_exhausted',
               'attempts': 1, 'seal_sha256': slot['id']}
    m.write_json(root / 'receipts' / (slot['id'] + '.json'), {
        **slot, 'protocol_sha256': m.digest((root / 'protocol.json').read_bytes()),
        'started_at': '2026-10-16T12:00:00+00:00', 'finished_at': '2026-10-16T12:01:00+00:00',
        'error': None, 'replay': checked, 'duration_ms': 60000})
    m.write_json(root / 'starts' / (slot['id'] + '.json'), {
        **slot, 'started_at': '2026-10-16T12:00:00+00:00',
        'protocol_sha256': m.digest((root / 'protocol.json').read_bytes())})
    directory = root / 'runs' / slot['id']
    m.write_json(directory / 'configuration.json', {'routes': [m.ROUTE.replace(':', '/', 1)]})
    m.write_json(directory / 'runtime.json', {'fix_image': plan['fix_image']})
    attempt = {'directory': 'attempts/001', 'number': 1, 'generation_status': 'ready_for_review',
               'verification_status': 'FIXED' if status == 'FIXED' else 'REGRESSION',
               'decision': 'fixed' if status == 'FIXED' else 'retry', 'reason': checked['stop_reason'],
               'duration_ms': 50000, 'generation_ms': 10000, 'verification_ms': 40000, 'workspace_cleanup': True}
    m.write_json(directory / 'result.json', {'family': slot['family'], 'limits': plan['limits'],
                                          'started_at': '2026-10-16T12:00:01+00:00',
                                          'finished_at': '2026-10-16T12:00:59+00:00',
                                          'original_unchanged': True, 'attempts': [attempt]})
    m.write_json(directory / 'attempts/001/verification/manifest.json', {'result': {'before_evidence': {
        'verdict': 'confirmed', 'created_at': '2026-10-16T12:00:30+00:00'}}})
    return checked


def test_success_rates_and_times_do_not_drop_failures(series, monkeypatch):
    root, plan = series
    checks = {}
    for index, slot in enumerate(plan['slots']):
        checks[slot['id']] = completed_slot(root, plan, slot, 'FIXED' if index < 3 else 'NOT_FIXED')
    monkeypatch.setattr(m, 'replay', lambda directory: checks[directory.name])
    result = m.summarize(root)
    assert result['complete']
    assert result['verified_eligible']['verified'] == 3
    assert result['verified_eligible']['eligible'] == 6
    assert result['attempts'] == 6 and result['regression_attempts'] == 3
    assert result['time_confirmed_input_to_verified']['n'] == 3
    assert result['time_confirmed_input_to_verified']['mean_ms'] == 60000
    assert result['fresh_before_to_verified']['mean_ms'] == 30000
    assert result['rows'][0]['historical_confirmed_to_verified_ms'] == 86460000
    assert result['rows'][5]['verified_ms'] is None


@pytest.mark.parametrize('mutation', ['family', 'limits', 'route', 'image', 'replay'])
def test_replayed_run_must_match_series_configuration(series, monkeypatch, mutation):
    root, plan = series
    slot = plan['slots'][0]
    checked = completed_slot(root, plan, slot, 'FIXED')
    directory = root / 'runs' / slot['id']
    name = {'family': 'result.json', 'limits': 'result.json', 'route': 'configuration.json',
            'image': 'runtime.json', 'replay': None}[mutation]
    if name:
        path = directory / name
        data = json.loads(path.read_bytes())
        key = {'route': 'routes', 'image': 'fix_image'}.get(mutation, mutation)
        data[key] = 'changed'
        path.write_text(json.dumps(data), encoding='utf-8')
    else:
        checked['status'] = 'NOT_FIXED'
    monkeypatch.setattr(m, 'replay', lambda _: checked)
    with pytest.raises(ValueError):
        m.summarize(root)


@pytest.mark.parametrize('interrupted', [False, True])
def test_execution_preserves_failure_receipts_without_replacement(series, monkeypatch, interrupted):
    root, _plan = series
    monkeypatch.setattr(m, 'ProviderFailoverClient', lambda **_: object())

    def failed(**kwargs):
        if interrupted:
            raise KeyboardInterrupt()
        raise ValueError('Private exception must not be persisted verbatim')

    monkeypatch.setattr(m, 'run', failed)
    if interrupted:
        with pytest.raises(KeyboardInterrupt):
            m.execute(Path('unused'), root)
        summary = m.summarize(root)
        assert summary['statuses']['INTERRUPTED'] == 1
        assert summary['statuses']['NOT_RUN'] == 5
        assert not summary['complete']
    else:
        m.execute(Path('unused'), root)
        summary = m.summarize(root)
        assert summary['statuses']['TECHNICAL_ERROR'] == 6
        assert summary['complete']
    assert 'Private exception' not in next((root / 'receipts').glob('*.json')).read_text()


@pytest.mark.parametrize('mutation', ['start', 'end', 'clock'])
def test_verified_time_requires_bound_start_finish_and_monotonic_duration(series, monkeypatch, mutation):
    root, plan = series
    slot = plan['slots'][0]
    checked = completed_slot(root, plan, slot, 'FIXED')
    monkeypatch.setattr(m, 'replay', lambda _: checked)
    path = root / 'receipts' / (slot['id'] + '.json')
    value = json.loads(path.read_bytes())
    if mutation == 'start':
        value['started_at'] = '2026-10-16T11:00:00+00:00'
    elif mutation == 'end':
        value['finished_at'] = '2026-10-16T12:00:40+00:00'
    else:
        value['duration_ms'] = 5
    path.write_text(json.dumps(value), encoding='utf-8')
    with pytest.raises(ValueError, match='timing|clock'):
        m.summarize(root)


def test_report_is_a_deterministic_projection_and_keeps_unattempted_rows(series):
    root, plan = series
    plan.update(baseline_sha256='a' * 64, route=m.ROUTE)
    result = m.summarize(root)
    text = m.render_report(result, plan)
    assert text == m.render_report(result, plan)
    assert '0/6' in text and '2/5' in text
    assert text.count('| NOT_RUN |') == 6
    assert 'Historical/production MTTR: **N/A**' in text


def test_cli_rejects_report_inside_target_before_running(tmp_path, monkeypatch):
    from app import repair_measurement
    target = tmp_path / 'target'
    target.mkdir()
    monkeypatch.setattr('sys.argv', ['repair_measurement', '--target', str(target),
        '--output', str(tmp_path / 'output'), '--report', str(target / 'report.md')])
    monkeypatch.setattr(repair_measurement, 'freeze', lambda *_: pytest.fail('must preflight before any execution'))
    with pytest.raises(SystemExit) as error:
        repair_measurement.main()
    assert error.value.code == 2
    assert not list(target.iterdir())
