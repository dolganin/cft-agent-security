"""Only exact operator-approved obsolete security assertions may be replaced."""
import copy
import json

import pytest

from fix_verification import native_contract as native


def observed():
    contract = native.load_native_contract()
    files = {r['file']: r['source_sha256'] for r in contract['failures']}
    rows = [{k: v for k, v in r.items() if k != 'source_sha256'} | {'failure_type': 'testCodeFailure'}
            for r in contract['failures']]
    report = {'summary': {'success': False, 'counts': {'tests': 415, 'passed': 411, 'failed': 2,
              'skipped': 2, 'cancelled': 0, 'todo': 0}}, 'files': sorted(files),
              'skipped': [{'name': 'original-rce-skip-1'}, {'name': 'original-rce-skip-2'}],
              'assertion_failures': rows}
    return report, files


def assess(report, files, **kwargs):
    return native.assess_native('C03 TEST REPORT ' + json.dumps(report),
        family=kwargs.get('family', 'redirect-allowlist'), phase=kwargs.get('phase', 'after'),
        files=files, raw_exit_code=kwargs.get('raw_exit_code', 1))


def test_exact_known_assertions_preserve_failed_native_status_and_require_independent_proof():
    report, files = observed()
    value = assess(report, files)
    assert value and value['raw_exit_code'] == 1
    assert not value['native_suite_success']
    assert len(value['accepted_security_assertions']) == 2
    assert value['independent_security_verification_required']


@pytest.mark.parametrize('mutation', ['source', 'name', 'line', 'code', 'actual', 'expected',
    'duplicate', 'extra', 'cancelled', 'todo', 'skips', 'missing-file', 'wrong-failure-type', 'missing-summary'])
def test_exception_never_admits_other_failures_or_modified_tests(mutation):
    report, files = observed()
    if mutation == 'source':
        files[next(iter(files))] = '0' * 64
    elif mutation == 'missing-file':
        report['files'].pop()
    elif mutation == 'duplicate':
        report['assertion_failures'][1] = copy.deepcopy(report['assertion_failures'][0])
    elif mutation == 'extra':
        report['summary']['counts'].update(tests=416, failed=3)
        report['assertion_failures'].append(copy.deepcopy(report['assertion_failures'][0]))
    elif mutation in {'cancelled', 'todo'}:
        report['summary']['counts'][mutation] = 1
    elif mutation == 'skips':
        report['summary']['counts']['skipped'] = 3
    elif mutation == 'wrong-failure-type':
        report['assertion_failures'][0]['failure_type'] = 'testTimeoutFailure'
    elif mutation == 'missing-summary':
        del report['summary']
    else:
        report['assertion_failures'][0][mutation] = 'changed'
    assert assess(report, files) is None


@pytest.mark.parametrize('kwargs', [{'family': 'sql-search'}, {'phase': 'before'}, {'raw_exit_code': 2},
                                    {'raw_exit_code': 0}])
def test_contract_is_never_used_in_before_sql_or_transport_failure(kwargs):
    report, files = observed()
    assert assess(report, files, **kwargs) is None


def test_untouched_suite_still_requires_zero_real_failures():
    report, files = observed()
    report['summary']['counts'].update(passed=413, failed=0)
    report['summary']['success'] = True
    report['assertion_failures'] = []
    value = assess(report, files, family='sql-search', phase='before', raw_exit_code=0)
    assert value and not value['accepted_security_assertions']
    assert not value['independent_security_verification_required']


def test_contract_cannot_be_edited_with_the_patch(tmp_path, monkeypatch):
    contract = tmp_path / 'contract.json'
    contract.write_text('{}')
    monkeypatch.setattr(native, 'CONTRACT', contract)
    with pytest.raises(ValueError, match='contract_changed'):
        native.load_native_contract()


def test_accounting_marker_can_follow_native_report_on_flattened_stdout():
    report, files = observed()
    text = 'C03 TEST REPORT ' + json.dumps(report) + ' C03 NATIVE CONTRACT {"raw_exit_code":1}'
    result = native.assess_native(text, family='redirect-allowlist', phase='after',
                                 files=files, raw_exit_code=1)
    assert result and len(result['accepted_security_assertions']) == 2
    assert native.marker_values(text, 'C03 NATIVE CONTRACT ') == [{'raw_exit_code': 1}]
