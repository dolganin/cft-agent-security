"""Protected exceptions for two upstream vulnerability-expectation assertions.

No tests are skipped or edited. Only a complete observed suite with precisely
these assertion outcomes may continue to independent HTTP/canonical AFTER.
"""
import json
import re
from pathlib import Path

from fix_verification.workspace import digest, safe_file

CONTRACT = Path(__file__).resolve().parents[1] / 'contracts/c03/native-security-contract.json'
CONTRACT_SHA256 = 'c923cd3aadc0c70d2b620664e1e6ca456002ea6f599d6512a8ebd61e88213a3e'


def load_native_contract():
    raw = CONTRACT.read_bytes().replace(b'\r\n', b'\n')
    if digest(raw) != CONTRACT_SHA256:
        raise ValueError('native_security_contract_changed')
    return json.loads(raw)


def marker_values(stdout, marker):
    # Executor's redactor may flatten newlines. Decode one JSON value rather
    # than greedily consuming the following independent accounting marker.
    decoder = json.JSONDecoder()
    return [decoder.raw_decode(stdout[m.end():].lstrip())[0]
            for m in re.finditer(re.escape(marker), stdout)]


def assess_native(stdout, *, family, phase, files, raw_exit_code):
    """Return explicit stage accounting or None; malformed/extra failures fail closed."""
    contract = load_native_contract()
    try:
        reports = marker_values(stdout, 'C03 TEST REPORT ')
        if len(reports) != 1 or raw_exit_code not in {0, 1}:
            return None
        report = reports[0]
        summary = report['summary']
        counts = summary['counts']
        expected_files = sorted(f for f in files if f.startswith('test/server/') and f.endswith('.unit.test.ts'))
        failed = counts['failed']
        if (type(failed) is not int or not expected_files or report['files'] != expected_files
                or counts['cancelled'] != 0 or counts['todo'] != 0 or counts['skipped'] != 2
                or counts['passed'] <= 0 or len(report['skipped']) != 2
                or counts['tests'] != counts['passed'] + failed + 2):
            return None
        accepted = []
        if failed == 0:
            if not summary['success'] or raw_exit_code != 0 or report.get('assertion_failures', []):
                return None
        else:
            if (family != contract['family'] or phase != contract['phase'] or failed != 2
                    or summary['success'] or raw_exit_code != 1):
                return None
            observed = report['assertion_failures']
            if len(observed) != 2:
                return None
            for expected in contract['failures']:
                value = files[expected['file']]
                sha = value[0] if isinstance(value, (list, tuple)) else value
                if sha != expected['source_sha256']:
                    return None
                matches = [r for r in observed if r['file'] == expected['file'] and r['name'] == expected['name']]
                if len(matches) != 1:
                    return None
                row = matches[0]
                if (row['line'] != expected['line'] or row['code'] != expected['code']
                        or row['actual'] is not False or row['expected'] is not True
                        or row['failure_type'] != 'testCodeFailure'):
                    return None
                accepted.append({'file': expected['file'], 'name': expected['name'], 'line': expected['line']})
        return {'schema_version': 'cft.c03.native-contract-result.v1',
                'contract_sha256': CONTRACT_SHA256, 'family': family, 'phase': phase,
                'raw_exit_code': raw_exit_code, 'native_suite_success': bool(summary['success']),
                'accepted_security_assertions': accepted,
                'independent_security_verification_required': bool(accepted)}
    except (KeyError, TypeError, ValueError):
        return None


def source_test_hashes(root):
    root = Path(root)
    return {p.relative_to(root).as_posix(): digest(safe_file(root, p.relative_to(root).as_posix()).read_bytes())
            for p in sorted((root / 'test/server').rglob('*.unit.test.ts'))}
