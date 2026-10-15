"""Operator HTTP oracle. Executed only in a separate, read-only Docker worker.

No proxy, cookies, credentials, configurable URLs or redirect following. The
pure evaluation functions are also used by offline replay.
"""
import hashlib
import json
import os
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

APPROVED = (
    'https://github.com/juice-shop/juice-shop',
    'https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm',
    'https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW',
    'https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6',
    'http://shop.spreadshirt.com/juiceshop',
    'http://shop.spreadshirt.de/juiceshop',
    'https://www.stickeryou.com/products/owasp-juice-shop/794',
    'http://leanpub.com/juice-shop',
)
SQL_CASES = (
    ('name-description-order', 'CFTApple', [9001, 9004]),
    ('description', 'CFTGreen', [9002]),
    ('empty-active-order', '', [9001, 9002, 9005, 9004]),
    ('no-match', 'cft-no-such-product', []),
    ('apostrophe', "CFTFarmer's", [9002]),
    ('boundary-200', 'L' * 200, [9005]),
    ('truncation-201', 'L' * 200 + 'Z', [9005]),
    ('boolean-original', "')) OR 1=1--", []),
    ('boolean-independent', "')) OR (2>1)--", []),
    ('union-independent', "')) UNION SELECT * FROM EvaluatorSentinel--", []),
)
HOSTILE = (
    'https://unapproved.invalid/?next=' + APPROVED[0],
    'https://unapproved.invalid/#' + APPROVED[0],
    'https://github.com@unapproved.invalid/juice-shop/juice-shop',
    APPROVED[0] + '.unapproved.invalid',
    '//unapproved.invalid/?next=' + APPROVED[0],
    'not-a-url',
    'https://unapproved.invalid',
)


def cases(family):
    if family == 'sql-search':
        return [(name, '/rest/products/search?' + urlencode({'q': q}), list(ids))
                for name, q, ids in SQL_CASES]
    if family == 'redirect-allowlist':
        return [(f'allowed-{i}', '/redirect?' + urlencode({'to': url}), url)
                for i, url in enumerate(APPROVED)] + [
            (f'hostile-{i}', '/redirect?' + urlencode({'to': url}), None)
            for i, url in enumerate(HOSTILE)]
    raise ValueError('unknown_family')


def evaluate(family, observations, baseline_ids=None):
    expected = cases(family)
    if len(observations) != len(expected):
        raise ValueError('http_ledger_incomplete')
    tests = []
    for (name, path, value), observation in zip(expected, observations, strict=True):
        if family == 'sql-search' and name == 'empty-active-order' and baseline_ids is not None:
            value = baseline_ids
        if (observation['id'] != name or observation['path_sha256'] != hashlib.sha256(path.encode()).hexdigest()
                or observation['sequence'] != len(tests) + 1):
            raise ValueError('http_ledger_mismatch')
        healthy = not observation['truncated'] and observation['bytes'] <= 65536
        if family == 'sql-search':
            passed = (healthy and observation['status'] == 200 and observation['contract']
                      and observation['ids'] == value and not observation['sentinel'])
            kind = 'security' if name.startswith(('boolean-', 'union-')) else 'functional'
        else:
            passed = healthy and (observation['status'] == 302 and observation['locations'] == [value]
                                  if value else observation['status'] == 406 and observation['locations'] == [])
            kind = 'functional' if value else 'security'
        tests.append({'id': name, 'kind': kind, 'passed': bool(passed)})
    return tests


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def run(family):
    if not Path('/.dockerenv').exists() or os.getenv('CFT_C03_WORKER') != '1':
        raise RuntimeError('Docker worker required')
    opener = build_opener(ProxyHandler({}), NoRedirect())
    observations = []
    deadline = time.monotonic() + 40
    for name, path, _ in cases(family):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('http_budget_exhausted')
        request = Request('http://juice:3000' + path, headers={'Accept': 'application/json', 'Accept-Language': 'en'})
        try:
            response = opener.open(request, timeout=min(3, remaining))
        except HTTPError as error:
            response = error
        with response:
            raw = response.read(65537)
            row = {'sequence': len(observations) + 1, 'id': name,
                   'path_sha256': hashlib.sha256(path.encode()).hexdigest(),
                   'status': response.status, 'bytes': len(raw), 'truncated': len(raw) > 65536,
                   'locations': response.headers.get_all('Location', []),
                   'contract': False, 'ids': [], 'sentinel': False}
            if family == 'sql-search':
                try:
                    data = json.loads(raw)
                    products = data['data']
                    row['contract'] = (data.get('status') == 'success' and isinstance(products, list)
                        and all(isinstance(p, dict) and type(p.get('id')) is int
                                and isinstance(p.get('name'), str) and isinstance(p.get('description'), str)
                                for p in products))
                    row['ids'] = [p['id'] for p in products]
                    row['sentinel'] = b'private-evaluator-sentinel' in raw or 999 in row['ids']
                except (ValueError, KeyError, TypeError):
                    pass
            observations.append(row)
    fixture = json.loads(Path('/input/fixture.json').read_text()) if family == 'sql-search' else {}
    return {'schema_version': 'cft.c03.http.v1', 'family': family,
            'observations': observations, 'tests': evaluate(family, observations, fixture.get('baseline_ids')),
            'fixture': fixture,
            'redirect_followed': False, 'destination_dns': False}


if __name__ == '__main__':
    import sys
    result = run(sys.argv[1])
    print(json.dumps(result, separators=(',', ':')))
    raise SystemExit(0 if all(t['passed'] for t in result['tests']) else 1)
