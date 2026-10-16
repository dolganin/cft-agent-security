"""Operator-owned C05 series; evaluator data never enters C04 model requests."""
from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean, median
from time import monotonic

from agent.llm import ProviderFailoverClient, parse_route_specs
from app.config import Settings
from app.stage1_e2e import pinned_image
from fix_verification.generation import write_json
from fix_verification.patch_context import original_input
from fix_verification.repair_loop import run, seal
from fix_verification.repair_replay import replay
from fix_verification.scope import BASELINE, SOURCE_COMMIT, assess_scope, load_scope
from fix_verification.workspace import digest, safe_file
from schemas.repair_loop import RepairLimits

FAMILIES = ('sql-search', 'redirect-allowlist')
ROUTE = 'nsu:qwen3.8-flash-next'
REPETITIONS = 3
LIMITS = RepairLimits(max_attempts=3, wall_clock_seconds=900)


def now():
    return datetime.now(UTC).isoformat()


def population():
    """Replay C01 proof first; review labels only supply evaluator case mapping."""
    scope = assess_scope()
    specs, _lock = load_scope()
    with zipfile.ZipFile(BASELINE) as archive:
        review = json.loads(archive.read('b09-single-2026-10-15-final/evaluation/confirmed-review.json'))
    confirmed = sorted({m['case_id'] for row in review
                        if row['persisted_execution_audit_and_approval_trace_match']
                        for m in row['matches'] if m['classification'] == 'tp'})
    cases = []
    for family in FAMILIES:
        spec = next(s for s in specs if s.id == family)
        entry = next(e for e in scope.entries if e.family_id == family)
        _spec, report, report_sha, _snapshot = original_input(family)
        if entry.status != 'eligible' or len(spec.case_ids) != 1 or spec.case_ids[0] not in confirmed:
            raise ValueError('C05 requires the unchanged two eligible C01 cases')
        cases.append({'family': family, 'case_id': spec.case_ids[0], 'finding_id': report.finding_id,
                      'report_sha256': report_sha,
                      'historical_confirmed_at': min(e.created_at.isoformat() for e in report.evidence
                                                   if e.verdict == 'confirmed' and e.source == 'runtime'),
                      'related_finding_ids': entry.finding_ids})
    return {'unit': 'unique frozen benchmark case, not finding or family category',
            'confirmed_case_ids': confirmed, 'cases': cases, 'scope': scope.model_dump(mode='json')}


def freeze(target: Path, output: Path):
    source, root = target.resolve(strict=True), output.resolve()
    if root.is_relative_to(source) or source.is_relative_to(root):
        raise ValueError('Series must be outside target')
    root.mkdir(parents=True, exist_ok=False)
    plan = {'schema_version': 'cft.c05.protocol.v1', 'frozen_at': now(),
            'implementation_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'source_commit': SOURCE_COMMIT, 'route': ROUTE, 'repetitions': REPETITIONS,
            'limits': LIMITS.model_dump(mode='json'), 'fix_image': pinned_image('cft-fix-juice:stage1'),
            'baseline_sha256': digest(BASELINE.read_bytes()), 'population': population(),
            'slots': [{'id': f'{repetition:02d}-{family}', 'family': family, 'repetition': repetition}
                      for repetition in range(1, REPETITIONS + 1) for family in FAMILIES],
            'selection': 'All two eligible unique cases, fixed interleaved order; no replacement runs',
            'time_origin': 'C05 accepts archived evidence-backed confirmed input before calling C04',
            'historical_mttr': None, 'production_mttr': None}
    shutil.copyfile(BASELINE, root / 'b09-full-search.zip')
    write_json(root / 'protocol.json', plan)
    (root / 'protocol.sha256').write_text(digest((root / 'protocol.json').read_bytes()), encoding='ascii')
    return plan


def protocol(root: Path):
    raw = safe_file(root, 'protocol.json').read_bytes()
    if digest(raw) != safe_file(root, 'protocol.sha256').read_text(encoding='ascii'):
        raise ValueError('Frozen protocol changed')
    plan = json.loads(raw)
    expected_slots = [{'id': f'{r:02d}-{f}', 'family': f, 'repetition': r}
                      for r in range(1, REPETITIONS + 1) for f in FAMILIES]
    if (plan['slots'] != expected_slots or plan['route'] != ROUTE
            or plan['limits'] != LIMITS.model_dump(mode='json')
            or plan['population'] != population() or plan['source_commit'] != SOURCE_COMMIT
            or plan['baseline_sha256'] != digest(BASELINE.read_bytes())
            or digest(safe_file(root, 'b09-full-search.zip').read_bytes()) != plan['baseline_sha256']):
        raise ValueError('Protocol or baseline does not match operator registry')
    return plan


def execute(target: Path, root: Path):
    """Single sequential series; completed or interrupted slots are never retried."""
    plan = protocol(root)
    for slot in plan['slots']:
        directory = root / 'runs' / slot['id']
        receipt = root / 'receipts' / (slot['id'] + '.json')
        if receipt.exists() or directory.exists():
            raise ValueError('C05 does not replace or silently resume attempted slots')
        started_at, started = now(), monotonic()
        row = {**slot, 'started_at': started_at, 'finished_at': None,
               'protocol_sha256': digest((root / 'protocol.json').read_bytes()), 'replay': None,
               'error': None}
        write_json(receipt, row)
        try:
            client = ProviderFailoverClient(routes=parse_route_specs(ROUTE, allow_external_fallbacks=False),
                credentials=Settings().llm_provider_credentials(), timeout_seconds=45,
                max_output_tokens=3072, reasoning_effort='low', trace=False)
            run(target=target, family=slot['family'], output=directory, client=client,
                limits=LIMITS, fix_image=plan['fix_image'])
            row['replay'] = replay(directory)
        except KeyboardInterrupt:
            row['error'] = 'operator_interrupted'
            raise
        except (ValueError, OSError, RuntimeError, subprocess.SubprocessError):
            row['error'] = 'technical_failure'
        finally:
            row['finished_at'] = now()
            row['duration_ms'] = int((monotonic() - started) * 1000)
            write_json(receipt, row)
        print(json.dumps({'slot': slot['id'], 'result': row['replay'], 'error': row['error']}), flush=True)


def statistics(values):
    return ({'n': len(values), 'mean_ms': mean(values), 'median_ms': median(values),
             'min_ms': min(values), 'max_ms': max(values)} if values else
            {'n': 0, 'mean_ms': None, 'median_ms': None, 'min_ms': None, 'max_ms': None})


def summarize(root: Path):
    plan = protocol(root)
    rows = []
    for slot in plan['slots']:
        receipt_path = root / 'receipts' / (slot['id'] + '.json')
        row = {**slot, 'status': 'NOT_RUN', 'attempts': 0, 'regression_attempts': 0,
               'duration_ms': None, 'verified_ms': None, 'fresh_before_to_verified_ms': None,
               'historical_confirmed_to_verified_ms': None, 'stop_reason': 'missing_receipt'}
        if receipt_path.is_file():
            receipt = json.loads(safe_file(root, receipt_path.relative_to(root).as_posix()).read_bytes())
            if (any(receipt.get(k) != v for k, v in slot.items())
                    or receipt['protocol_sha256'] != digest((root / 'protocol.json').read_bytes())):
                raise ValueError('Receipt does not match frozen slot')
            row['status'] = 'TECHNICAL_ERROR'
            row['stop_reason'] = receipt['error'] or 'unfinished'
            row['duration_ms'] = receipt.get('duration_ms')
            directory = root / 'runs' / slot['id']
            if receipt['replay'] is not None:
                checked = replay(directory)
                if checked != receipt['replay']:
                    raise ValueError('Saved replay receipt changed')
                result = json.loads(safe_file(directory, 'result.json').read_bytes())
                if result['family'] != slot['family'] or result['limits'] != plan['limits']:
                    raise ValueError('Run does not match series configuration')
                if json.loads(safe_file(directory, 'runtime.json').read_bytes())['fix_image'] != plan['fix_image']:
                    raise ValueError('Series runtime image changed')
                row.update(status=checked['status'], stop_reason=checked['stop_reason'],
                           attempts=checked['attempts'], seal_sha256=checked['seal_sha256'])
                row['regression_attempts'] = sum(a['verification_status'] == 'REGRESSION' for a in result['attempts'])
                row['original_unchanged'] = result['original_unchanged']
                row['attempt_history'] = [{k: a[k] for k in ('number', 'generation_status', 'verification_status',
                    'decision', 'reason', 'duration_ms', 'generation_ms', 'verification_ms', 'workspace_cleanup')}
                    for a in result['attempts']]
                if row['status'] == 'FIXED':
                    start, finish = datetime.fromisoformat(receipt['started_at']), datetime.fromisoformat(receipt['finished_at'])
                    elapsed = (finish - start).total_seconds() * 1000
                    if elapsed < 0 or abs(elapsed - row['duration_ms']) > 5000:
                        raise ValueError('Series clock disagreement')
                    row['verified_ms'] = row['duration_ms']
                    historical = next(c for c in plan['population']['cases'] if c['family'] == slot['family'])
                    row['historical_confirmed_to_verified_ms'] = (
                        finish - datetime.fromisoformat(historical['historical_confirmed_at'])).total_seconds() * 1000
                    before = []
                    for attempt in result['attempts']:
                        manifest = directory / attempt['directory'] / 'verification/manifest.json'
                        if manifest.exists():
                            evidence = json.loads(manifest.read_bytes())['result']['before_evidence']
                            if evidence and evidence['verdict'] == 'confirmed':
                                before.append(datetime.fromisoformat(evidence['created_at']))
                    if not before or min(before) < start or max(before) > finish:
                        raise ValueError('Missing fresh confirmation timing')
                    row['fresh_before_to_verified_ms'] = (finish - min(before)).total_seconds() * 1000
        rows.append(row)
    statuses = {s: sum(r['status'] == s for r in rows)
                for s in ('FIXED', 'NOT_FIXED', 'TECHNICAL_ERROR', 'INTERRUPTED', 'NOT_RUN')}
    families = {f: {'verified': sum(r['status'] == 'FIXED' for r in rows if r['family'] == f),
                    'eligible_runs': REPETITIONS} for f in FAMILIES}
    return {'schema_version': 'cft.c05.measurement.v1', 'protocol_sha256': digest((root / 'protocol.json').read_bytes()),
            'complete': all(r['status'] != 'NOT_RUN' for r in rows),
            'eligible_confirmed': {'eligible': len(FAMILIES), 'confirmed': len(plan['population']['confirmed_case_ids']),
                                   'unit': 'unique benchmark case'},
            'verified_eligible': {'verified': statuses['FIXED'], 'eligible': len(plan['slots']), 'unit': 'case-run'},
            'statuses': statuses, 'families': families, 'rows': rows,
            'regression_attempts': sum(r['regression_attempts'] for r in rows),
            'attempts': sum(r['attempts'] for r in rows),
            'time_confirmed_input_to_verified': statistics([r['verified_ms'] for r in rows if r['verified_ms'] is not None]),
            'fresh_before_to_verified': statistics([r['fresh_before_to_verified_ms'] for r in rows
                                                    if r['fresh_before_to_verified_ms'] is not None]),
            'historical_mttr': None, 'production_mttr': None,
            'limitations': ['Known development corpus; not unseen holdout or general repair quality',
                            'Success timing excludes failures; all failure durations remain in rows',
                            'Historical elapsed times include idle days and are not laboratory latency or production MTTR']}


def finalize(root: Path):
    report = summarize(root)
    write_json(root / 'measurement.json', report)
    seal(root)
    return report
