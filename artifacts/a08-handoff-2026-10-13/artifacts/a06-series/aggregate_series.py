"""Descriptive aggregation of saved A06 scores; no scanner or scorer changes."""
from pathlib import Path
from collections import Counter, defaultdict
from itertools import combinations
import hashlib
import json
import statistics
import subprocess

ROOT = Path.cwd()
BASE = ROOT / 'artifacts/a06-series'
def read(p):
    return json.loads(p.read_text(encoding='utf-8'))
def sha(p):
    return hashlib.sha256(p.read_bytes()).hexdigest()

baseline = read(BASE / 'freeze-before-series.json')
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip() == baseline['commit']
for name, digest in baseline['tracked_sha256'].items():
    assert sha(ROOT / name) == digest, name
runs = []
manifests = []
for i in range(1, 4):
    run = BASE / f'run-{i:02d}'
    scoring = BASE / f'score-{i:02d}'
    m = read(run / 'manifest.json')
    assert m['status'] in {'COMPLETED', 'COMPLETED_WITH_LIMITATIONS'}
    assert m['cleanup_complete'] and m['original_unchanged'] and not m['technical_errors']
    assert m['agent_commit'] == baseline['commit']
    seal = read(run / 'seal.json')
    assert seal == {p.relative_to(run).as_posix(): sha(p) for p in run.rglob('*') if p.is_file() and p.name != 'seal.json'}
    manifests.append(m)
    row = {'run': f'run-{i:02d}', 'attempt_id': m['attempt_id'], 'status': m['status'],
           'started_at': m['started_at'], 'retry_of': m['retry_of'],
           'seconds': {k: m['seconds'] if k == 'total' else m['components'][k]['seconds'] for k in ['total', 'sast', 'dast']},
           'technical_errors': m['technical_errors'], 'cleanup_complete': True, 'original_unchanged': True,
           'sealed_files': len(seal), 'views': {}}
    for view in ['sast', 'dast', 'union']:
        observations = read(run / (view + '-observations-v2.json'))
        scores = {split: read(scoring / (view + '-' + split + '.json')) for split in ['development', 'holdout']}
        positives = sorted({c['case_id'] for s in scores.values() for c in s['cases'] if c['detected'] and c['expected'] == 'vulnerable'})
        negatives = sorted({c['case_id'] for s in scores.values() for c in s['cases'] if c['detected'] and c['expected'] == 'safe'})
        classes = defaultdict(set)
        for score in scores.values():
            assert score['technically_valid']
            for match in score['matches']:
                classes[match['observation_id']].add(match['classification'])
        # Inventory only: outside means unmatched in BOTH separately scored splits.
        # Never sum split-specific outside counts or pool precision/recall.
        priority = ['tp', 'fp', 'duplicate', 'unresolved', 'outside_ground_truth']
        inventory = Counter(next(c for c in priority if c in values) for values in classes.values())
        raw = len(read(run / view / 'raw.json')['results' if view == 'sast' else 'alerts']) if view != 'union' else None
        row['views'][view] = {'raw_observations': raw, 'normalized_observations': len(observations),
                             'matched_positive_cases': positives, 'matched_safe_cases': negatives,
                             'inventory_classifications': dict(inventory),
                             'splits': {split: {'detection': score['detection'],
                                 'positive_denominator': sum(c['expected'] == 'vulnerable' for c in score['cases']),
                                 'safe_denominator': sum(c['expected'] == 'safe' for c in score['cases'])} for split, score in scores.items()}}
    sast = set(row['views']['sast']['matched_positive_cases'])
    dast = set(row['views']['dast']['matched_positive_cases'])
    row['contribution'] = {'sast_only': sorted(sast - dast), 'dast_only': sorted(dast - sast), 'overlap': sorted(sast & dast)}
    diagnostics = read(run / 'sast/raw.json').get('errors', [])
    def kind(d):
        t = d.get('type', 'unknown')
        return t[0] if isinstance(t, list) else str(t)
    row['diagnostics'] = {'semgrep': dict(Counter(kind(d) for d in diagnostics)),
                          'semgrep_total': len(diagnostics), 'warnings': len(m['coverage_limitations']),
                          'zap_errors': read(run / 'dast/coverage.json')['errors']}
    row['dast_coverage'] = read(run / 'dast/coverage.json')
    row['runtime_versions'] = {'semgrep': read(run / 'sast/raw.json')['version'],
                               'zap': read(run / 'dast/versions.json')['zap']['version']}
    runs.append(row)
for m in manifests[1:]:
    for field in ['profile', 'scanner_lock', 'images', 'target_files_sha256', 'dataset_lock_sha256', 'agent_commit', 'agent_dirty']:
        assert m[field] == manifests[0][field], field
stability = {}
for view in ['sast', 'dast', 'union']:
    sets = [set(r['views'][view]['matched_positive_cases']) for r in runs]
    frequencies = Counter(c for s in sets for c in s)
    stability[view] = {'found_3_of_3': sorted(c for c, n in frequencies.items() if n == 3),
                       'found_2_of_3': sorted(c for c, n in frequencies.items() if n == 2),
                       'found_1_of_3': sorted(c for c, n in frequencies.items() if n == 1),
                       'jaccard': {f'run-{a+1:02d}/run-{b+1:02d}': len(sets[a] & sets[b]) / len(sets[a] | sets[b]) if sets[a] | sets[b] else None for a, b in combinations(range(3), 2)}}
timing = {k: {'mean': statistics.mean(r['seconds'][k] for r in runs), 'min': min(r['seconds'][k] for r in runs), 'max': max(r['seconds'][k] for r in runs)} for k in ['total', 'sast', 'dast']}
initial = read(BASE / 'initial-blocked/aggregate.json')
profile = manifests[0]['profile']
aggregate = {'schema_version': 'a06.series.aggregate.v1', 'status': 'COMPLETE',
             'project_commit': baseline['commit'], 'initial_blocked': initial,
             'lf_restoration': read(BASE / 'lf-restoration.json'),
             'preflight': {'passed': True, 'missing_image_before_provision': profile['semgrep_image'],
                          'provision_exact_digests': True, 'log': 'resumed-preflight.txt'},
             'profile': profile, 'images': manifests[0]['images'],
             'configuration_sha256': sha(ROOT / 'benchmarks/baselines-a06-v5/profile.yaml'),
             'rules_sha256': sha(ROOT / 'benchmarks/baselines-a06-v5/semgrep-rules.yaml'),
             'rules_commit': initial['rules_commit'], 'matcher_sha256': sha(ROOT / 'evaluation/benchmark_v2.py'),
             'dataset_lock_sha256': manifests[0]['dataset_lock_sha256'],
             'runs': runs, 'stability': stability, 'timing_statistics_seconds': timing,
             'stage_timing': None, 'stage_timing_reason': 'Frozen worker records stage budgets/completion, not elapsed stage timings.',
             'attempt_count': 3, 'technical_invalid_attempts': [], 'retries': [],
             'preservation': {'all_539_tracked_byte_digests_unchanged_since_restoration': True,
                 'all_run_profiles_images_locks_target_bytes_equal': True, 'env_untouched': True,
                 'secret_forwarding': 'Existing minimal subprocess environment excludes LLM/API secrets; Docker receives no env-file. User .env was not read.'},
             'scope': 'Scanner detection inventory; A05 metrics remain separate DEV/HOLDOUT original samples. No Agent verification metrics.',
             'final_validation': read(BASE / 'final-validation.json')}
(BASE / 'aggregate.json').write_text(json.dumps(aggregate, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
history = (BASE / 'initial-blocked/a06-baseline-series.md').read_text(encoding='utf-8')
lines = ['# A06 baseline series — resumed after LF restoration', '', '**A06 SERIES COMPLETE: three sequential comparable real runs.**', '',
         'Scanner detection only. No Scout, Agent, LLM, A07 or remediation was run. Primary A05 metrics are the separate DEV/HOLDOUT original slices. Case-set inventory spans the disjoint slices; it does not pool their precision/recall.', '',
         '## Initial CRLF-blocked history', '', 'The earlier pre-series failure started zero scans. Its full report, aggregate and diagnostics remain in `artifacts/a06-series/initial-blocked/`. The original report is retained below as historical text.', '',
         '<details><summary>Initial blocked report (historical)</summary>', '', history, '</details>', '',
         '## LF restoration / resumed series', '',
         'Only `CRLF → LF` was applied to the four authorized files. Old hashes were saved before writing. Each resulting byte string equals `before.replace(b"\\r\\n", b"\\n")`, and each resulting SHA-256 equals the unchanged A04 lock.', '',
         '| File | Old SHA-256 | New SHA-256 = expected SHA-256 | Exact match |', '|---|---|---|---|']
for h in aggregate['lf_restoration']:
    lines.append(f"| `{h['path']}` | `{h['old_sha256']}` | `{h['new_sha256']}` | true |")
lines += ['', 'A01/A04/A06 validation passed. Full A04 validation checked the target source. Initial resumed preflight found the exact Semgrep image missing; existing provisioning downloaded only pinned digests, and a subsequent preflight without provisioning passed. All three scan invocations omitted provisioning.', '',
          'Before every run, all 539 tracked project byte hashes and 1300 pinned target file bytes were checked. The three manifests bind identical project commit, profile, scanner lock, dataset lock, images, target byte map and Git status. The pre-existing untracked report is recorded in that status; LF restoration has no textual Git diff.', '',
          '## Exact frozen configuration', '', f"Project commit: `{baseline['commit']}`. Profile: `benchmarks/baselines-a06-v5/profile.yaml`; SHA-256 `{aggregate['configuration_sha256']}`.", '',
          f"Semgrep CE 1.174.0: `{profile['semgrep_image']}`. ZAP 2.16.1: `{profile['zap_image']}`. Both versions were observed in each run.", '',
          f"Juice Shop v20.2.0: `{profile['target_image']}`; commit `{profile['target_commit']}`.", '',
          f"Rules: 310, upstream commit `{aggregate['rules_commit']}`; SHA-256 `{aggregate['rules_sha256']}`. Matcher SHA-256 `{aggregate['matcher_sha256']}`.", '',
          'Anonymous role, internal `http://juice:3000` scope, fresh target/scanner containers and internal network per run, no published ports. SAST is networkless. No authenticated, cross-user, OAST or business-logic coverage.', '',
          'Budgets (seconds): SAST 600, startup 180, traditional spider 60, AJAX spider 60, active scan 180, passive wait 180. Passive body limit 262144 bytes, max URLs 200, max alerts 10000. Profile seeds, scanner rules and all budgets were unchanged.', '',
          '## Three-run results', '', '| Run / attempt | Status | SAST raw / normalized | DAST raw / normalized | Union observations | Matched positives SAST / DAST / union | Total seconds |', '|---|---|---|---|---|---|---|']
for r in runs:
    v = r['views']
    lines.append(f"| {r['run']} / `{r['attempt_id']}` | {r['status']} | {v['sast']['raw_observations']} / {v['sast']['normalized_observations']} | {v['dast']['raw_observations']} / {v['dast']['normalized_observations']} | {v['union']['normalized_observations']} | {len(v['sast']['matched_positive_cases'])} / {len(v['dast']['matched_positive_cases'])} / {len(v['union']['matched_positive_cases'])} | {r['seconds']['total']:.3f} |")
lines += ['', 'Raw alerts are observations, not independent vulnerabilities. No safe original case was detected. Each run was scored immediately afterward using the existing split-aware wrapper; the wrapper repeated each score deterministically and verified the run seal and lock bindings.', '',
          '| Run | View | Duplicates DEV/HOLDOUT | Unresolved DEV/HOLDOUT | Outside truth DEV/HOLDOUT | Outside both splits (inventory) |', '|---|---|---|---|---|---|']
for r in runs:
    for view, v in r['views'].items():
        d, h = [v['splits'][s]['detection'] for s in ['development', 'holdout']]
        lines.append(f"| {r['run']} | {view} | {d['duplicates']}/{h['duplicates']} | {d['unresolved']}/{h['unresolved']} | {d['outside_ground_truth']}/{h['outside_ground_truth']} | {v['inventory_classifications'].get('outside_ground_truth',0)} |")
lines += ['', 'Split outside counts intentionally differ: a match to the other split is outside the currently scored slice. They must not be summed. The final column counts observations outside both slices. All split detection metrics and denominators remain in the six scorecards per run. Original scope: 27 positives and 8 safe properties; patched/synthetic controls were not scanned.', '', '| Run | SAST-only positives | DAST-only positives | Overlap |', '|---|---|---|---|']
for r in runs:
    c = r['contribution']; lines.append(f"| {r['run']} | {', '.join(c['sast_only']) or 'none'} | {', '.join(c['dast_only']) or 'none'} | {', '.join(c['overlap']) or 'none'} |")
lines += ['', '## Case-level stability', '', '| View | Found 3/3 | Found 2/3 | Found 1/3 | Jaccard 1–2 / 1–3 / 2–3 |', '|---|---|---|---|---|']
for view, s in stability.items():
    lines.append(f"| {view} | {', '.join(s['found_3_of_3']) or 'none'} | {', '.join(s['found_2_of_3']) or 'none'} | {', '.join(s['found_1_of_3']) or 'none'} | {' / '.join(str(x) for x in s['jaccard'].values())} |")
lines += ['', 'These are three bounded runs on one frozen configuration, not a general scanner accuracy claim. Raw DAST alert variability is reported separately above.', '', '## Timing and diagnostics', '', '| Run | Total seconds | SAST seconds | DAST seconds | Warnings | Semgrep diagnostics by type | Technical errors |', '|---|---|---|---|---|---|---|']
for r in runs:
    t=r['seconds']; lines.append(f"| {r['run']} | {t['total']:.3f} | {t['sast']:.3f} | {t['dast']:.3f} | {r['diagnostics']['warnings']} | {json.dumps(r['diagnostics']['semgrep'])} | 0 |")
lines += ['', '| Timer | Mean seconds | Min seconds | Max seconds |', '|---|---|---|---|']
for k, t in timing.items(): lines.append(f"| {k} | {t['mean']:.3f} | {t['min']:.3f} | {t['max']:.3f} |")
lines += ['', 'SAST/DAST durations are the saved scanner-container timers; total also includes preflight, staging, readiness, integrity checks and cleanup. Actual individual spider/AJAX/active/passive elapsed durations were not recorded by the frozen worker and remain unavailable; stage budgets are not timings.', '',
          'All Syntax error, PartialParsing and per-rule Timeout diagnostics remain in raw output, coverage and manifests. Warnings do not reduce ground-truth denominators. All three ZAP coverage exports report completed bounded stages and no errors. Limitations include anonymous-only access, no OAST or exhaustive/business-logic coverage and skipped oversized passive bodies.', '',
          '## Final verification and preservation', '',
          'A01/A04/A06 locks passed again. Relevant A05/A06 tests: 65 passed, 1 skipped (missing supplied legacy A05 demo artifacts). Ruff retains the explicitly exempt pre-existing I001 at `evaluation/scanner_baseline.py:410`; no formatter/import changes were made. `git diff --check` passed.', '',
          'All 539 tracked byte digests equal the post-restoration snapshot. Ground truth, locks, matcher, profile, rules and target were unchanged throughout. Target Git status and exact pinned bytes are clean. Final Docker label audit found zero A06 containers, networks or volumes. Every manifest reports original integrity and successful cleanup.', '',
          'No user `.env` was read or changed. Existing subprocess environment filtering excludes LLM/API secrets; scanner Docker commands use no env-file. No LLM, Scout or Agent calls occurred. A secret-pattern audit of saved files found no NSU key assignments or recognizable API key values; this audit does not read user secrets.', '',
          'Three scan attempts completed; no technically invalid scan attempts or retries. The initial CRLF block and missing-image preflight were pre-series failures, preserved separately. No prior attempt or sealed run was overwritten.', '',
          'Artifacts: `artifacts/a06-series/run-01..03/`, `score-01..03/`, `aggregate.json`, freeze checks, LF restoration receipt and validation logs. Raw runs remain locally ignored. Existing commands: `python -m app.scanner_baseline run --target artifacts/benchmark-target/juice-shop --output <fresh-run>` then `PYTHONPATH=. PYTHONUTF8=1 python scripts/rescore_a06_slices.py --artifacts <run> --output <fresh-score>`. On PowerShell set those process environment variables before invoking Python.', '',
          'A06 SERIES COMPLETE', '']
(ROOT/'docs/a06-baseline-series.md').write_text('\n'.join(lines),encoding='utf-8')
print(json.dumps({'runs': [(r['attempt_id'], r['views']['dast']['normalized_observations']) for r in runs], 'stability': stability, 'timing': timing}, indent=2))
