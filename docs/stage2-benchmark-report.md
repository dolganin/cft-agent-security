# Stage 2 — Benchmark: implementation and measured limits

Status on 2026-10-09: **Stage 2 completed with three real full runs** through the
canonical CI pipeline and NSU/Qwen3.8-27B. Stage 3–5 were not started. No scanner,
security rule or verification capability was added to improve the score. Stage 1
code and all existing production security contracts are unchanged.

## Reviewed implementation

The real path is `app.ci_pipeline.run_ci_pipeline`: trusted TargetProfile →
ProjectDiscovery → managed Docker/session map → `app.pipeline_run.run_pipeline` →
Semgrep normalization → RepositoryScout and Express source-map hints →
`merge_scout_candidates` → per-finding graph → Validator → Executor → persisted
Evidence/interpreter/guard → FinalReport → CI Gate. API persistence in `api/store.py`
indexes these artifacts; it is not a second analysis path.

Reviewed contracts and seams include `schemas/finding.py`, `schemas/evidence.py`,
`schemas/report.py`, `schemas/security_tools.py`, `schemas/target.py`,
`agent/repository_scout.py`, `agent/llm_model.py`, `agent/verification.py`,
`discovery/scout.py`, `tools/repository_source.py`, `sast/semgrep_runner.py`,
`evidence/interpreter.py`, `evidence/guard.py`, `executor/executor.py`,
`executor/sandbox_audit.py`, `pipeline/progress.py`, `pipeline/gate.py`,
`evaluation/runner.py`, and the demo and Stage 1 entrypoints/artifacts.

The older evaluator compares saved reports with expected IDs/status/severity; it
does not implement the new source-based detection measurement. It remains intact.
The new layer uses existing intermediate artifacts rather than modifying graph
nodes, prompt contracts, verdicts, API persistence or CI Gate.

## New files

| File | Purpose |
|---|---|
| `schemas/benchmark.py` | Producer-neutral dataset/observation/match/run/aggregate contracts |
| `evaluation/benchmark.py` | Deterministic maximum matching, separate detection/verification metrics, stability |
| `evaluation/benchmark_harness.py` | Infrastructure probe, truth isolation, frozen manifests, canonical runner, artifact adapter, seals/resume |
| `app/stage2_benchmark.py` | Official CLI with dataset/runs/output/target/resume/preflight-only |
| `benchmarks/juice-shop-v20.2.0/benchmark.yaml` | Frozen demo-equivalent operator configuration |
| `benchmarks/juice-shop-v20.2.0/ground_truth.yaml` | Ten positives and two narrow SQL-safe controls |
| `benchmarks/juice-shop-v20.2.0/dataset.lock.json` | Frozen truth/configuration and source digests |
| `benchmarks/juice-shop-v20.2.0/README.md` | Scope, exact matching policy, formulas, preparation and limitations |
| `benchmarks/juice-shop-v20.2.0/scorecard.py` | Read-only final reporting over sealed runs, exact provider requests and case-level supporting Evidence |
| `tests/test_stage2_benchmark.py` | Scorer, grounding, leakage, persistence and integrity tests |
| `docs/stage2-benchmark-report.md` | This report; includes only actual observations |

## Ground truth and matching

Dataset `juice-shop-v20.2.0-v1`, target commit
`5658473cf8814459bf89000ce373b20ed0b4eb37`. Ground truth SHA-256:
`3a13a0a41d5fd86d4ab75e23dbc7a61cc81439f034a574b9341a369c82b1aafe`.

Ten positives: SQL injection (2), sensitive directory enumeration (3), access
control (2), open redirect (1), code injection (1), password reauthentication (1).
Two negative controls concern only SQL injection at a constant SQL query and an
ORM lookup. This is non-exhaustive. Unknown findings are not presumed false.
TN/specificity refer only to these two defined controls. Precision is conditional
on adjudicated cases; no full Juice Shop precision or recall is asserted.

Truth is source/challenge grounded and frozen before scoring; it is never passed
to Scout, reasoning context, proposals or the production TargetProfile. Tests check
the explicit argument boundary and captured Scout/Agent inputs. Existing upstream
challenge-related application code is not rewritten by the benchmark; this is a
known limitation of benchmarking on an intentionally vulnerable public application.

Matching requires normalized file + inclusive intersecting ranges + frozen family
compatibility + declared service. There is no line tolerance or LLM judge. Sorted
maximum-cardinality matching prevents order-dependent lost assignments, one finding
from counting as two TP, and multiple findings from counting as multiple TP for one
case. Extra matches are duplicates. Expected labels and verification outcomes do
not determine matching. Full formulas and null semantics are in the dataset README.

## Actual results

Pentester base commit: `f6ecdbbdfdcaafb0f1f2c6df8d0e81a262b61a1a`.
The runs used the then-uncommitted `feature/stage2-benchmark` implementation;
all manifests bind its worktree digest as well as the base commit. The subsequent
publication commit does not change the recorded producer identity of those runs.

Real local Semgrep 1.174.0, existing `docs/demo/semgrep.yaml`, exact pinned clean
checkout: **7 findings**, zero parser/runtime errors. This is a single diagnostic
SAST measurement, not a completed full Pentester benchmark.

| SAST diagnostic metric | Value |
|---|---:|
| TP | 5 |
| FP on labeled controls | 0 |
| FN relative to v1 positives | 5 |
| TN on two SQL controls | 2 |
| Adjudicated precision | 1.0 |
| Recall relative to v1 scope | 0.5 |
| F1 | 0.6666666666666666 |
| Duplicates | 0 |
| Unique findings | 7 |
| Outside ground truth | 2 |
| Confirmation / verified recall | N/A: verification not run |

Matched: JS-SQL-001, JS-SQL-002, JS-FILE-001, JS-FILE-002, JS-FILE-003.
Missed: JS-ACCESS-001, JS-ACCESS-002, JS-AUTH-001, JS-CODE-001, JS-REDIRECT-001.
Unreviewed/outside: directory-listing observations at `server.ts:268` and `:292`.
They are not automatically classified FP. This scoped SAST rule selection is
expected to miss categories it does not scan; no new rules were added afterwards.

Raw/normalized data and deterministic case results are saved at
`artifacts/stage2-checks/diagnostic-sast/`. This diagnostic measurement supplies no
Scout delta, verification performance, LLM latency/cost, or repeatability claim.

Full-run preflight passed target commit/clean source/ranges/provenance/services,
operator Compose, Docker 29.7.2, installed image digests, Semgrep and a real neutral
NSU/Qwen3.8-27B readiness request. Initially missing credentials and then HTTP 401
blocked preflight; after the operator updated the local key, readiness succeeded.
Those failed preflights were never counted as benchmark runs or all-FN samples.
The user explicitly authorized source/context transfer and all three full runs.
No credential was displayed, copied to artifacts, or committed; `.env` was unchanged.

### Three full runs

All three used configuration SHA-256
`3654aa810bf7d480fcf2cab309e9fd4dbd70822b84eaa6d61d654d671ebb3cf1`.
Target, ground truth, aliases, line tolerance, model route, budgets, profile,
policy, rules, Docker images and producer code were unchanged between runs.
All three completed with canonical CI exit `1` (security failure), not `2`
(technical pipeline failure). Pipeline technical failure rate: **0/3**.

| Measurement | Run 001 | Run 002 | Run 003 |
|---|---:|---:|---:|
| SAST findings / Scout candidates | 7 / 4 | 7 / 4 | 7 / 4 |
| Detection TP / FP / FN / TN | 5 / 0 / 5 / 2 | 5 / 0 / 5 / 2 | 5 / 0 / 5 / 2 |
| Adjudicated precision / scope recall | 1.0 / 0.5 | 1.0 / 0.5 | 1.0 / 0.5 |
| F1 | 0.6666666666666666 | 0.6666666666666666 | 0.6666666666666666 |
| Benchmark duplicates / unique findings | 1 / 10 | 0 / 11 | 0 / 11 |
| Outside ground truth | 5 | 6 | 6 |
| Correctly evidence-confirmed positives | 3 | 2 | 2 |
| False confirmations / unsupported | 0 / 0 | 0 / 0 | 0 / 0 |
| Inconclusive / timeout / technical error | 7 / 1 / 0 | 8 / 1 / 0 | 8 / 0 / 1 |
| Rejected / policy blocked | 0 / 0 | 0 / 0 | 0 / 0 |
| Confirmation rate | 0.6 | 0.4 | 0.4 |
| End-to-end verified recall | 0.3 | 0.2 | 0.2 |
| Total seconds | 489.7030000000086 | 470.57799999999406 | 513.7970000000059 |
| Actual NSU request attempts | 55 | 57 | 57 |
| Successful NSU requests | 55 | 56 | 57 |
| Deterministic fallback notifications | 0 | 1 | 0 |
| Tool / Executor Docker actions | 15 / 15 | 15 / 15 | 15 / 15 |
| Scout reviewed / indexed source lines | 767 / 22529 | 853 / 22529 | 917 / 22529 |

Verification counts describe raw findings, including unreviewed findings and a
duplicate; TP/confirmation rates count distinct cases. No source-only confirmation
was observed: all seven positive case-run confirmations used the existing bounded
runtime SQL or sensitive-directory capabilities and matching persisted execution/
audit digests. Directory confirmation proves sensitive-name enumeration, not
successful downloads. Unsupported=0 does not imply coverage for missed categories:
five known positives were never matched, so their verification was never attempted.

There were **169 actual NSU request attempts**, 168 successful structured responses,
one network error and one explicit deterministic fallback in run 002. The existing
production fallback was retained and is not presented as a model answer. Primary
`performance.llm_calls` counts diagnostic events (55/58/57); the exact request count
excludes the non-request fallback event and is available in `scorecard.json`.
No token usage or monetary cost is invented.

Mean total analysis duration: **491.3593333333362 s** (8.18932222222227 minutes),
min 470.57799999999406, max 513.7970000000059, population standard deviation
17.68291209677817 s. Mean Discovery/SAST/Scout/Agent-verification durations:
0.26066666666883975 / 5.927333333340357 / 37.067666666664685 /
430.38533333333424 s. Other lifecycle/report time remains in the total.
Mean confirmation rate: **0.4666666666666667**; mean verified recall relative to
v1 scope: **0.23333333333333334**. Means are not full-project recall claims.

### A/B/C value and instability

SAST alone found the same five benchmark positives in every run. Scout added four
raw candidates each time, but **scope recall delta was 0.0 in all three runs**.
Its candidate set varied: pairwise exact normalized finding-anchor Jaccard values
for the full detection queue were 0.6153846153846154 (001/002), 0.5 (001/003), and
0.4666666666666667 (002/003). Ground-truth case detection was stable despite this
variation in unreviewed observations.

Runtime verification consistently confirmed `/ftp` and `/encryptionkeys`.
The run 001 Scout SQL candidate at `routes/login.ts:34` also confirmed login SQL
injection through `verify_sql_injection`. This did not add a TP: it was a benchmark
duplicate of SAST's login finding. Source-path normalization differs in production
on Windows: SAST retained backslashes while Scout emitted POSIX paths. Production
merge reported zero duplicates and the SAST SQL findings did not obtain the same
trusted specialized binding. Benchmark normalization recognizes the duplicate and
credits its Evidence once. This production limitation was recorded, not repaired
after seeing the score.

The run 003 Scout identified an open-redirect helper at
`lib/insecurity.ts:133–139`. The frozen truth anchor is the caller at
`routes/redirect.ts:13–19`; the strict same-file matcher does not award a TP for the
helper. The observation is retained as outside ground truth. This illustrates an
anchor-level matching limitation; it does not justify claiming the model never
noticed the redirect root cause. No helper alias or line tolerance was added.

| Case | Expected | Found | Evidence confirmed | Verification measurement statuses |
|---|---|---:|---:|---|
| JS-SQL-001, product search | vulnerable | 3/3 | 0/3 | timeout / inconclusive / inconclusive |
| JS-SQL-002, login | vulnerable | 3/3 | 1/3 | confirmed via Scout duplicate / timeout / technical_error |
| JS-FILE-001, FTP listing | vulnerable | 3/3 | 3/3 | confirmed / confirmed / confirmed |
| JS-FILE-002, key filenames | vulnerable | 3/3 | 3/3 | confirmed / confirmed / confirmed |
| JS-FILE-003, log listing | vulnerable | 3/3 | 0/3 | inconclusive / inconclusive / inconclusive |
| JS-ACCESS-001, basket read | vulnerable | 0/3 | 0/3 | not detected |
| JS-ACCESS-002, basket write | vulnerable | 0/3 | 0/3 | not detected |
| JS-AUTH-001, password change | vulnerable | 0/3 | 0/3 | not detected |
| JS-CODE-001, username eval | vulnerable | 0/3 | 0/3 | not detected |
| JS-REDIRECT-001, redirect caller | vulnerable | 0/3 | 0/3 | caller anchor not detected; helper observed in run 003 |
| JS-SAFE-SQL-001, constant query | safe | 0/3 | 0/3 | TN in every run |
| JS-SAFE-SQL-002, ORM lookup | safe | 0/3 | 0/3 | TN in every run |

Five positives were found in 3/3, zero in only 1/3 or 2/3, and five never matched.
Two positives were confirmed in 3/3. Two cases changed verification measurement
status (`unstable_verdicts=2` in the aggregate, including timeout/error changes);
only login changed Evidence-confirmation state. Original FinalReport verdicts are
preserved separately and were not rewritten into measurement error labels.

### Artifacts and reproducible reporting

Official execution command (scanner environment must be in PATH):

```text
python -m app.stage2_benchmark --dataset juice-shop-v20.2.0-v1 --runs 3 --target artifacts/benchmark-target/juice-shop --output artifacts/benchmarks/juice-shop-v20.2.0-v1
python benchmarks/juice-shop-v20.2.0/scorecard.py --output artifacts/benchmarks/juice-shop-v20.2.0-v1
```

Artifacts under `artifacts/benchmarks/juice-shop-v20.2.0-v1/`:
`configuration.json`, frozen YAML copies, `run-001..003/manifest.json`, raw findings,
matches, metrics, reports, canonical pipeline/Evidence/audit data and per-run seals;
`aggregate.json/.md`; `scorecard.json/.md`; cleanup and credential-check JSON.
The final scorecard joins **all** primary/duplicate matches so a duplicate's
confirmation includes its own Evidence references, rather than only the primary's
inconclusive evidence. Its read-only reporter validates seals before and after
generation and records its own code digest. No sealed run was rewritten.

All three configuration digests and target source digests matched. Producer code
still matched its frozen worktree digest after reporting. Docker checks confirmed
that no containers or networks remained for the three exact Compose projects.
Credential-value scans over benchmark text/JSON/YAML artifacts passed; only safe
provider status/route/timing metadata is recorded. `.env` remains uncommitted.

Two harness infrastructure fixes were made before scored runs: successful LLM
diagnostics use the production adapter's actual `ok` status, and readiness uses
the configured output-token budget. Preflight now records only safe attempt
metadata (route/status/latency/HTTP code); these variable probe details are excluded
from the repeated-run configuration digest. Dataset, matching policy and Pentester
security behavior were not changed.

## Validation

Commands executed from repository root unless noted:

```text
python -m pytest tests/test_stage2_benchmark.py -q
CFT_AGENT_MODE=stub python -m pytest -q -rs
python -m ruff check .
git diff --check
python -m app.main
python -m app.stage1_e2e --output-dir artifacts/stage2-checks/stage1-regression
cd frontend
npm test -- --reporter=dot
npm run typecheck
npm run build
```

Frontend: **28 passed**, typecheck and build passed. Real Stage 1 regression:
BEFORE CONFIRMED, reviewed isolated patch, all ten preparation/build/test/start/smoke
stages passed, AFTER REJECTED, FIXED, security_verified=true, original unchanged,
cleanup complete. Artifact:
`artifacts/stage2-checks/stage1-regression/stage1-d6674f0bec5847c3b8ff5884bc50bd5a/`.

Final backend check: **492 passed / 21 skipped / 0 failed**. Benchmark-specific
tests: **50 passed**, including a regression against the production LLM adapter's
`ok` diagnostic status. Ruff, `git diff --check` and `python -m app.main` passed.
The configured `.env` selects LLM mode; an unqualified backend run therefore
changed eight existing deterministic graph/report tests into live-mode behavior
and produced 484 passed / 8 failed / 21 skipped. This was diagnosed as test-process
configuration, not a benchmark security change. Backend regression uses
`CFT_AGENT_MODE=stub` only in its own process (PowerShell: `$env:CFT_AGENT_MODE='stub'`).
Full benchmark configuration remains frozen to `agent_mode=llm`; `.env` is unchanged.
Skips: six digest-configured Docker boundary checks, Windows symlink/resource-limit
checks, missing SberLab/Autodealer opt-in targets, other digest-configured sandbox
integration checks, and the opt-in two-cycle Stage 1 test. The separate real Stage 1
entrypoint above did run successfully. No production code was changed.

## Open-source methodology and license

The [OWASP Benchmark methodology](https://owasp.org/projects/benchmark) informed
fixed labeled cases and scanner normalization. Reviewed
[BenchmarkUtils](https://github.com/OWASP-Benchmark/BenchmarkUtils), GPL-3.0.
The [Capital One VulnHunter harness](https://github.com/capitalone/VulnHunter/tree/main/harness/local_harness/benchmark),
Apache-2.0, informed commit pinning, intermediate artifacts, checkpoint reuse and
per-case tally/stability. Its example corpus labels NodeGoat/Juice Shop/WebGoat
entries as synthetic placeholders; none were imported. Its LLM judge was not
adopted. Only architecture ideas were reused; no third-party code was copied.

## Remaining Stage 2 limits

The corpus is small/non-exhaustive and has just two narrow negatives; adjudicated
precision can look high despite low recall. Unreviewed findings are not proven FP,
and zero false confirmations on two controls is not a broad safety estimate.
Strict caller anchors can miss related helper observations. Production Windows
path/binding differences and one provider fallback affected verification. Neither
was hidden or fixed to improve this score. Run-level resume
does not recover an interrupted stage. Artifact seals detect mutation, but are not
signed/WORM storage. Token usage and full Docker lifecycle counts are unavailable
in current diagnostics, so remain null. The benchmark does not infer monetary cost
or change findings after seeing a score. No Nuclei, ZAP, XSS/BOLA capability or PR
automation was installed or started.
