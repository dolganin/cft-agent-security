# A06 baseline series — resumed after LF restoration

**A06 SERIES COMPLETE: three sequential comparable real runs.**

Scanner detection only. No Scout, Agent, LLM, A07 or remediation was run. Primary A05 metrics are the separate DEV/HOLDOUT original slices. Case-set inventory spans the disjoint slices; it does not pool their precision/recall.

## Initial CRLF-blocked history

The earlier pre-series failure started zero scans. Its full report, aggregate and diagnostics remain in `artifacts/a06-series/initial-blocked/`. The original report is retained below as historical text.

<details><summary>Initial blocked report (historical)</summary>

# A06 baseline series — 13 October 2026

**A06 SERIES INCOMPLETE. Zero scans started.**

Validation and preflight stopped at `Frozen input digest mismatch: .gitattributes` before Docker image inspection. The requested series requires a successful preflight. Frozen inputs were left unchanged under the explicit stop-on-problem instruction. No A07, agent, Scout or LLM run was started.

Project commit: `e6736eaae1d09c12368426b51de63261b0cbf4f5`. The initial project Git status was clean.

## Frozen configuration inspected

Profile: `benchmarks/baselines-a06-v5/profile.yaml`; SHA-256 `89baa9223001632e6a3960c13694861f2c910bc8511a98dfc3ba1c800e884c09`. These are configured values, not observed runtime versions.

- Semgrep CE 1.174.0: `semgrep/semgrep@sha256:f1f7b71861c7b28b6e0f661225a2c4f58a484f5d0f182465c6d6b3b22f972ade`.
- ZAP 2.16.1: `ghcr.io/zaproxy/zaproxy@sha256:7840969c7c9fead565bf9734b12f49f6886db90b1d35b1f74d79710bbd081dab`.
- Juice Shop v20.2.0: `bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`; commit `5658473cf8814459bf89000ce373b20ed0b4eb37`.
- Rules upstream commit `9bbf021d0acffa3095fcffd17b2bc7787eb4796d`, 310 rules; SHA-256 `1039d8b38468225f7462f44f14d25615aeb0e7cab81a6b919eb317228d2b8694`.
- Role: anonymous; scope: internal `http://juice:3000`, no published ports. SAST is networkless. No authenticated workflows.
- Budgets (seconds): SAST 600, startup 180, traditional spider 60, AJAX spider 60, active scan 180, passive wait 180. Passive body limit 262144 bytes; max URLs 200, max alerts 10000.
- Images were not pulled or provisioned. Image presence/runtime versions were not reached by preflight.

## Blocking exact-byte mismatch

A01 protocol validation passed. A04 validates SHA-256 of exact bytes; four of its 114 bound inputs differ. Converting CRLF to LF **in memory for diagnosis only** gives the expected hash in all four cases. No file was rewritten.

| Input | Expected SHA-256 | Working SHA-256 |
|---|---|---|
| `.gitattributes` | `5008ae7ff1de7bf23bbd8e97ded53ed3c0b20a16f668517635f2ef4c249f496f` | `d9c4607e5862579415c521adc01c2c89960e28f9f3a6376a3c349d8d8fc8a542` |
| `evaluation/benchmark_protocol.py` | `622ce7ff7985c108f430f17e90ab084fd6c96ed660187999ef81f75e001e59cf` | `00a8de1d2ed6951d76bb0bd24fdf815bd690209d5ec3e21dd4134d3dfb4524b4` |
| `schemas/benchmark.py` | `1532c28112eb27ea8f3b7c0682fb93aaabd2b3453b5cb77ff1005558238624c8` | `5bb0336c2f1092a05558325d7a6b8fb7a68b1a86a90000ada40e50f5287523d6` |
| `schemas/benchmark_control_expansion.py` | `4cd41d0f43a8a48239f142d1281d4058cbf13c813e1e22ebe042621b8a50fb30` | `299fc332370c98f8ae5dd3a65412beaa5f5a59126fbcdabde165284f44a58f3e` |

The `.gitattributes` Git blob also has the expected LF hash. Git reports a clean working tree because it normalizes line endings; this does not satisfy the exact-byte lock. A04, A06 validation and A06 preflight all stop at the first mismatch.

## Runs, scoring, stability and timing

| Planned run | Run ID/status | SAST/DAST/union observations | Matched positives | Duration |
|---|---|---|---|---|
| run-01 | Not started | N/A | N/A | N/A |
| run-02 | Not started | N/A | N/A | N/A |
| run-03 | Not started | N/A | N/A | N/A |

Attempts: 0. Retries: 0. No raw/normalized scanner outputs, scores or seals exist for this series. Warning counts, duplicates, unresolved/outside-ground-truth counts, unique contributions, 3/3–2/3–1/3 stability, Jaccard and timing statistics are unavailable. They are not reported as zero.

The existing split-aware offline command was identified but not executed:

```powershell
$env:CFT_AGENT_MODE='stub'
$env:PYTHONPATH='.'
python scripts/rescore_a06_slices.py --artifacts artifacts/a06-series/run-01 --output artifacts/a06-series/score-01
```

This existing wrapper checks the seal and locks, then calls A05 separately for original DEV/HOLDOUT samples and each SAST/DAST/union view. The legacy `app.scanner_baseline score` expects the older unsliced API; frozen scanner code was not edited.

## Verification and preservation

- Relevant A05/A06 tests outside the Windows sandbox: **46 passed, 19 failed, 1 skipped**. All 19 failures raise the A04 `.gitattributes` digest mismatch. Full diagnostics: `artifacts/a06-series/validation-tests.txt`. The first sandbox execution additionally encountered an atomic rename permission failure; it was repeated outside the sandbox.
- Ruff: existing **I001** import-order error at `evaluation/scanner_baseline.py:410`; preserved. Diagnostics: `artifacts/a06-series/ruff.txt`.
- `git diff --check`: passed.
- Juice Shop checkout exists at the requested commit; Git tracked/untracked status is clean. The byte-level target preflight did not complete because A04 validation failed first.
- Docker read-only queries for label `cft.a06.run` returned zero containers, networks and volumes. No scanner/target runtime was created by this series.
- Ground truth, locks, matcher, scanner configuration, source and user `.env` were not changed. No user `.env` was read or copied, no LLM secrets were supplied to scanners, and no scanner containers were started. Generated artifacts contain lock/config metadata and test diagnostics only.

Machine-readable status: `artifacts/a06-series/aggregate.json`. Run/score directories were not fabricated. Resuming requires restoration of the locked LF bytes and successful validation as a separate correction; this report does not alter the freeze.

A06 SERIES INCOMPLETE

</details>

## LF restoration / resumed series

Only `CRLF → LF` was applied to the four authorized files. Old hashes were saved before writing. Each resulting byte string equals `before.replace(b"\r\n", b"\n")`, and each resulting SHA-256 equals the unchanged A04 lock.

| File | Old SHA-256 | New SHA-256 = expected SHA-256 | Exact match |
|---|---|---|---|
| `.gitattributes` | `d9c4607e5862579415c521adc01c2c89960e28f9f3a6376a3c349d8d8fc8a542` | `5008ae7ff1de7bf23bbd8e97ded53ed3c0b20a16f668517635f2ef4c249f496f` | true |
| `evaluation/benchmark_protocol.py` | `00a8de1d2ed6951d76bb0bd24fdf815bd690209d5ec3e21dd4134d3dfb4524b4` | `622ce7ff7985c108f430f17e90ab084fd6c96ed660187999ef81f75e001e59cf` | true |
| `schemas/benchmark.py` | `5bb0336c2f1092a05558325d7a6b8fb7a68b1a86a90000ada40e50f5287523d6` | `1532c28112eb27ea8f3b7c0682fb93aaabd2b3453b5cb77ff1005558238624c8` | true |
| `schemas/benchmark_control_expansion.py` | `299fc332370c98f8ae5dd3a65412beaa5f5a59126fbcdabde165284f44a58f3e` | `4cd41d0f43a8a48239f142d1281d4058cbf13c813e1e22ebe042621b8a50fb30` | true |

A01/A04/A06 validation passed. Full A04 validation checked the target source. Initial resumed preflight found the exact Semgrep image missing; existing provisioning downloaded only pinned digests, and a subsequent preflight without provisioning passed. All three scan invocations omitted provisioning.

Before every run, all 539 tracked project byte hashes and 1300 pinned target file bytes were checked. The three manifests bind identical project commit, profile, scanner lock, dataset lock, images, target byte map and Git status. The pre-existing untracked report is recorded in that status; LF restoration has no textual Git diff.

## Exact frozen configuration

Project commit: `e6736eaae1d09c12368426b51de63261b0cbf4f5`. Profile: `benchmarks/baselines-a06-v5/profile.yaml`; SHA-256 `89baa9223001632e6a3960c13694861f2c910bc8511a98dfc3ba1c800e884c09`.

Semgrep CE 1.174.0: `semgrep/semgrep@sha256:f1f7b71861c7b28b6e0f661225a2c4f58a484f5d0f182465c6d6b3b22f972ade`. ZAP 2.16.1: `ghcr.io/zaproxy/zaproxy@sha256:7840969c7c9fead565bf9734b12f49f6886db90b1d35b1f74d79710bbd081dab`. Both versions were observed in each run.

Juice Shop v20.2.0: `bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`; commit `5658473cf8814459bf89000ce373b20ed0b4eb37`.

Rules: 310, upstream commit `9bbf021d0acffa3095fcffd17b2bc7787eb4796d`; SHA-256 `1039d8b38468225f7462f44f14d25615aeb0e7cab81a6b919eb317228d2b8694`. Matcher SHA-256 `7b47607a7f68f7e6b61c8053c0cd8adc81a3e35539e4d56fe46e318c058f8f61`.

Anonymous role, internal `http://juice:3000` scope, fresh target/scanner containers and internal network per run, no published ports. SAST is networkless. No authenticated, cross-user, OAST or business-logic coverage.

Budgets (seconds): SAST 600, startup 180, traditional spider 60, AJAX spider 60, active scan 180, passive wait 180. Passive body limit 262144 bytes, max URLs 200, max alerts 10000. Profile seeds, scanner rules and all budgets were unchanged.

Full A06 scanner-lock SHA-256: `c6381e5e8ad071a29df9e6f7611495ea393002fdf28d56bc002ab6f8e03eb771`. Start/end timestamps also confirm that scan runtimes did not overlap.

## Three-run results

| Run / attempt | Status | SAST raw / normalized | DAST raw / normalized | Union observations | Matched positives SAST / DAST / union | Total seconds |
|---|---|---|---|---|---|---|
| run-01 / `a06-7c17446b29a04516` | COMPLETED_WITH_LIMITATIONS | 94 / 94 | 494 / 409 | 503 | 4 / 1 / 4 | 229.844 |
| run-02 / `a06-3065852c9fcf4e5f` | COMPLETED_WITH_LIMITATIONS | 94 / 94 | 490 / 405 | 499 | 4 / 1 / 4 | 238.016 |
| run-03 / `a06-e8400e2187274b7c` | COMPLETED_WITH_LIMITATIONS | 75 / 75 | 497 / 412 | 487 | 4 / 1 / 4 | 265.203 |

Raw alerts are observations, not independent vulnerabilities. No safe original case was detected. Each run was scored immediately afterward using the existing split-aware wrapper; the wrapper repeated each score deterministically and verified the run seal and lock bindings.

| Run | View | Duplicates DEV/HOLDOUT | Unresolved DEV/HOLDOUT | Outside truth DEV/HOLDOUT | Outside both splits (inventory) |
|---|---|---|---|---|---|
| run-01 | sast | 1/4 | 0/0 | 92/87 | 85 |
| run-01 | dast | 0/0 | 0/0 | 409/408 | 408 |
| run-01 | union | 1/5 | 0/0 | 501/495 | 493 |
| run-02 | sast | 1/4 | 0/0 | 92/87 | 85 |
| run-02 | dast | 0/0 | 0/0 | 405/404 | 404 |
| run-02 | union | 1/5 | 0/0 | 497/491 | 489 |
| run-03 | sast | 1/4 | 0/0 | 73/68 | 66 |
| run-03 | dast | 0/0 | 0/0 | 412/411 | 411 |
| run-03 | union | 1/5 | 0/0 | 485/479 | 477 |

Split outside counts intentionally differ: a match to the other split is outside the currently scored slice. They must not be summed. The final column counts observations outside both slices. All split detection metrics and denominators remain in the six scorecards per run. Original scope: 27 positives and 8 safe properties; patched/synthetic controls were not scanned.

| Run | SAST-only positives | DAST-only positives | Overlap |
|---|---|---|---|
| run-01 | JS-FILE-001, JS-REDIRECT-001, JS-SQL-002 | none | JS-SQL-001 |
| run-02 | JS-FILE-001, JS-REDIRECT-001, JS-SQL-002 | none | JS-SQL-001 |
| run-03 | JS-FILE-001, JS-REDIRECT-001, JS-SQL-002 | none | JS-SQL-001 |

## Case-level stability

| View | Found 3/3 | Found 2/3 | Found 1/3 | Jaccard 1–2 / 1–3 / 2–3 |
|---|---|---|---|---|
| sast | JS-FILE-001, JS-REDIRECT-001, JS-SQL-001, JS-SQL-002 | none | none | 1.0 / 1.0 / 1.0 |
| dast | JS-SQL-001 | none | none | 1.0 / 1.0 / 1.0 |
| union | JS-FILE-001, JS-REDIRECT-001, JS-SQL-001, JS-SQL-002 | none | none | 1.0 / 1.0 / 1.0 |

These are three bounded runs on one frozen configuration, not a general scanner accuracy claim. Raw DAST alert variability is reported separately above.

## Timing and diagnostics

| Run | Total seconds | SAST seconds | DAST seconds | Warnings | Semgrep diagnostics by type | Technical errors |
|---|---|---|---|---|---|---|
| run-01 | 229.844 | 95.844 | 114.250 | 56 | {"Syntax error": 20, "Timeout": 1, "PartialParsing": 35} | 0 |
| run-02 | 238.016 | 91.969 | 127.453 | 57 | {"Syntax error": 20, "Timeout": 2, "PartialParsing": 35} | 0 |
| run-03 | 265.203 | 98.281 | 147.203 | 58 | {"Syntax error": 20, "Timeout": 3, "PartialParsing": 35} | 0 |

| Timer | Mean seconds | Min seconds | Max seconds |
|---|---|---|---|
| total | 244.354 | 229.844 | 265.203 |
| sast | 95.365 | 91.969 | 98.281 |
| dast | 129.635 | 114.250 | 147.203 |

SAST/DAST durations are the saved scanner-container timers; total also includes preflight, staging, readiness, integrity checks and cleanup. Actual individual spider/AJAX/active/passive elapsed durations were not recorded by the frozen worker and remain unavailable; stage budgets are not timings.

All Syntax error, PartialParsing and per-rule Timeout diagnostics remain in raw output, coverage and manifests. Warnings do not reduce ground-truth denominators. All three ZAP coverage exports report completed bounded stages and no errors. Limitations include anonymous-only access, no OAST or exhaustive/business-logic coverage and skipped oversized passive bodies.

## Final verification and preservation

A01/A04/A06 locks passed again. Relevant A05/A06 tests: 65 passed, 1 skipped (missing supplied legacy A05 demo artifacts). Ruff retains the explicitly exempt pre-existing I001 at `evaluation/scanner_baseline.py:410`; no formatter/import changes were made. `git diff --check` passed.

All 539 tracked byte digests equal the post-restoration snapshot. Ground truth, locks, matcher, profile, rules and target were unchanged throughout. Target Git status and exact pinned bytes are clean. Final Docker label audit found zero A06 containers, networks or volumes. Every manifest reports original integrity and successful cleanup.

No user `.env` was read or changed. Existing subprocess environment filtering excludes LLM/API secrets; scanner Docker commands use no env-file. No LLM, Scout or Agent calls occurred. A secret-pattern audit of saved files found no NSU key assignments or recognizable API key values; this audit does not read user secrets.

Three scan attempts completed; no technically invalid scan attempts or retries. The initial CRLF block and missing-image preflight were pre-series failures, preserved separately. No prior attempt or sealed run was overwritten.

Artifacts: `artifacts/a06-series/run-01..03/`, `score-01..03/`, `aggregate.json`, freeze checks, LF restoration receipt and validation logs. Raw runs remain locally ignored. Existing commands: `python -m app.scanner_baseline run --target artifacts/benchmark-target/juice-shop --output <fresh-run>` then `PYTHONPATH=. PYTHONUTF8=1 python scripts/rescore_a06_slices.py --artifacts <run> --output <fresh-score>`. On PowerShell set those process environment variables before invoking Python.

A06 SERIES COMPLETE
