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
