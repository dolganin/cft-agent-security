# A07 baseline series

## Status

**A07 COMPLETE WITH LIMITATIONS.** The operator reduced this iteration to one requested Agent run. One valid Agent run completed and was scored, sealed, checked for target integrity and cleaned up. The requested count is recorded as `requested_agent_runs: 1`; the completed valid count is `completed_valid_agent_runs: 1` in `artifacts/a07-series/aggregate.json`.

По решению оператора текущая A07 серия сокращена с трех независимых Agent runs до одного для уменьшения времени выполнения. Поэтому межзапусковая стабильность Agent в этой итерации не измеряется.

Three earlier attempts from the prior three-run request ended technically invalid at SAST and remain preserved. They are excluded from valid-run and scorecard-performance counts. The successful run used the final frozen project state after the infrastructure fix. No performance result is extrapolated from it, and no between-run stability statistic is reported.

Final freeze: `artifacts/a07-series/a07-config.json`; lock: `artifacts/a07-series/a07.lock.json`. Configuration digest: `d4847b45ebc0b5dec99e391823c3a0a5284aa3570d4065f00740c13483e17e5a`. Project commit: `d7fb6e913e6da923314cf71d4a8e7124ea22b1aa`.

## Frozen inputs and prerequisites

- A01 protocol: `juice-shop-v20.2.0-v2`; protocol and lock hashes are recorded in the A07 lock.
- A04: 41 cases (28 development, 13 holdout); dataset lock SHA-256 `1a5a42f1b8917472bbe6dbcacd22597c2695d70e524c5f783fd88b82db4da947`; ground-truth SHA-256 `579b9a51531010e8b4d53b27cb7607f410898cb144fe1db76cef9810e82a5366`.
- A05 matcher: `evaluation/benchmark_v2.py`, SHA-256 `7b47607a7f68f7e6b61c8053c0cd8adc81a3e35539e4d56fe46e318c058f8f61`; scorer: existing `evaluation/offline_rescore.py`.
- Target: OWASP Juice Shop v20.2.0, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`, image `bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`; exact source tree `299c108c28cd9783ec49ffa4c076956d084ef468`.
- Model and budgets stayed frozen: NSU/Qwen3.8-27B, low reasoning, temperature 0.1, max output 8,192 tokens, provider timeout 55 sec, Scout 2 turns / 4 candidates / 160,000 source characters / 60 sec, agent 120 sec / 2 iterations. No credentials are recorded.
- Agent SAST rules stayed at `docs/demo/semgrep.yaml`, SHA-256 `8c96c80e042e636c064813e339d65adf8d5d6edd60b4def3be214fc82786c829`. The A06 scanner baseline uses a separate locked profile.
- Runtime preflight: Docker `29.7.2/linux/amd64`; A01, full A04 source validation, A06 validation and preflight passed on the final freeze. A04 checked all 1,300 target files.

## SAST infrastructure issue and resolution

The first three attempts used the system Python, which had no Semgrep CLI, so each stopped with `DEPENDENCY_UNAVAILABLE` before the Agent workflow. The already-present A06 preflight image was the pinned Semgrep v1.174.0 digest `semgrep/semgrep@sha256:f1f7b71861c7b28b6e0f661225a2c4f58a484f5d0f182465c6d6b3b22f972ade`.

The minimal Windows runtime fix uses that exact local image when the CLI is unavailable. The scanner uses `--pull=never`, `--network none`, and read-only mounts for the Juice Shop source and the one trusted A07 rules file. It keeps the existing Semgrep rules and scan arguments. The fix and its tests are committed in `13ecc85` (`Use pinned Docker Semgrep when Windows CLI is missing`); the A07 unique retry-id support is in `d7fb6e9` (`Add A07 retry attempt support`). The final A07 freeze was regenerated after those commits.

## Attempt inventory

| Attempt | Configuration | Status | Duration | LLM requests | Technical result | Seal / cleanup |
|---|---|---|---:|---:|---|---|
| `agent-run-01-20261013T104530Z` | Initial freeze | technically invalid | 19.953 s | 0 | SAST `DEPENDENCY_UNAVAILABLE` | valid seal; cleanup passed |
| `agent-run-02-20261013T104803Z` | Initial freeze | technically invalid | 19.609 s | 0 | SAST `DEPENDENCY_UNAVAILABLE` | valid seal; cleanup passed |
| `agent-run-03-20261013T104859Z` | Initial freeze | technically invalid | 19.703 s | 0 | SAST `DEPENDENCY_UNAVAILABLE` | valid seal; cleanup passed |
| `agent-run-01-retry-01-20261013T105848Z` | Final freeze | **completed, valid** | 536.531 s | 46 | Pipeline completed; security gate exit code 1 | valid seal; cleanup passed |

The three invalid attempts were retained and not scored as security misses. For the one valid run, all 46 LLM requests succeeded; retries, timeouts, fallbacks, policy blocks and technical errors were zero. SAST completed with 7 findings. Scout used 2 turns and returned 4 candidates. The workflow recorded 12 proposals, 12 Validator approvals, 12 executions, 4 confirmed and 8 inconclusive Evidence outcomes. The final nonzero pipeline exit code is a completed security-gate decision, not a technical pipeline failure.

## A05 scorecards

The existing A05 offline scorer ran after the successful attempt was sealed. All four scorecard slices are technically valid. These are measurements from one run only:

| Split / sample | TP | FN | TN | FP | Precision | Recall | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Development / original | 1 | 19 | 2 | 0 | 1.000 | 0.050 | 0.095 |
| Development / patched | 0 | 0 | 2 | 0 | N/A | N/A | N/A |
| Development / synthetic | 0 | 0 | 4 | 0 | N/A | N/A | N/A |
| Holdout / original | 3 | 4 | 6 | 0 | 1.000 | 0.429 | 0.600 |

These values are not averages, do not describe run-to-run stability and were not used to tune the Agent, matcher, rules or configuration. The scorecard also records findings outside the frozen ground truth; see the raw A05 outputs for full detail.

## A06 baseline provenance

`reused_baseline_series: true`. The three existing sealed A06 runs match the final frozen A04/A05 inputs, target commit/image, A06 v5 scanner profile and rules, image digests, budgets, anonymous role and internal-only scope. Their seals remain in their original directories; they were not copied or rerun.

| A06 run | Manifest SHA-256 | Seal-file SHA-256 | Status |
|---|---|---|---|
| `a06-7c17446b29a04516` | `af965cc3f25a62bb3b03a651c397ec5505c3c4c3a87546c8ae984c502e82071c` | `18d62982fcadd0bd973643fb71bbdb4eea64da8cfdd3d8bc89aab5fc5557fdf5` | `COMPLETED_WITH_LIMITATIONS` |
| `a06-3065852c9fcf4e5f` | `6bc812c4072989da7874a84e0ea8dd02cfe3a2c49b969212941711336e66b4b7` | `785d90a6e8103033b7290ed3cb03c2c8e69ba41b0a9232fa7abe424c535f8e6b` | `COMPLETED_WITH_LIMITATIONS` |
| `a06-e8400e2187274b7c` | `e767ceca8e1736c9a9d567ee4a049b529b52e82edbc2a2d09ca52858be9d03dd` | `89615d30af1f17e77e81c0047f2fe48d7f345e89287ddc6fe638979c4cdce1e9` | `COMPLETED_WITH_LIMITATIONS` |

## Safety, integrity and scope

The initial tool review blocked a launch before process creation because bounded source-derived Juice Shop context could reach the frozen NSU endpoint. No source context was sent before the user explicitly authorized this bounded transfer, without ground truth, labels or secrets. No user `.env` value was read. The producer received no ground-truth or HOLDOUT labels, expected severity, or hidden evaluator fixtures.

The valid run used a fresh target reset, fresh internal Docker network and fresh evaluator session, with no published ports. The original target integrity check passed. The target container, Semgrep container, networks and volumes were removed; cleanup reported no remaining resources. The Agent did not bypass Validator or Executor. No external target was scanned, and no B/C work, remediation or A08 analysis was performed.

The post-run artifact audit found one PEM private-key block embedded in the Juice Shop source finding report. That target fixture block was redacted while preserving the report structure; the manifest records the redaction, the run was resealed, and A05 scoring was rerun against the redacted sealed artifacts. The final secret-pattern audit found no remaining credential patterns. No user secret or `.env` value was read.

## Artifacts and checks

- Final freeze: `artifacts/a07-series/a07-config.json`, `artifacts/a07-series/a07.lock.json`.
- Valid Agent run: `artifacts/a07-series/agent-run-01-retry-01/` (manifest, run status, 58 sealed raw files and seal).
- A05 scoring: `artifacts/a07-series/score-agent-run-01-retry-01/`.
- Three prior invalid attempts and their scorer outputs remain in their own directories.
- Machine-readable rollup: `artifacts/a07-series/aggregate.json`.
- Reused A06 source runs remain under `artifacts/a06-series/run-01..03/`.

Validation: final A07 freeze verification passed; A05 tests passed (22 passed, 1 skipped); SAST runner tests passed (7 passed); Ruff, `py_compile`, run-seal checks, target-integrity checks and the A07 secret-pattern audit passed. The audit checked generated artifacts without reading user secrets. The earlier combined A01/A04/A05/A06 suite had 117 passed and 1 skipped, with one Windows fixture path-access failure (`WinError 5` in `test_target_unicode_names_and_hidden_worktree_mutation`) deselected; it was not changed for A07.

**A07 COMPLETE WITH LIMITATIONS.** One valid run and its A05 scorecards are complete. Межзапусковая стабильность Agent в этой итерации не измеряется.
