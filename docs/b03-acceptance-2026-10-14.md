# B03 source-discovery acceptance — 14 October 2026

## Result

B03 is complete for its source-discovery comparison scope on the frozen Juice Shop v20.2.0 development set. The `round_robin` and `handlers` Scout modes each completed eight model turns against the same pinned source snapshot and saved SAST baseline. Every candidate is linked to successfully read source; unread source ranges, budgets, model telemetry, and stop reasons are retained in the run artifacts.

This is a DEV-only source-discovery measurement. It is not runtime verification, a confirmed-finding precision result, or a holdout/generalization result. The agent did not execute Juice Shop or send exploit requests. All matched scorecard cases have `confirmation_supported: false` and `verification: not_run`.

## Paired comparison

Frozen target: Juice Shop v20.2.0, commit `5658473cf8814459bf89000ce373b20ed0b4eb37`. Dataset: locked v2 DEV original split, 20 positive source cases and 2 safe controls. The model received ordinary application source only; it did not receive benchmark labels, case IDs, or answer files.

| Mode | DEV positive cases matched | DEV discovery recall | Safe controls matched | DEV control FPR | New candidates | Runtime |
|---|---:|---:|---:|---:|---:|---:|
| SAST baseline | 1/20 | 5% | 0/2 | 0% | — | 283.341 s scan |
| SAST + Scout `round_robin` | 3/20 | 15% | 0/2 | 0% | 12 | 59.026 s |
| SAST + Scout `handlers` | 4/20 | 20% | 0/2 | 0% | 19 | 66.736 s |

The matching-only precision in the frozen catalog was 3/3 for `round_robin` and 4/4 for `handlers`. Do not report that as precision among confirmed findings: no findings were confirmed, only two safe controls were present, and 82/88 additional Scout observations fell outside the catalog and were not labeled false positives. The `round_robin` `JS-PATH-001` source match also depends on a file-write challenge that is disabled in the pinned Docker environment; treat it as a source-code match, not an active-runtime result.

Relative to SAST, the frozen matcher found two additional DEV cases with `round_robin` and three with `handlers`. This is one paired experiment, so it does not establish a causal improvement or repeatability across runs. The earlier pilot and prior-index attempts are retained as superseded artifacts and are not pooled with these metrics.

## Source review and coverage

The final code review covered all 31 candidate observations (12 `round_robin`, 19 `handlers`) against the pinned source and relevant route registration, middleware, helper, and local dependency. The record is [source-review.json](../artifacts/b03-dev-review-source-2026-10-14-attempt-07/source-review.json). It separates source-supported hypotheses from overclaims, Docker-disabled branches, and unresolved impact. It is a read-only source review, not independent runtime evidence; its classifications do not alter the frozen matcher or create terminal agent verdicts.

The source index remains capped at 256 files and 4 MiB. A regression found that lexically earlier frontend files displaced backend models, including `models/user.ts`. Ranking was corrected to reserve earlier slots for server-side models, services, libraries, and data helpers. On the pinned target the index still contains 256 files, now includes `models/user.ts` and 20 model files, and contains 140 frontend files instead of 165. The fixed model source was read during the final `handlers` run. A synthetic test covers this cap boundary.

| Mode | Indexed lines | Reviewed lines | Indexed line coverage | Fully reviewed files | Model tokens |
|---|---:|---:|---:|---:|---:|
| `round_robin` | 20,861 | 1,865 | 8.94% | 11 | 218,434 |
| `handlers` | 20,861 | 3,184 | 15.26% | 28 | 199,506 |

Token totals come from provider-reported usage. Currency cost is unavailable because no verified price was used. The SAST baseline completed with exit code 0 and 75 normalized findings, but emitted 58 warnings, including partial-parser diagnostics and timeouts; its coverage is incomplete and should be reported with that limitation.

## Reproduction and artifacts

Offline rescoring uses the committed producer and reviewer code plus the saved artifacts. A new online run uses the same target, model route, turn/source/candidate budgets and a newly provisioned NSU credential; the ignored local `.env` is not included.

```bash
PYTHONPATH=/tmp/cft-b03-deps-hY6bdB PYTHONDONTWRITEBYTECODE=1 CFT_AGENT_MODE=stub \
  .venv/bin/python -m evaluation.b03_review \
  --inputs artifacts/b03-dev-2026-10-14-attempt-07 \
  --target artifacts/benchmark-target/juice-shop \
  --output artifacts/b03-dev-review-reproduced
```

To reproduce the model comparison, run `python -m app.b03_acceptance` for each fresh output directory using `--model qwen3.8-flash-next --max-turns 8 --sast-from artifacts/b03-dev-2026-10-14-sast-cache`. The SAST cache includes its pinned image/rules identity, raw redacted output, normalized findings, and target snapshot.

Final pair: [attempt-07](../artifacts/b03-dev-2026-10-14-attempt-07/). Offline scorecards and bindings: [review-07](../artifacts/b03-dev-review-final-2026-10-14-attempt-07/). The [attempt ledger](../artifacts/b03-dev-review-source-2026-10-14-attempt-07/attempt-ledger.json) separates failed attempts, pilot results, and the sole final metric pair. Seals and source digests are retained with the artifacts.

The measured implementation identity is `e76a9747b535ece61432a7bae16f1a066131b4f0f37e104ba10016f2c6bda0ee`; target commit and dataset lock are stored in `attempt-07/implementation.json`. The checkout HEAD at measurement start was `f72ffd17996d898b4fb370900cd56708cc45e5c2`; the source-index change was present in the measured file hashes and is included in this B03 branch. Historical A01/A08 locks and artifacts were not modified.

After the recorded pair, a compatibility adjustment restored the frozen A02 catalog's diagnostic inventory while making all live Scout/API source-map call sites explicitly exclude answer-serving controllers. This preserves the live input policy used by attempt-07, but changes the checkout's byte-level implementation identity; attempt-07 remains bound to its original sealed identity. Two independent offline rescoring passes on the saved attempt produced byte-identical outputs and matched the committed review. A fresh online pair would be required to claim a measurement under the new checkout hash.

The final attempt and scorecard seals validate with no missing or extra files. The source review and attempt ledger have a separate [integrity seal](../artifacts/b03-dev-review-source-2026-10-14-attempt-07/seal.json), bound to the attempt-07 seal, candidate bindings, and pinned target commit.

## Scope limits

- No HOLDOUT labels were opened or scored.
- No runtime checks, new confirmations, severity/Context Priority scoring, fixes, or MTTR measurement were performed.
- No repeated pair was run with identical implementation and settings; model output may vary between runs.
- B03 closes source discovery and comparison only. Verification and repair remain separate workflow stages.
