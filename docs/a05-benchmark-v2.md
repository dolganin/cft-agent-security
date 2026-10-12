# A05 — Benchmark Harness & Scorer v2

A05 evaluates saved artifacts deterministically. It does not call an LLM, SAST,
Docker or the target application, and it does not change an agent verdict.

## Semantics

- Source and HTTP anchors are matched with family, service and sample context.
- More than one eligible independent case is `unresolved`.
- One case owns at most one detection; additional findings are `duplicate`.
- Unknown findings are `outside_ground_truth`, not automatic false positives.
- Detection and supported verification are separate measurements.
- `confirmed` and `rejected` count only with matching medium/high persisted
  Evidence, a successful execution record and its audit digest. Missing Evidence
  is `invalid_evidence`; absence of a finding is `not_detected`, never rejected.
- Run-level technical invalidity retains artifacts but returns no security metrics.
- Every zero denominator is JSON `null`.
- Severity and Context Priority use only independent expected labels and report
  the reviewed and assessed sample sizes.

The pipeline stores a redacted trace for every executed finding under `traces/`.
It includes plans, complete proposals, Validator decisions, Executor results,
Evidence, agent decisions and stop state. Existing reports, execution evidence,
audit logs, stage errors and LLM attempt records remain canonical artifacts.

## Offline rescoring

With an A04 dataset:

```bash
python3 -m evaluation.offline_rescore \
  --dataset path/to/ground-truth-v2.yaml \
  --artifacts path/to/saved/pipeline \
  --output path/to/rescore
```

Using the provisional A02/A03 adapter:

```bash
python3 -m evaluation.offline_rescore \
  --positive-catalog benchmarks/juice-shop-v20.2.0-v2/catalog/positives.reviewed.yaml \
  --control-catalog benchmarks/juice-shop-v20.2.0-v2/controls/controls.reviewed.yaml \
  --expanded-control-catalog benchmarks/juice-shop-v20.2.0-v2/controls/expansion/controls.reviewed.yaml \
  --artifacts path/to/saved/pipeline \
  --output path/to/rescore
```

The output contains stable `scorecard-v2.json`, `scorecard-v2.md`,
`observations-v2.json` and `history-v2.json`. It must be outside the immutable
input directory so rescoring cannot alter or invalidate saved run artifacts.

## A04 boundary

The current A02/A03 catalogs are explicitly provisional. A04 must independently
review and freeze corpus membership, anchors, split and rubric labels. Until then,
the adapter is valid for synthetic integration tests, but not for final benchmark
claims. It does not infer severity or Context Priority from CWE, scanner severity
or challenge difficulty.
