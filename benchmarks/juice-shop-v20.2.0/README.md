# Juice Shop v20.2.0 benchmark v1

Frozen before any full scored run. Target commit:
`5658473cf8814459bf89000ce373b20ed0b4eb37`.

This is a **non-exhaustive real-world subset**, with ten vulnerable conditions
and two SQL-injection-safe statements across six categories. Recall is relative
to benchmark-v1 scope, never the entire Juice Shop. A safe SQL statement does
not imply a safe handler: `routes/basket.ts:19` is SQL-safe but lacks ownership
enforcement, which is labeled separately.

Ground truth is authored from pinned source and upstream challenge metadata,
not Pentester results. Each case explains the source condition and lists its
provenance. The source is available under the pinned commit at
[Juice Shop](https://github.com/juice-shop/juice-shop/tree/5658473cf8814459bf89000ce373b20ed0b4eb37).
Directory labels mean enumeration of sensitive names, not proof of downloading
their contents. Code injection is conditional on the default enabled challenge
configuration. Two existing demo SAST rules and the existing production profile
are retained; the corpus deliberately includes cases beyond those rules and
beyond the current runtime verification capabilities.

`dataset.lock.json` pins raw ground truth/configuration and labeled source-file
digests. Changing cases, ranges, aliases, budgets or matching assumptions requires
a new dataset version and reviewed lock, never a post-score adjustment.

## Preparation

Use Python with the project's ordinary dependencies, with the existing Semgrep
CLI available in PATH. Keep scanner installation isolated if its dependencies
conflict with the API's Starlette constraint. Do not run the API using the scanner
environment. Benchmark does not install new scanners or security capabilities.

```bash
git -c core.autocrlf=false clone --branch v20.2.0 --depth 1 https://github.com/juice-shop/juice-shop.git artifacts/benchmark-target/juice-shop
git -C artifacts/benchmark-target/juice-shop rev-parse HEAD
cp docs/demo/compose.yaml artifacts/benchmark-target/juice-shop/docker-compose.presentation.yml
printf '\n/docker-compose.presentation.yml\n' >> artifacts/benchmark-target/juice-shop/.git/info/exclude
docker pull bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b
docker pull python:3.12-alpine
```

Use `Copy-Item` and `Add-Content` for the last two file operations in PowerShell.
Compose is an operator input outside the tracked source corpus. The runner checks
it against the exact demo file, hashes it, and accepts no unreviewed replacement.
All tracked bytes are hashed. LF blobs must stay LF; one upstream file natively
has CRLF and is retained verbatim rather than rewritten. Git status must be clean.
No modification of the existing Stage 1 target is required.

Configure the existing provider adapter through the local `.env` or environment.
Never place credentials in benchmark YAML. The selected route is NSU/Qwen3.8-27B,
matching the demonstration, with low reasoning, 8192 output-token limit, 55-second
request timeout, two Scout turns, four candidates and two workflow iterations.
Preflight's neutral connectivity probe contains no source or truth.

```bash
python -m app.stage2_benchmark --preflight-only --dataset juice-shop-v20.2.0-v1 --target artifacts/benchmark-target/juice-shop
python -m app.stage2_benchmark --dataset juice-shop-v20.2.0-v1 --runs 3 --target artifacts/benchmark-target/juice-shop --output artifacts/benchmarks/juice-shop-v20.2.0-v1
```

Full runs send ordinary production source/context to the configured provider.
An infrastructure or approval blocker must be resolved before those runs begin.
Preflight failure returns technical failure and creates no scored run. Provider
probe results are not benchmark performance metrics.

## Matching and metrics

Each producer observation requires an equal normalized relative file, inclusive
range intersection, equal family, and equal service when declared by the case.
Backslashes become forward slashes; repeated separators and `./` collapse;
case is preserved for the Linux target; absolute/traversal paths are rejected.
No fuzzy title judge or LLM judge is used. Family aliases live in ground truth.
Multiple compatible aliases do not establish a match. Line tolerance is zero.

Sorted observations/case IDs drive deterministic maximum-cardinality bipartite
matching. A primary finding and case each receive at most one assignment.
Additional compatible findings are duplicates, not more TP. Verification outcome
and expected label do not influence primary assignment. Evidence from a duplicate
may confirm its assigned case once; the case records all matched finding IDs.

The two explicit negative SQL statements define the negative universe **only for
those statements**. A match to a safe case is FP; an unmatched safe case is TN.
For this non-exhaustive corpus, other findings are unreviewed/outside_ground_truth
and excluded from adjudicated precision, while retained in raw and case reports.
No project-wide specificity or precision is claimed.

* Precision = TP / (TP + FP), over adjudicated cases only.
* Recall = TP / (TP + FN), relative to the ten selected positives.
* F1 = 2PR / (P + R); zero when P and R are defined and both zero.
* Specificity = TN / number of defined negative controls.
* Duplicate rate = duplicate findings / raw observations.
* Confirmation rate = distinct evidence-confirmed positives / detected positives.
* Verified recall = distinct evidence-confirmed positives / all selected positives.
* False confirmation rate = confirmed negative controls / all negative controls.

Undefined denominators yield JSON `null` (N/A), never NaN. Verification metrics
are N/A for SAST-only observations. Reported verdict is preserved separately from
measurement status. Confirmation requires structured high/medium-reliability
Evidence, this run's successful persisted execution, matching action/run/tool/
target/session, and matching Executor audit/proposal/evidence digests. Static and
runtime confirmations have separate counters; neither overclaims the other's scope.
No CVSS or Context Priority value participates in matching or truth.

## Artifacts, timing and resume

Each run saves `manifest.json`, `raw-findings.json`, `matches.json`, `metrics.json`,
`report.md`, and untouched canonical artifacts under `pipeline/`. The root retains
the frozen configuration and truth copies and an aggregate JSON/Markdown report.
Manifest records target/source/config/profile/rules/policy/architecture digests,
Pentester commit and dirty-source digest, Docker image IDs/repository digests,
scanner version, model settings, budgets, platform and timestamps. It contains no
credential values. Actual model routes/attempts remain in ordinary LLM diagnostics.

External timers wrap real Discovery/SAST/Scout calls, preserving their inputs,
return values and exceptions. Agent/verification time includes per-finding context
and report orchestration. Tool actions and LLM attempts are counted from canonical
artifacts. Docker actions count Executor audit records with Docker backend;
unavailable lifecycle counts, token usage and monetary costs are not invented.

Run directories are never overwritten. Completed runs have file-hash seals.
`--resume` checks the full configuration digest and seals before reuse. It never
silently mixes versions or retries an incomplete directory; choose a new output
directory for interrupted work. Resume is at run boundaries, not within expensive
verification stages. The runner is intentionally sequential.

Startup/detection/model failures are technical failures, not all-FN samples.
Degraded runs with unavailable Scout or no successful LLM response are excluded
from primary aggregate statistics. They remain visible with diagnostics and the
technical failure rate. Per-finding unsupported/inconclusive/timeout/policy-blocked
states remain separate. Completed runs report mean/min/max/stddev and per-case
detected/confirmed frequencies and verdict instability; failed runs are excluded
from the stability denominator.

The A/B/C views come from one canonical run: original SAST findings; Scout-merged
detection; that same queue's FinalReports/Evidence. No separate production pipeline
or tuning for better score was added. Only producer `pentester` is currently run.

After runs complete, regenerate the final case-level Evidence joins and exact
provider request counts without contacting a model or rewriting sealed runs:

```bash
python benchmarks/juice-shop-v20.2.0/scorecard.py --output artifacts/benchmarks/juice-shop-v20.2.0-v1
```

`scorecard.json/.md` distinguishes actual provider request attempts from other
diagnostic events, includes confirmation from duplicates, and reports pairwise
exact-anchor set stability. The original `performance.llm_calls` field counts
diagnostic events, so use the scorecard's `llm_requests` for actual API attempts.

## References and reuse

[OWASP Benchmark](https://owasp.org/projects/benchmark) supplies the methodological
pattern of labeled cases and normalized scanner outputs. Its utility implementation
[BenchmarkUtils](https://github.com/OWASP-Benchmark/BenchmarkUtils) is GPL-3.0.
[VulnHunter's harness](https://github.com/capitalone/VulnHunter/tree/main/harness/local_harness/benchmark)
is Apache-2.0. Its pinned commits, checkpointed artifacts and tally/history patterns
informed this harness. Its example NodeGoat/Juice Shop/WebGoat corpus explicitly uses
synthetic placeholders, so no labels or commits were imported. Its LLM judging was
not adopted. No third-party code was copied; this implementation is original.
