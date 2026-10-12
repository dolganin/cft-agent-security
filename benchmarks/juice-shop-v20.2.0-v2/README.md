# Benchmark v2 — A04 frozen corpus

A04 review/freeze is documented in `../../docs/a04-benchmark-freeze.md`.
`ground_truth.yaml` is the A05-compatible projection, `scope.yaml` records the
mandatory independent reporting slices, `rubric.yaml` records labels and N/A,
and `dataset.lock.json` binds exact input bytes. Use
`python -m evaluation.benchmark_freeze validate` before consuming this corpus.
Optional `--target <pinned-checkout>` additionally validates source and recorded
control Evidence without executing the target. A05/A06/A07 remain separate gates.

The following A01 description is historical protocol context; statements saying
that A02/A03/A04 are pending refer to its original publication, not current status.

## Historical measurement protocol v2 — A01

The authoritative rules are in `protocol.yaml`, validated by
`schemas.benchmark.BenchmarkProtocolV2`. `protocol.lock.json` binds its exact
bytes with SHA-256. This directory contains a protocol, **not a measured dataset**:
A02/A03 labels and the A04 dataset lock are pending. Historical
`../juice-shop-v20.2.0/` and sealed Stage 2 results remain unchanged development/
regression evidence. Their detection precision is never renamed to v2 precision.

Validate A01 without Docker, provider calls, target execution or scoring:

```bash
python -m evaluation.benchmark_protocol
python -m pytest tests/test_a01_measurement_protocol.py tests/test_stage2_benchmark.py -q
```

Future v2 preflight must call `load_protocol()` before infrastructure/producer
calls, and separately check A04 dataset and A06 scanner locks. The current Stage 2
runner remains v1-only. A01 does not enable scored v2 runs.

## Case, scope and matching

One case represents one independent security root cause. A reviewed
`independence_group` identifies that cause and its related controls. Two scanners,
SAST/Scout observations, caller/helper observations, alternate anchors or multiple
challenges for that cause do not create more positives. At most one positive per
group/sample slice is allowed. A negative control must have its own independent
reviewed safe condition; scanner silence is insufficient. Patched and synthetic
twins carry the original group. Report `original`, `patched`, `synthetic` and
development/holdout separately. Never pool twins as independent root causes.

A case may declare multiple reviewed source/HTTP/caller-helper anchors. A02/A04
must record admissible anchors before measurement; A01 implements no HTTP matcher,
caller/helper resolver or new source matcher. Source diagnostics reuse v1's exact
normalized relative file, intersecting inclusive line range (tolerance 0), frozen
family compatibility and service when declared. Ambiguous family aliases do not
establish a match. Stable maximum-cardinality bipartite matching uses sorted
observations/case IDs and never ranks expected labels or verification outcomes.
One finding has at most one primary case; one positive case has at most one TP.
Extra compatible findings are duplicates. Their matching Evidence may decide a
case once. Conflicting evidence-backed binary verdicts yield abstention, preserving
all Evidence; there is no best-result selection.

Scope is non-exhaustive and restricted to reviewed labeled cases at the pinned
target. Unknown findings remain `outside_ground_truth` or `unreviewed`, retained
with counts and artifacts; they are neither FP nor TP/TN/FN and never enter primary
precision. Newly reviewed discoveries can enter only a later dataset version.

## Metrics

All counts are distinct labeled cases in the evaluated split/sample slice, except
explicit raw duplicate/unknown diagnostics. JSON `null` means N/A.

| Metric | Numerator | Denominator |
|---|---|---|
| confirmed_precision | Correct evidence-backed CONFIRMED positives | All evidence-backed CONFIRMED labeled cases |
| supported_verified_recall | Correct evidence-backed CONFIRMED positives | All labeled positives in evaluated scope |
| false_confirmation_rate | Evidence-backed CONFIRMED negatives | All labeled negative controls |
| answered_accuracy | Correct CONFIRMED positives + correct REJECTED negatives | All valid evidence-backed CONFIRMED/REJECTED cases |
| decision_coverage | Valid evidence-backed CONFIRMED/REJECTED cases | All labeled cases |
| abstention_rate | Cases without a valid binary decision | All labeled cases |
| technical_failure_rate | TECHNICALLY_INVALID attempts | All attempts, including retries |

Zero denominators yield N/A, including no confirmations, no controls or no
answered cases. `supported` describes the evidence-backed numerator: unsupported,
undetected and abstained positives remain in verified recall's denominator. A
REJECTED positive is an incorrect answered case. An undetected negative may be a
detection TN, but is not a correct security rejection.

Detection remains diagnostic: TP/FP/FN/TN, precision=TP/(TP+FP), recall=TP/(TP+FN),
F1=2PR/(P+R). TN is available only for explicit labeled negative controls. F1 is
N/A when P or R is undefined, 0 when both are defined and zero. Runtime failures
cannot change detection FN. Duplicates never add TP.

Both binary decisions require Evidence with the matching verdict, high/medium
reliability and the existing successful persisted execution/audit binding
(action/run/tool/target/session and proposal/evidence digests). Static/runtime
scope must be preserved. A model conclusion or absent confirmation is insufficient.
`verification_metrics_v2()` extends the existing scorer by reducing its matches;
it trusts normalized `evidence_backed` observations supplied by the evaluator.
The v1 adapter certifies only confirmations. A05 must bind rejections too before
using this reducer on real v2 artifacts; production contracts are unchanged.

Keep case abstention reasons separate: `inconclusive`, `unsupported`, `timeout`,
`policy_blocked`, `technical_error`, `not_detected`, `not_run`, `invalid_evidence`,
`conflicting_evidence`. Without a valid duplicate decision, use the primary
observation's reason. Preserve every raw observation's reason as well. The five
required operational reason counts are always present, even when zero.

Run-level Docker/target startup/required-provider/artifact/configuration failures
are `TECHNICALLY_INVALID` and have no primary security metrics. Retain them in
artifacts, logs, aggregate reports and technical failure rate. A capability error,
lost session or verification timeout affecting only one case is case abstention,
never an implicit REJECTED or runtime-generated detection FN. V1's conservative
Gate-based whole-run invalidity is historical and is not retrospectively changed.

Severity/Context Priority remain independent evaluations: correct assessed labels /
assessed cases with reviewed independent labels, plus assessed / reviewed-label
coverage and reviewed-label / all-case coverage. Missing labels/assessments mean
N/A. Difficulty, scanner severity, challenge presence and LLM confidence are not
CVSS proxies. A01 adds no rubric labels or CVSS engine.

## DEV/HOLDOUT and truth isolation

For exact UTF-8 group identifier `g`, compute SHA-256 of `seed + NUL + g`, interpret
the digest as an unsigned big-endian 256-bit integer `h`. Assign development when
`h * 100 < 70 * 2**256`, otherwise holdout. Seed is
`cft-juice-shop-v2-a01-2026-10-11`. No normalization, random state, input order or
expected label affects assignment. Related vulnerable/negative/synthetic/caller/
helper variants share a group. Adding another group cannot move existing groups.

The ratio is approximately 70/30, not a quota. Small-family imbalance must be
reported; do not change seed or reassign cases after tuning or scores. A02/A03
must review cause grouping and family coverage; A04 locks membership before
tuning. Public Juice Shop and historical v1 exposure limit holdout generalization;
holdout means withheld project benchmark labels, not necessarily unseen model code.

Evaluator truth, expected/split labels, safe/vulnerable status, non-production
expected anchors and protocol metadata never enter Scout/Agent prompts,
ActionProposal or production TargetProfile. Existing explicit production argument
and reasoning-context allowlists are reused and tested with sentinel metadata.
Evaluator artifacts stay outside target discovery. No production behavior changed.

## Baseline, repeats and freeze

Target is OWASP Juice Shop v20.2.0 at
`5658473cf8814459bf89000ce373b20ed0b4eb37`. Baseline settings come from the real
benchmark config, sealed Stage 2 manifest, current config defaults and adapter:
NSU/Qwen3.8-27B, low reasoning, temperature 0.1, JSON object, stream=false,
8192 output tokens, 55 s LLM timeout; no request seed. Scout: 2 turns, 4 candidates,
160000 source characters, 60 s. Agent: 120 s and 2 iterations. Existing deterministic
fallback is logged and never presented as a successful model response; fully
unavailable required provider makes the run invalid.

Executor limits: 5 s wall time, 2 s CPU, 256 MB RAM, 1048576 file bytes, 8 processes,
16384 output bytes, 1 run/action and 1 concurrent run. The actual immutable worker
digest, target image, current policy/profile/code input digests and hardcoded
read/search/index/probe limits are in YAML. Credentials and environment secret
values are absent. Historical v1 input hashes use raw bytes; other text input
hashes normalize CRLF to LF for portable checkouts. Protocol hashes always use raw
bytes; `.gitattributes` preserves LF. Scanner final versions/configuration and
DAST availability are explicitly deferred to A06; this does not enable DAST.

Each final compared configuration requires three independent real runs with fresh
directories and target state reset. Keep target, truth, matching, split, model,
budgets, policies, scanner and producer configuration identical within a series.
Store every attempt's ID, reason, error and `retry_of` relationship. Never replace
an invalid attempt silently. Aggregate valid runs only, with failure rate and the
number of defined/N/A observations for each statistic; fewer than three valid
runs is an incomplete series, even if three attempts were made.

A01 freezes protocol semantics/baseline and the protocol lock. A04 freezes actual
truth/anchors/split membership with a new dataset lock; A06 freezes scanners.
After freeze, changes require a separate v2.1/v2.2/v3 artifact with changelog,
reason and new digest. Never overwrite prior locks or published results. Improved
configurations may be compared under the same metric protocol with separately
frozen manifests; `check_baseline=False` skips only the baseline-producer byte check,
never protocol validation/lock checking. Their intentional producer changes must
be recorded; they are not the frozen baseline series.

No A02/A03 cases, controls, DAST, new SAST rules, Scout enhancements, security/fix
capabilities or scored v2 results exist in this artifact. The next work is parallel
A02/A03; the measurement integration belongs to A05 after these fixed rules.
