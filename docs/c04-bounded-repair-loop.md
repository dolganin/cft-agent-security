# C04 — bounded generation, independent verification and retries

Implemented on main base `b8197c3`. Acceptance: 16 October 2026, Asia/Novosibirsk.
This composes C02 and C03 for C01's existing SQL-search and redirect-allowlist
families. The original target, frozen baseline, evaluator, native security
contract and execution policies are unchanged. No automatic merge is provided.

## Run

Provide an ignored local `.env` with a valid `NSU_OPENWEBUI_KEY`, a clean pinned
Juice Shop checkout and the already provisioned C03 images. Provisioning remains
separate: `docs/demo/fix-verification.Dockerfile` produces the operator fix image;
verification never pulls/builds images. The accepted ARM64 fix image is recorded
by its actual immutable ID in `docs/evidence/c04/results.json`. Its npm installation
is not a claim that rebuilding an unlocked dependency tree produces identical bytes.

```bash
python3 -m app.repair \
  --target artifacts/benchmark-target/juice-shop \
  --family sql-search \
  --output artifacts/c04-new-sql \
  --max-attempts 3 --wall-clock-seconds 3600 \
  --bundle artifacts/c04-new-sql.zip

python3 -m app.repair --replay artifacts/c04-new-sql
```

Only one operator-selected provider route is allowed; default
`nsu:qwen3.8-flash-next`. Limits are finite: 1–5 proposals, 1–14400 seconds;
defaults are 3 and 3600. The provider's existing 60-second deadline can only be
shortened. C03 stages, provisioning and execution share the remaining work
deadline. Cleanup continues after work expires, using existing bounded cleanup
transports. This is not a hard kill of the Python runner at an exact second;
final duration includes cleanup. A missed deadline cannot be promoted to FIXED.

Run exit codes: 0 FIXED; 1 finished unsuccessful; 2 technical failure. Replay exit
0 means the saved bundle was validated, independently of whether its repair
succeeded. Both run directory and ZIP must be new and outside the original
target. ZIP export cannot write into either the original or sealed run.

## Per-attempt behavior

1. Verify the whole original Git snapshot and C01 lock. Create a new clone without
   checkout filters/hooks; populate exact source bytes as data and check its hash.
2. Call C02's real provider adapter with the original bounded source/Evidence and,
   when appropriate, the previous typed feedback. Source is never executed on host.
3. Check raw response diff, canonical diff and resulting-file fingerprints. Any
   previously seen patch stops the campaign before another verifier execution.
   Proposal UUIDs and rationale cannot evade deduplication.
4. Pass the exact ready C02 review and archived report to a new C03 verifier.
   C03's engineering reference-patch default is never invoked by C04.
5. Independently replay C03's persisted execution/audit/Evidence. Confirm proposal,
   source, applied-patch and result digests agree, then decide whether to finish
   or generate another proposal from another clean original copy.
6. Remove attempt copies and verify the unchanged original before sealing results.

C04 retries bounded diff/structured-response errors, conclusive C03 NOT_FIXED,
and required AFTER build/native-test failures with a confirmed BEFORE and verified
cleanup. Auth/payment/rate-limit/model-network failures, lost scope/integrity,
incomplete runtime proof and failed cleanup terminate without a fix claim.
The campaign's `NOT_FIXED` means no independently verified patch was delivered;
it does not itself prove that the vulnerability remained exploitable.

Feedback is fixed operator-authored text selected by code. Raw native stdout,
private test cases, secrets, reference patches and arbitrary verifier prose never
enter the next model request. Request size remains within C02's original budget.
Malformed/secret responses retain safe provenance but are not published as raw patches.

## Persistence and replay

The directory records configuration, source snapshot, original report, immutable
runtime identities, append-only events, per-attempt generation/request/model
response/review, candidate fingerprints, C03 bundles, feedback, durations and a
final result/report/seal. Interruptions preserve partial records; no interrupted
chain becomes FIXED. Docker control processes have separate POSIX sessions so
cancellation cannot kill the caller's process group.

Offline replay requires the repository's protected C01/C03 evaluator assets and
baseline archive, but not the target checkout, Docker, subprocess execution or
LLM access. It validates file membership/hashes, archived-original provenance,
operator configuration, model edits versus canonical edits, C03 receipts, attempt
order, timing/events, feedback and stop decisions. Plain seals establish saved
bytes, not cryptographic provider identity; replay also checks semantic bindings.

## Actual acceptance

| Case | Fresh LLM proposals | Independent outcome | C04 terminal result | Duration |
|---|---:|---|---|---:|
| SQL search | 1 | BEFORE confirmed, AFTER rejected; all required stages passed | FIXED | 92.287 s |
| SQL search, final transport-hardened code `04cdd5d` | 1 | BEFORE confirmed, AFTER rejected; all required stages passed | FIXED | 70.351 s |
| Redirect allowlist | 2 | First C03 REGRESSION; feedback; same patch returned | NOT_FIXED / duplicate_patch | 191.303 s |

Both cases used real `nsu/qwen3.8-flash-next`, unmodified model-generated changes
and fresh copies. Neither original changed; owned runtime and workspace cleanup
was verified. All three bundles replayed twice identically. Initial SQL's native phases each
reported 413 passed, 2 original RCE skips, 0 failures.

Redirect AFTER native tests returned exit 1 with a file-level failure plus one
assertion failure; the protected contract did not permit it. Canonical security
AFTER was not reached. The underlying test-process failure is not attributed to
the patch, and the run is not described as a demonstrated security non-fix.
C04 passed only the safe REGRESSION category, obtained the repeated patch and
stopped before a second C03 run. Full observations and varying native counts are
preserved in the local bundle; no protected test exception was added.

An earlier C04 call stopped on invalid credentials. It remains a sealed technical
failure, excluded from remediation acceptance. A separate C03 image smoke used
an archived C02 proposal; it is not counted as fresh C04 generation.

Final-code SQL acceptance is an additional fresh provider call, not a replay or
manually supplied patch. Full pytest on this code: 1587 passed, 24 skipped;
C04-only: 99 passed; real Docker boundary: 6 passed. Changed-file Ruff and the
stub graph smoke passed. Full Ruff reports 7 pre-existing issues in unchanged
files; this branch does not meet a repository-wide clean-lint merge gate yet.
See retained logs and `transport-timeout-observation.md` for the earlier failed
validation process and the narrowly scoped process-group correction.

Portable successful evidence: `docs/evidence/c04/sql-live.zip` and the final-code
`docs/evidence/c04/sql-live-final.zip`. Extract either ZIP into a new
directory and pass that directory to `--replay`. Redirect's complete bundle is
local at `artifacts/c04-redirect-live-2026-10-16-01.zip`: its two bound helper source
snapshots contain the upstream seeded private-key fixture. The published
`redirect-history/` is an explicitly partial diagnostic readout, not a replacement
for that complete replayable bundle. See `docs/evidence/c04/README.md`.

These are functional acceptances, not C05 fix-quality/MTTR measurements or proof
of general patch correctness. C04 provides no UI, PR platform or automatic merge.

## Follow-up validation — 16 October 2026

The earlier full-lint failure above is historical. Follow-up fixes remove unused
bindings, redundant returns, nested conditions and import-layout issues in C04,
plus legacy multiple statements and lambda assignments in test helpers. The
hash-frozen A04 scorecard stays byte-identical: its necessary standalone CLI
bootstrap receives a file-specific E402 exception, without suppressing other
lint rules or changing evaluator locks.

A new regression test extracts the final transport-hardened SQL acceptance and
replays it twice with process execution and model calls forbidden. Both successful
acceptance bundles are now covered by automated offline replay. Runtime repair
behavior, budgets, feedback, duplicate stopping and protected security checks are
unchanged; this follow-up does not manufacture a new live-provider measurement.

Current check logs and limitations are recorded separately under
`docs/evidence/c04-followup/`, preserving the original sealed C04 delivery.

## Completion review — 16 October 2026

Feedback v2 distinguishes failed AFTER build and native-test stages. It does not
attribute a test-process failure to the patch without evidence. The next request
also contains the prior validated diff, bound to its canonical SHA256, with the
same source-line redaction as C02. Rationale, evaluator annotations, private tests
and raw stdout/stderr are excluded. The existing 24 KB request limit still applies.
Replay verifies that projection against the actual previous attempt; v2 requires
it after a verified unsuccessful proposal. Legacy bundles remain replayable.

A live review found that fresh copies lost operator-local Git excludes and then
rejected the copied provisioning Compose file as untracked. Copies now preserve
bounded local exclude data, without inheriting hooks or Git configuration. The
regression test checks clean copies, independent files and unchanged originals.

The portable negative regression now runs real C02 generation/orchestration with
an explicitly synthetic network response containing an invalid diff. It retries,
detects the repeated diff, finishes NOT_FIXED, exports a complete ZIP and replays
the extracted bundle without subprocesses, Docker or model calls. This automated
failure path no longer depends on the unavailable historical private redirect
bundle. It is not represented as a fresh live-provider security non-fix.

The additional real redirect campaign used one fresh LLM proposal and completed
FIXED in 331.247 s: canonical BEFORE confirmed, AFTER rejected, independent gates
and the unchanged protected native-security contract passed. Original integrity
and cleanup passed. Its complete local bundle is
`artifacts/c04-review-negative-2026-10-16-02.zip` (the name describes the attempted
negative acceptance, not its actual successful outcome). The earlier run without
the exclude fix stopped technically before generation and is not counted as a
remediation acceptance. No manual replacement patch or new test exception was used.

Completion checks: 1586 passed, 32 platform/opt-in skips; full Ruff and the graph
smoke passed. Logs and the new live acceptance receipt are retained under
`docs/evidence/c04-completion/`. The portable negative regression passes without
the historical private bundle. These results assess the bounded C04 contract,
not universal repair quality or C05 MTTR.
