# C03 — Independent Patch Verification

Date: 15 October 2026. Independent verifier with the explicitly authorized protected redirect
security-test contract described below. Reference patches
are operator engineering inputs, not LLM-generated patches. C02, C04 and C05 are
not implemented by this change.

## Pipeline and reused components

`IndependentPatchVerificationService` specializes `FixVerificationService`.
The existing service still owns proposal freezing, disposable source snapshots,
BEFORE gating, patch application, exact changed-file checking and original
integrity. Stage 1's public interface and artifact version remain unchanged.
C03 uses a separate `cft.c03.v1` envelope around that artifact.

```text
reviewed proposal + C01 family + archived confirmed finding
→ C01 lock/eligibility + source/proposal/scope/preflight
→ disposable source snapshot
→ approved fixed prepare/build/native-tests/start/smoke stages
→ fresh canonical BEFORE (SQL or B06 redirect)
→ original proposal/digest recheck → one-file data-only apply
→ new isolated generation(s): build/native-tests/start/smoke
→ protected C01 source evaluator + independent HTTP observer
→ same canonical capability, hypothesis and B01 route, over patched source
→ independent deterministic verdict → original/cleanup proofs → sealed artifact
```

All active stages use existing `PolicyValidator`, `SafeExecutor`, approval digest,
execution store and audit. The separate `policies/c03.yaml` grants only the three
required registered tools. Default and historical B06 policies are unchanged.
C03 adds fixed stage identifiers to `fix_target_stage`; callers still cannot
provide argv, URLs, image selections, shell commands or credentials in a patch.

`C03FixRuntime` extends `DockerFixRuntime`; `C03RedirectRuntime` extends
`B06Runtime`. Redirect retains B06's two pre-bound generations, registered
`verify_redirect_destination`, controls, header-only probe, sink, interpretation
and action/fixture/audit checks. It runs the built snapshot, without substituting
precompiled safe-control image overlays. SQL uses `verify_sql_injection`, search
mode only. B01 resolves actual registration and handler ASTs again in each phase;
AFTER changes the authorized source digest, not the route or hypothesis.

## Trust boundaries and patch scope

The proposal is untrusted. C01, the B09 archive, tests, evaluator, policies and
runtime adapters are operator-owned. `load_scope` and `assess_scope` check the
unchanged C01 lock and archived execution/audit-backed selection. Supplied
reports must match an eligible archived report. No archived `confirmed` value
substitutes for fresh runtime BEFORE.

Pinned target: `5658473cf8814459bf89000ce373b20ed0b4eb37`.
Original target must have no tracked/untracked changes. Docker must be Linux;
all required immutable images must already exist. Verification never pulls or
builds an image and never executes target code on the Windows host.

`validate_candidate`, the existing review parser and `git apply --check` enforce
one existing allowlisted file, exact context, bounded diff, path containment,
no links/reparse escapes, additions, mode changes or changes to tests/config.
Application is data transformation only, inside the disposable snapshot.
The original is mounted neither writable nor as a target execution directory.

An additional conservative defensive grammar accepts a single SQL query rewrite
using Sequelize `replacements` or `bind` with the unchanged query/filter/order,
or a minimal exact redirect comparison/route allowlist guard. Larger safe rewrites
may be rejected as unsupported. This deliberately prevents arbitrary added JS,
process exit, imports or VM escapes from forging the native runner/evaluator's
stdout. It is not a general JavaScript sandbox or a claim to support arbitrary
patch forms. C01's frozen evaluator is unchanged.

The helper defensive grammar is shared with C02: either operand order of strict
equality, whitespace and an optional semicolon are accepted consistently. Loose
equality, unconditional approval and appended statements remain rejected.

Redirect scope permits the caller or helper file. The C01 source oracle evaluates
the helper, so a route-only fix preserving a vulnerable helper is conservatively
unqualified by that oracle. No FIXED claim is made for that alternative shape.

## Runtime and independent checks

Each phase creates fresh non-root containers with read-only roots and source
mounts, a writable application copy in bounded tmpfs, no capabilities, no-new-
privileges, CPU/memory/PID/output/deadline limits. Build/native tests are
networkless. HTTP startup/verification uses only a unique internal Docker
network. Redirect destinations are inspected without following or resolving them.

SQL adds five fixed products, including deleted/apostrophe/200-character cases,
and an evaluator-only sentinel table in the disposable database. It preserves
the original products: deleting them races Juice Shop background model reloads.
The full public product fixture digest and ordered active IDs must match between
BEFORE/AFTER. Startup timestamps are excluded from the fixture digest; names,
descriptions, IDs and deletion state remain bound.

The HTTP oracle runs in a **separate read-only Python container**, without target
source imports. It checks name/description search, order, active/deleted records,
empty/no-match, literal apostrophe, 200/201-character behavior, JSON contract,
original/independent boolean and UNION variants and sentinel absence. Redirect
checks all eight exact original Location values and query/fragment/userinfo/
hostile-suffix/protocol-relative/malformed/unapproved destinations.

The protected source oracle runs in a separate networkless container with C01's
read-only evaluator. The selected family's entire case set must pass. This is
supplementary to HTTP; helper success alone cannot prove the route is fixed.

The native test command remains the existing fixed Node runner. C03's read-only
reporter records success/failure/skip totals, observed test files and an event
digest. Every source-inventory `test/server/**/*.unit.test.ts` must be observed;
failure/cancellation is forbidden except for the two exact obsolete security
assertions authorized below. Their raw failure and exit status remain recorded. The two existing Docker-disabled RCE skips
remain visible. The number of dynamically reported cases is recorded, not
assumed to be the historically observed 415. A plain `success` stdout is invalid.

## Verdict and replay

FIXED requires fresh canonical BEFORE confirmed, reviewed patch applied, all
required stages, independent source/HTTP cases, canonical AFTER explicitly
rejected, matching Validator/Executor/audit/bindings, original integrity and
verified container/network/observer/workspace cleanup. Inconclusive observations,
HTTP 500/404, timeout or a disappearing endpoint cannot become a rejection.

NOT_FIXED requires a conclusive canonical AFTER confirmation. Native functional
test failures are REGRESSION. Invalid preflight proposals are REJECTED. Missing,
contradictory or technically incomplete evidence is INCONCLUSIVE. Reason codes
are separate from display explanations. Rejected untrusted patch text is not
retained as a potential secret archive; its original digest is retained.

Each fresh output directory contains a versioned manifest, reviewed proposal,
source manifests and raw B01 source snapshots, individual persisted executions,
Validator decisions, audit, interpreted Evidence, fixture observations, native
test report, HTTP ledger, cleanup proofs and SHA-256 file seal. No .env, session
tokens or credentials are provisioned or stored by these two C03 protocols.
Cleanup uses only owned names; no global Docker prune occurs.

```powershell
artifacts/benchmark-tools/venv/Scripts/python.exe -m app.independent_fix `
  --family sql-search --target artifacts/benchmark-target/juice-shop `
  --output artifacts/c03-sql-search-<fresh-id>

# Same entry point for redirect-allowlist. Run acceptances sequentially.
# Add --report report.json --review review.json for a prepared reviewed proposal.

artifacts/benchmark-tools/venv/Scripts/python.exe -m app.independent_fix `
  --replay artifacts/c03-sql-search-<fresh-id>
```

Replay does not execute a model, Docker, target code or patch. It validates schema,
safe membership/seal, duplicate executions, proposal/application/source bindings,
persisted record copies, deterministic Validator decisions, action/execution/
audit digests, canonical protocol facts, native/source test evidence, independently
recomputed HTTP expectations and cleanup/integrity. It compares the recalculated
status with the saved status. Resealing contradictory documents does not make them
valid. Seals are consistency/integrity, not signatures or independent binary/source
attestation. Trusted operator observations remain the source of provenance.

## Historical acceptance and superseded blocker

SQL and redirect execution results and checks are recorded in
`docs/evidence/c03/results.json` (populated after the final checks).

The first redirect reference acceptance reproduced BEFORE in both fresh Docker
generations, applied the reference patch, built it and ran the real native suite.
It failed two pre-existing tests:

* `test/server/insecurity.unit.test.ts:259`: “returns true for URLs containing
  allowed URLs” expects the old substring behavior, including `/issues`.
* `test/server/redirect.unit.test.ts:84`: “tricking the allowlist should solve
  redirectChallenge” expects the vulnerable route to accept the attack.

The exact comparison reference intentionally removes this behavior. The required
native suite therefore fails (411 passed, 2 failed, 2 skipped in that run).
No test, allowlist, lock, evaluator, reference patch or target original is changed
to obtain green output. AFTER is not attempted after the required test failure.
This is a genuine acceptance blocker under the requested all-native-tests-pass
rule, not evidence that the original redirect vulnerability is fixed.

Roman explicitly retained all upstream tests as mandatory on 15 October 2026.
That initial contract enabled no exclusions or accepted assertion failures. Its
redirect result remains REGRESSION in the preserved historical evidence. The
subsequent explicit authorization below supersedes that contract for new runs.

The continuation also checks the raw original source against the frozen B09
snapshot, receipt/session/artifact provenance and the exact stage inventory.
Offline replay cannot upgrade an inconclusive verifier result to FIXED. Cleanup
accounts for resources actually created even when a mandatory stage stops a
generation early; completing both required redirect generations remains a
separate condition for FIXED. Canonical redirect worker absence is recorded.

## Definition of Done and limits

C03 COMPLETE requires both reference acceptances FIXED under the versioned native
contract, successful independent
replay, all required negative/provenance/lifecycle tests and no material regression.
The earlier mandatory-all-assertions contract remains preserved in historical
REGRESSION artifacts. Current acceptance uses only the explicit two-assertion
replacement below; there is no C02/C04 completion or model patch-quality claim. Runtime observations establish only the
registered hypotheses and tested controls; they do not prove general vulnerability
absence, production suitability, or arbitrary patch correctness.


## Authorized protected security-test contract (continuation)

Roman explicitly authorized a separate protected contract for the two tests
requiring the vulnerability. The upstream files are never edited or skipped;
every native test still executes. Historical REGRESSION results remain unchanged.
`contracts/c03/native-security-contract.json` binds the original commit, exact
file SHA-256, test names and assertion stack lines (259 and 84), ERR_ASSERTION,
and actual=false/expected=true. Source locations come from assertion stack traces;
Node/tsx event registration lines refer to transpiled code and are unsuitable.

Only redirect AFTER can accept exactly these two known assertion failures, with
zero other failures, cancellations or new skips and complete native file inventory.
Changed test hashes, names, assertion types, locations, results, missing markers,
changed contract version, SQL and BEFORE exceptions all fail closed. Read-only
reporter output retains summary.success=false, both assertion facts and raw exit 1.
A separate persisted `C03 NATIVE CONTRACT` receipt states operator-stage acceptance;
its exit 0 never relabels the native suite green. Replay recomputes this receipt.

All source/HTTP checks and the canonical independent protocol still must succeed.
FIXED additionally requires fresh BEFORE confirmed and explicit AFTER rejected,
original integrity, complete two-generation lifecycle and cleanup. The replaced
assertions themselves cannot establish remediation or upgrade an incomplete run.
This contract is outside the patch allowlist and its SHA-256 is checked in code.
The first development attempt is retained under artifacts/c03-redirect-protected-contract-01;
it is not counted as completed acceptance.


## Completed acceptance under the authorized contract

Both fresh reference acceptances are FIXED and independently replay to
complete_independent_chain. SQL has BEFORE confirmed, AFTER rejected, native
413 passed/2 original RCE skips in both phases and no accepted assertions.
Redirect has two generations per phase: BEFORE 413 passed/2 skips, AFTER
411 passed/2 obsolete security assertion failures/2 original skips in each.
Those failures and raw exit 1 remain visible alongside the separately accepted
operator contract. Independent HTTP/source tests and canonical AFTER reject
both attacks. Original source and tests are unchanged; owned resources and
workspaces are verified removed.

Current results: [protected-contract-results.json](evidence/c03/protected-contract-results.json).
Portable SQL evidence: [sql-protected-contract-runtime.zip](evidence/c03/sql-protected-contract-runtime.zip).
Delivery integrity: [protected-contract-seal.json](evidence/c03/protected-contract-seal.json).
The complete redirect bundle stays local at artifacts/c03-redirect-protected-contract-02
because its bound original helper includes Juice Shop's seeded private-key fixture.
No reference run is described as an LLM-generated patch or general vulnerability proof.

Full checks: 1483 passed, 29 platform/opt-in skips, zero failures; Ruff and
app.main passed. The new 22 native-contract tests reject additional failures,
changed source/test locations/assertion kinds, duplicate errors, new skips,
BEFORE/SQL exceptions, invalid exit codes, modified contracts and flattened
stdout ambiguity. Replay tests also reject missing/version-changed contract receipts.
