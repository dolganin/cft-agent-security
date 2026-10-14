# B05 — Evidence-based access-control verification

**Current status: B05 V3 DEV VERIFIED — CANONICAL APPROVAL PENDING.** One bounded v3 Docker acceptance completed with `CONFIRMED`, 12/12 exchanges, three reset-separated generations, verified cleanup/integrity, and successful sealed offline replay. This is a candidate DEV measurement; it does not approve canonical R01. Historical OWN-WRITE v2 remains `INCONCLUSIVE` and unchanged, while OWN-READ and OWNERSHIP-TRANSFER retain their separately confirmed results.

## 1. Scope and base

This implementation continues B05 on base commit `7b4f8572af99f0432c8afd1454232378e9a21d28`. The model still offers only `juice-basket-own-read-v1`; the operator registry also contains the denied legacy Address write and separately selected DEV candidates `juice-basket-own-write-v2`, `juice-basket-own-write-v3`, and `juice-address-ownership-transfer-v1`. v2 and v3 bind to the same single B01 source route because they exercise the same target handler; their check IDs and Evidence protocols stay separate. The pinned Juice Shop DEV checkout is commit `5658473cf8814459bf89000ce373b20ed0b4eb37`.

No HOLDOUT, ground-truth labels, A05 matcher, scanner baseline, A06/A07 artifacts, user `.env`, or target source files were read or changed for this implementation. The target checkout's source snapshot was verified before and after each disposable runtime.

## 2. Reused components and binding

B05 reuses B01 `VerificationBinding` / `resolve_binding` and the B04 `AccessFixtureLab`, worker, identity checks, ownership proof, opaque session storage, fresh Docker network, reset, cleanup and source-integrity check. The read route binds both `server.ts` route registration and `routes/basket.ts::retrieveBasket`; the write candidate binds the Address PUT registration, `appendUserId` middleware and owner-side address read route.

Validator and Executor recompute the source binding against the current checkout. Executor also compares the bound source-file digests with the active B04 generation. The model can select only an opaque `check_id`; it cannot supply an actor, object, endpoint, HTTP method, URL, session, credential, header, field or body.

## 3. Registered capability and policy

`verify_access_control` is a narrow registered capability with strict Pydantic inputs and sanitized typed observations. Its allow rule is supplied by `policies/b05-access.yaml`, layered over the unchanged frozen `policies/default.yaml`. The overlay is accepted only for this exact tool and exact `check_id` contract.

The operator registry records OWN-READ at `GET /rest/basket/:id` with a 7-exchange limit. The legacy Address city-write remains denied after B01 recomputation. BasketItem v2 and ownership transfer are fixed operator-owned DEV candidates with 12-exchange limits; they are not automatically offered to the model. No arbitrary URL, object ID, method, body, SQL or credentials are agent inputs.

## 4. OWN-READ semantics and Docker result

The runtime performs the R01 schedule exactly: owner read, separate denied-object control, attacker self-read, owner baseline, two attacker cross-owner reads with a complete B04 reset between trials, and final owner baseline read. It requires both verified identities, owner-only object proof, permissions, successful controls, matching source/action bindings, identical owner-bound private marker observations, reset, cleanup and unchanged source hashes.

The final Docker acceptance returned **CONFIRMED** for `juice-basket-own-read-v1` on the pinned Juice Shop DEV image: 7/7 exchanges, both repeated probes exposed the owner-bound basket data, controls passed, reset passed, cleanup passed and source integrity passed. This is a controlled result for synthetic accounts and one disposable object; it does not claim exposure of real user data.

## 5. OWN-WRITE semantics and safe-target limitation

The earlier fixed Address city-write attempt in a disposable container remains preserved. Its separate negative-control PUT returned success, then the owner-side readback returned HTTP 400 because the generic Address PUT middleware replaced `UserId` with the caller's identity. This can change ownership even when the body contains only `city`; the trace was **INCONCLUSIVE**, never REJECTED or CONFIRMED. Validator continues to deny this unsafe legacy candidate.

Changing ownership violates B05's one-field mutation boundary. The code now fails closed: Validator denies this candidate before fixture bootstrap, Executor repeats the same check, and Agent does not offer it. This prevents subsequent runs from repeating the unsafe operation. The final acceptance records the denial and performs no OWN-WRITE HTTP requests.

A refreshed source review of the pinned target supports a candidate at `PUT /api/BasketItems/:id`: authentication and quantity bounds are enforced, the model has no `UserId`, `BasketId` and `ProductId` are protected by hooks, and timestamps are enabled. The candidate allows exactly `{quantity, updatedAt}`, with server-generated timestamp proof, unchanged `createdAt`/relationships/other items and independent B-owner readback. Canonical R01 adoption remains pending explicit review; this runtime experiment does not approve or rewrite R01.

The bounded Docker DEV run `artifacts/b05-own-write-v2-20261014-v7/` completed exactly 12 HTTP exchanges across three reset-separated generations. Both trial readbacks observed exactly `{quantity, updatedAt}`; `createdAt`, IDs, basket/product relationships and other items remained unchanged. Owner-write and self-write positive controls, ownership, reset, cleanup and source integrity passed. However, A's separate update of another B-owned negative-control BasketItem also returned HTTP 200 and changed it, so `negative_control=false`. Under the fixed contract this failed control forces Evidence **INCONCLUSIVE**; the manifest is `incomplete`, not a successful R01 result. The observed candidate delta is measured but does not override the control failure. See [`b05-r01-own-write-v2-candidate.md`](b05-r01-own-write-v2-candidate.md).

## 6. Separate OWNERSHIP-TRANSFER hypothesis

Source review found the Address route authenticated globally, then passing through `appendUserId()`, which assigns the caller's ID to `req.body.UserId`; the generic Finale Address handler exposes the model's `UserId`. Unlike the owner-side GET route, the inspected PUT route has no per-object ownership check. This creates a testable unauthorized ownership-transfer hypothesis but does not prove persistence or access-control failure by itself.

A distinct v1 candidate uses a fixed empty-body PUT by synthetic A against disposable Address B and a fixed read-only parameterized SQLite query returning only row ID and `UserId`. In `artifacts/b05-ownership-transfer-v1-20261014-v1/`, both reset-separated trials proved initial owner B and persisted final owner A; A/B identities, separate denied-read control, owner availability, reset, cleanup and source integrity passed. Evidence is **CONFIRMED** for this narrow ownership-transfer hypothesis. The former owner's HTTP response is supplementary only. This result is not OWN-WRITE, R01-AUTH or permission to alter canonical R01. See [`b05-ownership-transfer-v1-candidate.md`](b05-ownership-transfer-v1-candidate.md).

## 7. Evidence, artifacts and offline review

Other reviewed paths were unsuitable for the same contract: product reviews are shared and can trigger challenge state, profile updates derive the current user's identity rather than testing cross-owner access, and delivery/accounting operations change multiple or sensitive fields. No candidate passed source review. The prior Address diagnostic remains INCONCLUSIVE and is preserved; it is not evidence for the BasketItem path.

Deterministic unit tests cover synthetic confirmed and rejected OWN-WRITE traces, including independent owner readbacks, exact repetition and reset. Those are contract tests only; they are not a real Juice Shop write result and are not benchmark metrics. A separately approved DEV fixture/adapter must provide an operation that persists exactly one allowlisted field and supports independent owner readback and reset before runtime OWN-WRITE can be enabled.

The interpreter is deterministic code; no LLM judges the result. It validates exact schedule and actor/object/endpoint/method tuples, controls, generations, B01 binding, source snapshot, fixed mutation metadata, repeated observations, reset, cleanup and integrity. Incomplete or mismatched observations remain inconclusive. Validator denial remains a policy outcome, not a finding verdict.

Acceptance files contain the action, B01 binding resolution, Validator decision, Executor record, audit reference, sanitized trace, Evidence, B04 lifecycle, manifest and SHA-256 seal. Session tokens remain in worker `/state` tmpfs. No request/response bodies or credentials are persisted. The offline verifier checks file sets and byte hashes, validates provenance and recomputes verdicts without an LLM. Current valid packages and failed-attempt diagnostics are:

- OWN-READ regression: `artifacts/b05-own-read-regression-20261014-v1/` — sealed, 13 files, CONFIRMED, 7 exchanges.
- OWN-WRITE v2: `artifacts/b05-own-write-v2-20261014-v7/` — sealed, 14 files, INCONCLUSIVE, 12 exchanges. Six earlier technical attempts `v1`–`v6` remain separately sealed with their diagnostics; none was deleted or scored as a valid result.
- OWNERSHIP-TRANSFER: `artifacts/b05-ownership-transfer-v1-20261014-v1/` — sealed, 13 files, CONFIRMED, 12 exchanges.
- Offline verifier scorecards and seals for all nine packages (including all six failed attempts) are in `artifacts/b05-offline-verification-20261014/`. All nine package seals match their files; offline replay confirmed the three completed packages and correctly rejected incomplete attempts as scoreable runs.

Final historical acceptance package: `artifacts/b05-acceptance-20261014-final/` — 17 sealed files, 105,250 bytes before the seal file; seal SHA-256 `4ebdf0d789de50bcf8b6c2d266efdd5a6a9bf2e0c0bfd80eafe185d70716517b`. Its offline result remains `verified_with_limitations`; OWN-READ confirmed in 7 exchanges, legacy Address OWN-WRITE unsupported by Validator, cleanup verified.

The separately versioned v3 package is `artifacts/b05-own-write-v3-20261014-v1/` — 15 files including `seal.json` (14 sealed entries), 353,794 bytes total; seal SHA-256 `fe90288398573d9ed5dc1343a42e7e8e398c70b2fe0620f1177ef8903777f076`. Offline verification returned `verified`, recomputing `CONFIRMED` at 12 exchanges and matching all three worker steps, session/generation bindings, full-basket snapshots, profile permission relations and cleanup. Secret-pattern scan found no suspicious files. Docker cleanup left no B04-labeled containers; the pinned target checkout remained clean at `5658473cf8814459bf89000ce373b20ed0b4eb37`.

The earlier unsafe write-candidate diagnostic is preserved separately in `artifacts/b05-acceptance-20261014-run04/`. It records the failed control and inconclusive result and must not be read as a vulnerability verdict. Three earlier bootstrap/implementation attempts are also sealed in their run directories; all confirmed container/network cleanup and unchanged target sources.

## 8. Isolation and integrity

The integration uses digest-pinned local images, an internal Docker network, no published ports, read-only target source, bounded CPU/memory/process/time/output, and a worker with a private tmpfs for session tokens. The B04 target and worker are destroyed on completion and failure. Runtime checks never invoke host commands or accept an external target. Acceptance records `external_targets: 0`, `llm_requests: 0`, and `ground_truth_read: false`.

The B05 addition does not modify frozen A05 matcher, labels, scoring, protocol, or `policies/default.yaml`. The Juice Shop checkout stayed at pinned commit `5658473cf8814459bf89000ce373b20ed0b4eb37` and remained clean. No benchmark labels, holdout, A06/A07 measurements or `.env` were read or changed.

## 9. Verification results

The current combined B05, B01, B04, Validator, Executor, Evidence and backend regression passed: **182 passed, 1 skipped**. This includes the 16 v3 contract-matrix scenarios. Ruff, Python compilation, `git diff --check`, and `python -m app.main` passed.

The full backend suite was rerun with a temporary path to the already clean pinned Juice Shop checkout: **1017 passed, 27 skipped, 21 failed**. All 21 failures are the known freeze-dependent A01/A04/A06 tests and stop at the same A04 input-lock check: the locked `.gitattributes` byte digest differs from the feature worktree's file. No frozen input or lock was changed. The temporary checkout junction was removed. The single bounded v3 Docker acceptance was run separately and its sealed artifacts passed offline replay.

## 10. Definition of Done

| Requirement | Result |
|---|---|
| Registered opaque access check behind Validator → Executor → Evidence | Implemented |
| B01 binding and B04 fixture lifecycle reused | Implemented |
| OWN-READ deterministic verdict and real Docker integration | Confirmed; exact 7-exchange schedule |
| OWN-WRITE v2 bounded runtime candidate | **Historical INCONCLUSIVE**; retained as sealed, unchanged evidence |
| OWN-WRITE v3 bounded runtime candidate | **DEV VERIFIED / CONFIRMED**; one 12-exchange acceptance, sealed and offline-replayed; canonical approval pending |
| OWNERSHIP-TRANSFER | **Confirmed separately** by read-only SQLite owner proofs in both trials; not counted as R01 OWN-WRITE |
| Offline provenance, rescore, seal and cleanup evidence | Verified for all completed packages; all technical attempts preserved and sealed |
| Frozen A05 inputs and matcher unchanged | Verified; A05 focused tests passed |

Current project status is **B05 V3 DEV VERIFIED — CANONICAL APPROVAL PENDING**. v3 directly observed A's fixed cross-owner update change B's registered `quantity` from 1 to 2 in both reset-separated trials; independent B readbacks showed only `{quantity, updatedAt}`, while ownership, object relations and all untouched siblings remained stable. The anonymous control returned 401 and left the full basket unchanged; owner/self controls, reset, cleanup and integrity passed. This supports the narrow disposable Juice Shop BasketItem BOLA/IDOR hypothesis and does not generalize beyond this route or authorize canonical R01 adoption. The historical v2 negative-control failure and separate ownership-transfer result remain intact. No B06/B07/B09 work was started, and this branch was not merged or pushed.
