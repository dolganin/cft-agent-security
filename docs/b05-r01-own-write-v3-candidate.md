# B05/R01 OWN-WRITE v3 — candidate operator extension

**Status:** B05 V3 DEV VERIFIED — CANONICAL APPROVAL PENDING. Canonical R01 and v2 are unchanged. One bounded versioned DEV acceptance completed and passed sealed offline replay; the candidate is not canonical approval.

## 1. Architecture review and decision

### Threat model

A is an authenticated, ordinary synthetic customer. B is a distinct authenticated ordinary synthetic customer. The operator owns both accounts and the disposable Juice Shop lab. The claim is narrowly whether A can mutate one registered, B-owned BasketItem at `PUT /api/BasketItems/:id` despite the trusted owner-only permission matrix. The model supplies only the opaque check ID; it does not choose URL, method, body, identity, object, SQL, or credentials. A trusted B04 broker provisions the objects and holds credentials in worker tmpfs. B01 binds the route and target source snapshot. The target is local/pinned DEV only.

### Why v2's negative control is not discriminating

R01 v2 borrowed the usual purpose of a negative protection control: demonstrate that a forbidden cross-owner action is denied, while independent availability/self controls show the check is live. On this Juice Shop route, the main probe and the control are both authenticated A `PUT`s to distinct BasketItems under the same B basket, with the same owner-only permission relation. Source review found no per-item authorization rule that would distinguish them. Requiring one equivalent write to persist and the other to be denied has no server-side basis; v7's two successful B readbacks are consistent with one missing owner check, not with a broken request.

The control's security property must not disappear. v3 splits it into independent properties: (a) unauthenticated callers are rejected and cause no mutation (authentication only); (b) trusted fixture data proves A≠B, the exact object-to-basket-to-owner relationship, and A's denied/B's allowed permission relation (authorization oracle); (c) B's own write and A's self-write prove the operation is available; (d) an untouched sibling plus complete basket snapshots prove non-interference. Authentication is never treated as authorization. There is no independent target authorization boundary for a second equivalent cross-owner request on this endpoint; v3 says so rather than fabricating one.

### Strength of a confirmed result

A `CONFIRMED` result still requires an operator-owned permission oracle saying A cannot update B's basket; B04 server-identity/ownership proof; a fixed A-authenticated write to the exact B-owned registered item; independent B readback proving a real business-field change; exact full-state diff permitting only `quantity` plus server `updatedAt`; unchanged owner, basket/product relationships and all sibling items; separate authn, owner-write and A-self controls; and the same result after a complete reset. This is direct evidence of the specific BOLA/IDOR claim, stronger than an HTTP status or LLM conclusion. The v2 same-permission negative write is replaced by a truly independent untouched-object control, not dropped without replacement.

False-confirmed paths are blocked by verified server identities, fixed permission profile, item/basket/owner binding, exact action/source binding, actor/session/generation links, B-owner independent readback, full sibling snapshot comparison, exact allowlist, repeat/reset, and offline recomputation. A wrong map, missing proof, unexpected field/owner change, non-mutating HTTP 200, missing readback, identity/session mismatch, failed authn control, or failed cleanup yields INCONCLUSIVE/DENIED. One unresolved residual is that any checker trusts the pinned worker's sanitized observation of target responses; the seal gives integrity, while B01 source and action digests bind the fixed producer and request.

## 2. Fixed scope and schedule

Registered check ID: `juice-basket-own-write-v3`, bound to the single existing B01 source route `juice-basket-own-write-v2` because both protocol versions verify the same handler. This keeps B01 unambiguous while the Evidence workflow remains versioned. The operation remains `PUT /api/BasketItems/:id`; business field `quantity`, fixed value `2`; only allowed technical field `updatedAt`. No new generic HTTP capability is introduced. `basket-write-negative-b` is never written in v3 and becomes the untouched non-interference sibling. The owner control remains `basket-write-control-b`; A's self control remains `basket-write-self-a`.

The exact schedule is **12 B05 HTTP exchanges**, the already approved family budget. B04 bootstrap/control traffic remains in its existing separately bounded B04 phase; it is not silently charged as free B05 traffic. Reset itself is a fixed destroy/recreate adapter action, not an HTTP request. No retry is available in the fixed 12-request v3 schedule; a technical failure makes the run incomplete and artifacts are preserved.

| # | Exchange | Actor/object | Purpose / success evidence |
|---:|---|---|---|
| 1 | `oc-b-update` | B → B control BasketItem, PUT quantity=2 | Authorized operation is available |
| 2 | `oc-b-readback` | B → B basket, GET | Independent exact owner-write diff; also baseline snapshot for candidate and untouched siblings |
| 3 | `authn-anon-put` | anonymous → candidate BasketItem, same fixed PUT | Authentication control only; expect 401/403 |
| 4 | `authn-b-readback` | B → B basket, GET | Prove unauthenticated request left candidate and all siblings unchanged; closes authentication control |
| 5 | `sc-a-update` | A → A BasketItem, PUT quantity=2 | Optional-but-retained session/operation control |
| 6 | `sc-a-readback` | A → A basket, GET | Prove A self-write and its exact delta |
| 7 | `probe-b-t1` | authenticated A → candidate B item, PUT quantity=2 | First fixed unauthorized probe |
| 8 | `probe-b-t1-readback` | B → B basket, GET | Independent readback; exact diff and non-interference snapshot |
| 9 | `baseline-b-t2` | B → newly reset B basket, GET | Prove fresh-generation candidate and sibling baseline before repeat |
| 10 | `probe-b-t2` | authenticated A → candidate B item, PUT quantity=2 | Repeated unauthorized probe after reset |
| 11 | `probe-b-t2-readback` | B → B basket, GET | Independent readback; exact diff and non-interference snapshot |
| 12 | `cleanup-b-baseline` | B → freshly reset B basket, GET | Verify recreated baseline, ownership and sibling state |

The 12-entry schedule is exact, fixed, and no larger than the existing R01 family budget of 12. If a future revision needs another exchange, it must stop for separate budget approval; v3 must not stretch the cap.

## 3. Evidence contract and redaction

Each B04 generation binds generation ID, source/profile digests, distinct verified A/B identity hashes, role-scoped opaque session bindings, reset provenance and fixed permission profile. Session bindings are HMAC digests made inside the worker with an ephemeral generation key; the key, tokens, cookies, passwords and raw headers never leave tmpfs. The key is destroyed with the lab. Per-exchange provenance records the actor role (or `anonymous`), actor identity/session binding where applicable, generation, fixed endpoint/method, request digest, and opaque target/parent object identity.

B-owner basket snapshots contain only fixed synthetic fixture facts: registry object ref, per-generation opaque BasketItem/Basket identity digests, fixed ProductId, quantity, `createdAt`/`updatedAt`, owner role/identity hash, and a verifier-computable digest of those fields. No response body, email, password, token, or real-user data is persisted. The worker verifies nested `BasketItem.BasketId == basket.id`, `Products[].id == BasketItem.ProductId`, and `basket.UserId == verified B` before emitting a ready snapshot. The same opaque IDs must link baseline → request → readback within one generation and change after reset; untouched sibling IDs and states must remain stable within the generation. Offline verifier checks these links, recomputes state deltas and timestamp ordering, replays the verdict, and checks the sealed files. Missing raw identifiers are not replaced by an unexplained boolean.

## 4. Controls and decision table

| Control / proof | Property | Preconditions and expected result | Independent evidence | Failure effect |
|---|---|---|---|---|
| Anonymous PUT + B readback | Authentication | Fixed candidate exists and baseline known; anonymous request denied; no object state changes | status plus full B snapshot before/after | INCONCLUSIVE; never substitute for authorization |
| A/B identity + ownership + permission | Authorization oracle | Distinct server `customer` identities; item belongs to B basket; operator matrix says A update=false, B update=true | B04 whoami, owner proof, nested relation, hashed profile binding | INCONCLUSIVE |
| B control write/readback | Endpoint and field availability | B updates its separate control item; only quantity and later updatedAt change | B owner readback and baseline | INCONCLUSIVE |
| A self-write/readback | A session and request wiring | A updates its own disposable item; exact delta only | A identity-bound readback | INCONCLUSIVE |
| A cross-owner probe + B readback | BOLA/IDOR under test | Fixed request and exact registered B object; real B-owned state mutation or no mutation | Request/object/session binding and B's independently read basket snapshot | Changed permitted delta in both trials may CONFIRM; unchanged in both may REJECT; mixed/unknown => INCONCLUSIVE |
| Untouched sibling/full basket comparison | Non-interference | At least one separate B-owned fixture item is never written by this check | Same opaque item/basket IDs and full safe row-state digests at every B snapshot | Any sibling/relationship/owner change => INCONCLUSIVE |
| Reset/repeat/cleanup/integrity | Reproducibility and containment | Fresh generation before trial 2 and clean disposable lab afterward | Distinct generation/session bindings, baseline equality, destroyed resource labels, source digest | INCONCLUSIVE |

`CONFIRMED`: all proofs/controls pass, both reset-separated probes reach the bound object as authenticated A, B independently observes the same registered business value in both trials, the exact changed set is `{quantity, updatedAt}`, timestamp is server-generated and later than baseline, and no owner/relation/sibling/other-field change occurs.

`REJECTED`: all the same identity/ownership/permission/availability/authn/readback/integrity controls pass, both A writes demonstrably leave the bound B object at baseline, and full snapshots show no side effects. An HTTP 200 alone is never a mutation result. If the probe was not bound to the expected object or did not reach the registered endpoint, the result is INCONCLUSIVE, not REJECTED.

`INCONCLUSIVE`: missing/ambiguous proof; failed authn/positive control; wrong identity or object mapping; unavailable independent readback; unchanged/ambiguous business field; unexpected state changes; incomplete reset/repeat/cleanup/source integrity; session/generation discontinuity; budget exhaustion; or any technical failure. Validator denial remains a policy outcome, not an Evidence verdict.

## 5. Regression matrix required before runtime

| Case | Expected result |
|---|---|
| Vulnerable endpoint: both equivalent A→B writes mutate | CONFIRMED only with all v3 proofs and both complete trials |
| Protected endpoint: owner control works, A cross-owner writes do not mutate | REJECTED |
| HTTP 200 without state change | REJECTED only if both readbacks and every control are complete; otherwise INCONCLUSIVE |
| Wrong role mapping / identity swap | INCONCLUSIVE |
| Wrong BasketItem→Basket mapping | INCONCLUSIVE |
| Missing owner proof | INCONCLUSIVE |
| Missing permission proof/profile mismatch | INCONCLUSIVE |
| Business field absent/ambiguous | INCONCLUSIVE |
| Unexpected sibling business-field change | INCONCLUSIVE |
| Owner relation changes | INCONCLUSIVE |
| Anonymous request not denied or changes state | INCONCLUSIVE; do not continue toward CONFIRMED |
| Reset incomplete or reused generation | INCONCLUSIVE |
| Source/action binding mismatch | DENIED before runtime or INCONCLUSIVE in offline replay |
| Independent B readback missing | INCONCLUSIVE |
| Session/generation binding discontinuity | INCONCLUSIVE |
| Schedule exceeds 12 exchanges | DENIED/INCONCLUSIVE; never increase budget |

These synthetic regression cases test the deterministic contract only; they are not runtime measurements. They cannot replace the one bounded Docker acceptance.

## 6. Non-goals and compatibility

The v3 check is a new versioned operator registration. It does not change canonical R01, existing v2 interpretation, OWN-READ, OWNERSHIP-TRANSFER, A05 matcher/scoring, frozen A01–A08 inputs, Juice Shop source, or model authority. Old v2 acceptance packages remain byte-for-byte unchanged and must still pass offline replay. v3 does not claim general BOLA coverage from one fixture or generalize beyond the registered BasketItem operation.

## 7. Acceptance gates and status

Before Docker acceptance: deterministic regression matrix passes; targeted B05/B01/B04/Validator/Executor/Evidence/offline tests pass; Ruff, compilation and `git diff --check` pass; old OWN-READ/OWNERSHIP-TRANSFER sealed packages replay unchanged; exact action source binding resolves against the pinned Juice Shop commit; schedule remains the fixed 12 exchanges. The acceptance uses one new versioned output directory and one run; v2 and other historic artifacts remain immutable.

The single DEV acceptance at `artifacts/b05-own-write-v3-20261014-v1/` returned `CONFIRMED`, completed all 12 exchanges, passed reset/source integrity/cleanup, and was sealed. `python -m evaluation.b05_offline artifacts/b05-own-write-v3-20261014-v1` returned `verified` for 14 sealed entries. The package contains 15 files including the seal, totals 353,794 bytes, and has seal SHA-256 `fe90288398573d9ed5dc1343a42e7e8e398c70b2fe0620f1177ef8903777f076`. Relevant tests passed (182 passed, 1 skipped); full suite: 1017 passed, 27 skipped, 21 known freeze-dependent `.gitattributes` failures. Ruff, compilation, diff check and `python -m app.main` passed. This status does not approve canonical R01; the known failures and historical evidence remain visible and unchanged.
