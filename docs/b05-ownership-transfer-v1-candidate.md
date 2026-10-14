# B05 OWNERSHIP-TRANSFER v1 — bounded development candidate

**Status: bounded DEV acceptance completed and CONFIRMED.** This is a distinct security hypothesis, not R01-OWN-WRITE and not R01-AUTH. It does not add a microservice or modify Juice Shop.

## Fixed hypothesis and scope

On the pinned Juice Shop DEV commit `5658473cf8814459bf89000ce373b20ed0b4eb37`, can synthetic role A, which has no update permission for one disposable Address owned by role B, transfer its `UserId` to A through the registered `PUT /api/Addresss/:id` route?

The route is authenticated globally and passes through `appendUserId()`, which overwrites request `UserId` with the authenticated caller's ID. The generic Finale Address handler accepts the model's `UserId` field. The inspected route has no per-object owner check on PUT. The owner-side GET route filters by both address ID and `req.body.UserId`. This is sufficient source evidence to justify a bounded test, but not enough to claim a vulnerability: authorization, actual persistence, initial/final ownership and controls must be observed at runtime.

## Required independent proof and schedule

Use exactly two newly created synthetic users and one disposable Address B in a fresh internal Docker lab. Before mutation, prove both server identities, B's owner-side GET and the independent server-side `Addresses.UserId` value. Prove A cannot read the object and has no update permission in the fixture manifest. Send one fixed A-authenticated PUT with an empty JSON object; no caller-selected IDs, URL, field, value or credentials are accepted.

After mutation, independently inspect the target's SQLite row using a fixed, read-only, parameterized query inside the target container. The only allowed lookup is the registered numeric Address ID against `Addresses`; return only the row ID and `UserId`, not address contents. Require this proof to bind the same disposable generation and compare the resulting owner to the independently verified role-A ID. A role-A owner-side GET may corroborate the result; role-B GET returning 400 is only a secondary observation and is never the ownership proof. An HTTP status alone cannot decide the verdict.

The acceptance must include the fixed positive control (B reads its own address), separate negative control (A cannot read a distinct B-owned address and its owner still can), the A unauthorized transfer trial, reset and an exact repeated trial, final owner-side/server-side state checks, source integrity and Docker cleanup. If trusted DB observation is unavailable or any control fails, verdict is INCONCLUSIVE. If Validator denies, record policy denial, not REJECTED. `confirmed` requires independently proved original B ownership, denied A permission, persisted final A ownership in both trials, matching identities, successful controls, reset, cleanup and integrity.

## Runtime result (2026-10-14)

The sealed package `artifacts/b05-ownership-transfer-v1-20261014-v1/` completed 12 HTTP exchanges across two independent B04 generations. Both began with role B as the verified owner and ended with role A as the persisted `Addresses.UserId`, as shown by the fixed read-only parameterized SQLite query inside the target container. Synthetic identities, owner availability, the separate denied-read/owner-readable control, reset, cleanup and source integrity all passed. The old owner's HTTP response was only supplementary. Deterministic Evidence is **CONFIRMED** for this exact DEV ownership-transfer scenario. This does not establish generic IDOR coverage, does not count as OWN-WRITE/R01-AUTH, and does not change canonical R01 or historical benchmark results.

## Safety boundary

The worker must use only fixed source-controlled SQL and a bound integer parameter; no SQL, path or shell fragment comes from AgentState. It emits booleans, opaque IDs and digests only. Tokens stay in worker tmpfs. Target remains pinned, read-only from the host, on an internal network with no published ports. No production target, real user data, ground truth, HOLDOUT or benchmark scorer is involved. The experiment must not be represented as OWN-WRITE or R01-AUTH.

