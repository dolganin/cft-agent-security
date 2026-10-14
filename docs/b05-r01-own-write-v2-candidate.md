# B05/R01 OWN-WRITE v2 — candidate operator extension

**Status: candidate only; bounded DEV runtime was exercised, while canonical R01 adoption still requires explicit review.** This document defines the narrow source-reviewed contract used by the disposable B04 acceptance; it does not approve a canonical R01 change.

## Contract delta

The existing R01-OWN-WRITE one-business-field rule remains. A check may change exactly one registered business field and may additionally persist `updatedAt` only when all of the following hold:

- the target model declares Sequelize timestamps and has no target-specific update hook that writes additional fields;
- the fixed request contains only the registered business field;
- the independent owner readback records the exact changed-field set as `{<registered business field>, updatedAt}`;
- `updatedAt` is a valid server-generated timestamp later than its baseline, while `createdAt` is unchanged;
- ownership and all other fields, relations, identities and permissions remain unchanged;
- the request and the complete repeat/reset schedule stay inside the already declared family budget.

For the candidate Juice Shop BasketItem check only, the business field is `quantity`, the endpoint is `PUT /api/BasketItems/:id`, and the sole allowed technical field is `updatedAt`. The exact changed-field set must be `{quantity, updatedAt}`. `UserId`, `BasketId`, `ProductId`, `createdAt`, all other BasketItems, and all other fields are forbidden changes. An HTTP success without the independent owner readback is inconclusive. This extension does not grant permission to pass arbitrary extra fields or to ignore changed-field accounting.

## Source review snapshot

Pinned target commit: `5658473cf8814459bf89000ce373b20ed0b4eb37`.

The route is behind `security.isAuthorized()` and uses `appendUserId()`; the update middleware loads the item by ID, checks the requested quantity against product stock/limits, and then falls through to the generic Finale BasketItem model handler. BasketItem declares `ProductId`, `BasketId`, `id`, and `quantity`, with Sequelize timestamps enabled by default. Relationship hooks mark `BasketId` and `ProductId` non-updatable. No BasketItem-specific update hook was found in the inspected model/route. The BasketItem has no `UserId`; the operator fixture must prove ownership through B's basket and the nested BasketItem relation.

This review supports a bounded experiment, not a runtime result or canonical R01 approval. Before enabling it, the worker must independently read B's basket before and after, compare the exact nested BasketItem ID, parent basket, product, quantity, `createdAt`, and `updatedAt`, and demonstrate that the fixture's legitimate B update and separate A negative-control attempt work. Reset destroys and recreates the whole disposable lab.

## Bounded DEV runtime result (2026-10-14)

The sealed package `artifacts/b05-own-write-v2-20261014-v7/` completed 12/12 registered exchanges across three reset-separated generations. Both candidate readbacks showed exactly `{quantity, updatedAt}`; `createdAt`, item/basket/product relationships, and other items remained unchanged. The distinct cross-owner negative-control update also returned HTTP 200 and changed its B-owned item, however, so the control failed and deterministic Evidence remained **INCONCLUSIVE**. This run supports the observed target behavior but does not satisfy the OWN-WRITE DoD and is not canonical R01 acceptance. Offline replay and package seal verification passed. Six earlier technical attempts remain preserved under `artifacts/b05-own-write-v2-20261014-v1/` through `-v6/`.

