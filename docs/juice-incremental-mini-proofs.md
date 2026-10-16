# Juice Shop incremental fixed-proof acceptance

This is a bounded operator-only acceptance harness for two controlled Juice Shop
properties. It is not an agent discovery run, an A04 benchmark score, or a
reproducibility estimate. It must not be presented as evidence that RepositoryScout
found either issue.

## Frozen environment

- Source checkout: `artifacts/benchmark-target/juice-shop`
- Commit: `5658473cf8814459bf89000ce373b20ed0b4eb37` (Juice Shop v20.2.0)
- Target image: `bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b`
- Worker image: `python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4`

The runner checks the clean pinned checkout, snapshots only protocol source files,
hash-binds the fixed worker and profile, creates a fresh internal Docker network and
target container, then removes both. The worker is non-root, read-only, networked
only to that internal target, and has CPU, memory, process, request, response, and
wall-time limits. Credentials and session tokens remain in worker memory and are
not written into artifacts. Each acceptance output directory must be new and
outside the target checkout.

## Protocols

### Elevated role registration

The worker registers a normal customer as a healthy control, registers a second
one-time account requesting the `admin` role, logs into both independently, and
reads `/rest/user/whoami?fields=id,email,role` through each new session. The verdict
uses the server-side readback and distinct account identities; a successful
registration response alone is insufficient. The protocol does not use existing
users or credentials.

### Anonymous Product PUT

The worker creates two disposable products as a synthetic customer. An authenticated
PUT/readback is the positive control. It then makes an anonymous PUT to a second
synthetic product and independently reads the resulting state. An anonymous POST
control must be denied and the created product must remain absent. The protocol
changes no pre-existing catalog entries; all mutations live only in the disposable
target container, which is destroyed after the trial.

## Run

```bash
python -m app.juice_incremental_proof \
  --target artifacts/benchmark-target/juice-shop \
  --output artifacts/juice-incremental-role-acceptance-<unique-id> \
  --protocol role-registration --generations 1

python -m app.juice_incremental_proof \
  --target artifacts/benchmark-target/juice-shop \
  --output artifacts/juice-incremental-product-acceptance-<unique-id> \
  --protocol anonymous-product-put --generations 1
```

For reproducibility work, use two independent generations and distinct fresh output
directories. Do not treat a single-generation acceptance as a reproducibility
measurement.

## Acceptance record on 16 October 2026

One real Docker generation completed for each protocol:

| Protocol | Result | Independent observations | HTTP requests | Cleanup/source integrity |
|---|---|---|---:|---|
| Elevated role registration | `confirmed` | baseline `customer`; candidate read back as `admin`; distinct identities | 6 | pass / pass |
| Anonymous Product PUT | `confirmed` | authenticated PUT persisted; anonymous PUT persisted; anonymous POST denied and absent | 13 | pass / pass |

These are protocol-level findings on the pinned Juice Shop instance. They do not
change A04 labels or scores, and they do not count as model detections. The two
checks are now exposed to the canonical agent workflow only through the dedicated
`targets/juice-incremental-proof.yaml` profile and fixed `verify_juice_proof`
capability. The source-detector rule ID and exact source file must match one of two
operator-owned routes. The application creates the binding; Validator and Executor
recompute the route/source binding, and approval covers the entire proposal. The
model receives only a registered candidate ID and cannot choose a URL, path,
command, protocol body, or target.

Executor runs the fixed worker in a fresh pinned internal Docker generation.
Evidence is derived from the persisted typed trial, recomputes the narrow verdict,
and requires a matching execution record and audit. Missing or mismatched audit,
stale source, denied policy, failed controls, or unverified cleanup cannot confirm
the finding. Offline regressions cover routing, binding, policy, wire compatibility,
verdict recomputation, and cleanup failure.

The live model has not yet discovered these cases through a fresh blind run. The
acceptance records above remain protocol-level results, not proof of improved A04
Recall. A future run must first discover a matching finding without scanner seeds
or benchmark labels before this proof capability can be selected.

## Canonical campaign acceptance

The opt-in test `test_incremental_proofs_through_real_campaign_and_offline_replay`
ran both real source-detector findings through the ordinary campaign, registered
profile, Validator, SafeExecutor, persisted audit, Evidence and final report.
Both protocols returned `confirmed`; source integrity and cleanup passed.
Offline replay reconstructed the same two verdicts. The acceptance took 12.33
seconds and made zero model calls. Its output is
`artifacts/juice-incremental-canonical-acceptance-2026-10-16/`.

This integration check exposed an incorrect JSON nesting assumption in Evidence:
the fixture returns `result.trial`, while the old interpreter expected
`result.result.trial`. The interpreter and regression now consume the real
fixture shape and also bind the trial generation hash to the persisted session.

The diagnostic runner now explicitly loads the incremental profile. Each new
protocol reserves 114 campaign HTTP requests (90 readiness attempts plus at most
24 protocol exchanges) and retains the entire reservation. It requires 900
seconds remaining for its bounded lifecycle. The integrated research run uses
an explicit total cap of 2048; the per-question research cap stays unchanged.
These fixed proofs remain attributable to their exact detector findings and
cannot be propagated to grouped findings. Source snapshots in the sealed proof
profile are checked against finding provenance during offline scoring.

The first acceptance attempt exposed two implementation defects before yielding a
verdict: Docker Desktop rejected a one-file local log configuration, and the host
and worker computed the generation binding differently. Both were fixed; the
successful results above came from fresh disposable generations. Failed-attempt
diagnostic artifacts are retained separately and must not be combined with the
successful acceptance records.
