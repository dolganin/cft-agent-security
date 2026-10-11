# R01 acceptance-fix result

Date: 2026-10-11. Branch: `codex/s01-integration-contracts` (no commit, no
push). Scope strictly `docs/r01-verification-specifications.md`,
`contracts/examples/r01/*`, `tests/test_r01_specifications.py` and this file.
No production capability, interpreter, schema, policy, K01/K02 artifact,
subagent or live payload was touched. All examples remain synthetic;
`r01_synthetic_fixture` remains unregistered.

## Changed files

* `docs/r01-verification-specifications.md`
  * Common budget rewritten: `common_max_http_exchanges = 8`; positive and
    negative controls must be distinct requests from the probe (no request may
    simultaneously expect denial and unauthorized success); family budgets are
    explicit enumerated schedules, never a silent loosening; operator reset
    adapter runs are never unreviewed model writes and are not HTTP exchanges,
    but every verification read they require is counted.
  * R01-AUTH (acceptance point 1): one claim per run; the authorization
    negative control MUST NOT reuse the candidate operation — the operator
    pins a distinct B-reserved `auth_control_operation_id` never verified by
    the candidate; `oc-a-protected` is the operator positive availability
    control proving the real operation works for B; explicit 10-exchange
    schedule (authn runs: 9), including two independent session/principal
    verification exchanges and reserved retry.
  * R01-REDIRECT (point 1): separate `negative-control destination ID` and
    probe destination ID; probe and negative control are distinct requests;
    explicit 8-exchange schedule (7 + reserved retry), sink never contacted.
  * Per-family enumerated HTTP budgets with exact totals (point 2):
    OWN-READ 7 (tightened), OWN-WRITE 12 (explicit reviewed family budget;
    the original 8 cannot hold two control cycles + two write/readback
    trials), AUTH 10/9, REDIRECT 8, CODE 6 (container evaluations counted as
    exchanges). Each schedule lists operations, controls, readbacks, retries
    and cleanup; every total was machine-recomputed against the fixtures.
  * R01-CODE (point 3): mandatory evaluation-observability positive control —
    the identical fixed inert arithmetic expression must return its
    marker-bound scalar in a separate operator-allowlisted safe evaluating
    context (`oc-c-observable`); literal reflection alone is explicitly
    insufficient; expression grammar remains fixed arithmetic over constants
    plus a synthetic marker, no shell/network/secrets.
  * Every family lists its three synthetic fixture files; the catalog section
    now states that fixtures are contract templates and that
    `tests/test_r01_specifications.py` is the only (test-only) conformance
    evaluator.
* `contracts/examples/r01/r01-family-specifications.synthetic.json` (new)
  machine-readable family spec templates: enumerated exchanges, maxima,
  reserved retry capacity, required facts, deficiency codes, mutation kinds.
  Contract fixture only, `contract_fixture_only: true`, not a second
  production Evidence model.
* `contracts/examples/r01/evidence-{owned-read,owned-write,auth,redirect,code-eval}-{confirmed,rejected,inconclusive}.synthetic.json`
  (15 new files, point 4/5): canonical `Evidence`-valid synthetic examples per
  family with control results, identity/owner proof, `claim_id` and
  action/endpoint/snapshot bindings, executed-exchange lists, repeat counts and
  cleanup facts. All refs are synthetic.
* `tests/test_r01_specifications.py`
  * Keeps the original section-structure, catalog/rubric and legacy
    ownership-read compatibility tests (point 4: old examples stay valid; they
    are now additionally asserted to be flagged incomplete by the semantic
    evaluator).
  * Adds semantic sufficiency evaluation (point 5): confirmed/rejected
    fixtures must evaluate with zero deficiencies; each inconclusive fixture
    must carry its documented deficiency. Mutation tests: missing negative
    control (value and removed-fact variants), no repeat, binding mismatch,
    ambiguous owner, mere HTTP-200/status/reflection basis, missing
    independent readback, unproved identity, unregistered required facts —
    each must break sufficiency.
  * Adds docs↔fixtures consistency tests: budget tables in Markdown must match
    the machine-readable exchanges, claims scoping, reserved rows and maxima
    exactly; AUTH/REDIRECT/CODE control-separation and observability phrases
    are asserted.

## Checks run

Integration acceptance after this worker result added mutation tests for runtime
provenance, cross-family binding, missing identity on rejected results, and
distinct auth/redirect negative controls. The test-only evaluator now rejects
these cases for both terminal verdicts. Targeted suite: **49 passed**.
The worker's original test counts below remain historical, not current totals.

* `PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m pytest tests/test_r01_specifications.py -q` → 39 passed.
* `... pytest tests/test_r01_specifications.py tests/test_contracts.py tests/test_evidence_v2.py tests/test_validator.py -q` → 64 passed (no regressions in adjacent contract/evidence/validator areas).
* `... ruff check tests/test_r01_specifications.py` → All checks passed.
* Whitespace hygiene: `rg " +$"` over all touched files → no matches.
* JSON validity of all 20 fixtures is enforced by every pytest run above
  (canonical `Evidence.model_validate`).

## Honest blockers / deviations

* `git diff --check` exact command was blocked by this session's tool
  permission policy (only the listed `git status|diff|log ...` forms are
  allowed). I did not bypass it; equivalent trailing-whitespace checks were
  done with `rg " +$"` (clean). Please run `git diff --check` before merge.
* Ad-hoc `python` scripting outside `pytest`/`ruff` is also policy-blocked, so
  validation was done exclusively through pytest.
* `apply_patch` is not available in this session; file edits used the
  permitted edit/write tools inside the allowed paths only.
* `ruff format --check` reports differences for this file, matching existing
  repo state (several pre-existing test files, e.g. `tests/test_contracts.py`,
  are equally unformatted); `ruff check` (the CI gate) passes. I did not
  reformat to avoid unrelated churn.
* The full repository suite was not run — other agents have in-flight K01/K02
  changes in the worktree and the assignment restricted me to targeted runs.

## Limitations

* Everything here is design specification plus synthetic contract fixtures.
  No capability registration, no live requests, no Docker runs, no real
  Evidence. The conformance evaluator is test-only.
* Budgets are declared maxima/enumerations, not enforced runtime counters;
  future capability implementations must enforce them in Executor.
* CVSS remains `UNASSESSED`, Context Priority remains separate; benchmark
  ground truth still requires separate L01/R02 review.
