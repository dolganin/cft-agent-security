# A07 integration review (2026-10-13)

The incoming branch adds the Windows-only pinned offline Semgrep fallback,
an operator A07 harness and historical A06/A07 reports. This merge does not run
a new benchmark and does not certify the remote operator's raw artifacts.
Those artifacts have not been supplied to this checkout.

Review corrections for future attempts:

- The harness now explicitly passes frozen model, Scout, Executor and wall-clock
  settings to the producer. Previously it recorded settings but inherited the
  process environment and .env. Historical effective settings require the raw
  logs and operator configuration to verify; they cannot be inferred from this fix.
- Failure counters include the provider's actual request/auth/schema statuses;
  fallback audit rows are not counted as provider requests.
- Run names support all three independent attempts and their distinct retries.
- A completed manifest requires successful integrity and cleanup checks; missing
  cleanup evidence cannot be recorded as a completed attempt.

The CLI currently freezes/verifies/runs individual attempts. Offline scoring and
series aggregation are separate operator steps, not implemented by this script.
Provider `network_error` combines network failures and timeouts; its audit alone
cannot establish an exact timeout count. The raw artifacts remain necessary.

Existing results and immutable A01/A04/A06 inputs are not rewritten. A new run
requires a new freeze at the new commit, never reusing a historical A07 lock.
Historical single-run detection scores are not confirmed-verdict metrics or
evidence of between-run reproducibility. The baseline reuse predicate currently
requires an identical agent commit, so older baseline artifacts may need a
separate provenance review even when their scanner inputs are unchanged.
