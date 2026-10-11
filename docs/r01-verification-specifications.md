# R01: bounded verification specifications

Status: design specification and labeling template only. These five families
are not registered capabilities, approved tools, or benchmark ground truth.
This document does not grant target, service, endpoint, role, or network access.
Every future active operation still requires an operator-owned target binding,
Validator approval, registered Executor capability, bounded execution, and
persisted Evidence. Production is out of scope.

## Common contract

The test unit is one operator-created, disposable local test fixture pinned to a
source snapshot and reset procedure. `target_id`, `service_id`, `endpoint_id`,
`role_a_id`, `role_b_id`, object IDs, request shapes, and reset adapter IDs are
opaque operator registry identifiers; the agent may select only identifiers
already approved by that registry. They are not host paths, URLs, credentials,
or permission to add an endpoint. Role A is the less-privileged tester; role B
owns the reference object or has the comparison privilege. A human or fixture
manifest establishes ownership and intended authorization before the run.
Accounts use synthetic data and disposable credentials; secrets and real user
data are excluded from Evidence.

Default upper bounds for a future contract test (operator may tighten, never
loosen without review): 8 local HTTP test-service exchanges per run
(`common_max_http_exchanges = 8`), 4 KiB request body per exchange, 64 KiB
response body per exchange, 20 seconds wall time for the check, and one
verification iteration plus one repeat after reset. One bounded positive
control and one separate negative control are mandatory, and they must be
distinct requests from the candidate probe: no single request may carry both a
deny expectation and an unauthorized-success expectation. No redirects are
automatically followed. No operation may escape the configured local
Docker/test network. The capability contract must declare stricter
family-specific bounds when the fixture needs fewer operations.

Families whose controls, trials, readbacks and cleanup cannot fit the common 8
exchanges must not silently loosen it. Each family below declares an explicit
budget schedule: an enumerated list of exchanges (operations, controls,
readbacks, resets, retries, cleanup) and an exact maximum. A family maximum
above 8 is an explicitly reviewed family budget, never an implicit relaxation
of the common default. Every HTTP exchange, including readbacks and cleanup
verification reads, counts. Operator-owned resets run through the pinned reset
adapter (fixture reload/reseed, session revocation, container destruction) and
are never unreviewed model writes; adapter invocations are not HTTP exchanges
but every verification read they require is counted. The in-container
evaluation invocations of R01-CODE are counted as exchanges inside the same
numeric envelope. The machine-readable
`contracts/examples/r01/r01-family-specifications.synthetic.json` lists the
same exchanges and maxima; docs and fixtures must match, and
`tests/test_r01_specifications.py` is the only conformance evaluator (it is
test-only, not a production Evidence model, interpreter capability, or tool
registration).

Verdict semantics describe the finding hypothesis, not whether a request merely
returned 2xx:

* `confirmed`: all required preconditions and controls passed, and repeated,
  bound observations directly establish the specified unauthorized effect.
* `rejected`: all required preconditions and controls passed, and the protected
  operation was denied or the effect was absent in both observations, including
  a positive control proving the fixture and legitimate access path work.
* `inconclusive`: evidence is incomplete, ambiguous, technically invalid, or
  cannot be bound to the authorized target/action/snapshot. Missing proof is not
  a negative security result. Validator DENY remains `policy_blocked` at the
  workflow level and is never a finding verdict.

## Evidence mapping

Use only the existing `Evidence`, `EvidenceAction`, `EvidenceObservation`,
`EvidenceScope`, and `EvidenceArtifact` contracts. No schema extension is
proposed here.

| Contract field | Required R01 mapping |
| --- | --- |
| `Evidence.id` | Unique evidence record ID from the persisted Executor record. |
| `action_id`, `action.id` | Exact approved `ActionProposal.id`; never a proposed or reconstructed ID. |
| `action.tool` | The future registry name only after separately approved registration; examples use the literal `r01_synthetic_fixture` and are not tool registration. |
| `action.run_id` | Persisted execution run ID, when available. |
| `type`, `observation.kind` | Same stable family-specific observation kind and schema version. |
| `observation.facts` | Structured control results, opaque target/service/endpoint and role IDs, owner/permission basis, snapshot digest, repeat index, sanitized status/headers or minimal response facts, cleanup result, claim ID (`claim_id`) and binding identifiers. Never tokens, passwords, user records, or response bodies beyond the minimal synthetic marker. |
| `verdict` | `confirmed`, `rejected`, or `inconclusive` only after deterministic contract validation of the facts below. |
| `source`, `sandbox_session_id` | Runtime HTTP verification is `runtime` and requires the persisted sandbox session ID. Source-only observations remain `static` and cannot establish runtime access. |
| `scope` | Exact registered target ID, `local` or `sandbox` environment, service ID, endpoint ID and approved test-fixture description. |
| `artifacts`, `artifact_refs` | Identical ordered refs. Include persisted execution and audit records plus the pinned source/fixture manifest; do not include secret-bearing logs. |

The interpreter today validates only its existing specialized result contracts.
These family mappings are a future contract-test target; a generic successful
execution, LLM conclusion, source map, or free-form stdout is not trusted
verdict Evidence. Action binding, endpoint binding, source/fixture snapshot,
session, and audit linkage must all match. Do not persist secret values or real
user data in facts, summaries, artifacts, or logs.

A source map only helps locate a candidate. It does not grant permission and
cannot expand registered target, service, endpoint, or role allowlists.

## Family specifications

### R01-OWN-READ — cross-owner object read

**Claim and scope.** Determine whether role A can read one explicitly identified,
synthetic object owned by role B through one registered read operation. Scope is
the single object, endpoint, service, snapshot, and authorization rule listed in
the operator fixture manifest. This is not a generic endpoint or ID enumeration
test.

**Fixture and controls.** The operator pins `source_snapshot_id`, `fixture_id`,
`reset_adapter_id`, `target_id`, `service_id`, `endpoint_id`, `role_a_id`,
`role_b_id`, `object_a_id`, `object_b_id`, and a separate B-owned
`negative_control_object_id`, along with owner and authorization facts. A
legitimate role-B read of B's test object is the positive availability and
permission control. A role-A read of the separate, known-forbidden control
object must be denied; this is the negative protection control. A role-A read of
A's own object additionally checks session wiring. The manifest must separately
state that A is not allowed to read B's test object. Before probing, record the
baseline object version/digest and prove the owner mapping. Never infer ownership
from sequential IDs or response content.

**Allowed operation and limits.** One registered `GET`-like operation using
`object_a_id` and then `object_b_id`; only operator-selected IDs and an opaque
session handle are parameters. Apply common request/response/time/repeat bounds.
Do not accept an arbitrary URL, object ID, header, or cookie from the model.
The complete exchange schedule is enumerated; the run budget is exactly 7
exchanges, tighter than the common default:

| Exchange | Class | ID / parameter | HTTP |
| --- | --- | --- | --- |
| `oc-r-read` | positive control | role B reads `object_b_id` | 1 |
| `nc-r-deny` | negative security control | role A reads separate `negative_control_object_id` | 1 |
| `sc-r-self` | session wiring control | role A reads own `object_a_id` | 1 |
| `baseline-r-digest` | baseline/ownership proof read | `object_b_id` version/digest pre-trial | 1 |
| `probe-r-t1` | trial 1 probe | role A reads `object_b_id` | 1 |
| `probe-r-t2` | trial 2 probe after operator reset | role A reads `object_b_id` | 1 |
| `cleanup-r-verify` | cleanup verification read | baseline digest confirmation | 1 |

Budget max 7. Operator reset and session revocation run through
`reset_adapter_id` and are not HTTP exchanges.

**Verification and verdict.** With separate role sessions, repeat the exact B
read after resetting the fixture. `confirmed` requires positive control success,
proved B ownership and A's lack of permission, and both B reads returning the
same owner-bound private synthetic marker/digest under A's identity. `rejected`
requires positive control success and both A-as-A-to-B reads denied or returning
no B-only data. HTTP 200 alone is insufficient. Inconclusive on unknown owner,
control failure, lost/changed session, ambiguous shared/public data, truncation,
technical error, changed snapshot, or any binding mismatch.

**Cleanup.** Revoke fixture sessions, reset the object and confirm its baseline
digest/version, then verify fixture teardown. Cleanup failure makes the run
inconclusive and is recorded without secret values.

**Contract examples.** Positive: A receives B's unique synthetic read marker
twice while B's legitimate read succeeds, the separate negative control is
denied, and the manifest denies A. Negative: both A-to-B reads are denied while
B's positive control, the negative control denial, and the A-to-A boundary
check work. Uncertain: B's owner manifest is missing or the second read loses
its session. Fixtures: `evidence-owned-read-confirmed.synthetic.json`,
`evidence-owned-read-rejected.synthetic.json`,
`evidence-owned-read-inconclusive.synthetic.json`; the earlier
`evidence-{confirmed,rejected,inconclusive}.synthetic.json` files remain valid
compatible ownership-read examples.

### R01-OWN-WRITE — cross-owner object mutation

**Claim and scope.** Determine whether role A can change one explicitly identified
synthetic object owned by B via one registered, reversible update operation.
Only the named field and object are in scope; delete, bulk update, arbitrary
state transition, and other records are excluded.

**Fixture and controls.** Pin the common identifiers plus `writable_field_id`,
`baseline_value_digest`, and the allowed synthetic before/after values. B's
legitimate update/readback on a separate disposable control object proves the
operation is available. A's legitimate update/readback of A's own object proves
session and operation wiring. A's attempted write to a separate B-owned,
known-forbidden control object must leave its value unchanged; this is the
negative protection control. The fixture manifest proves B ownership and that
A has no write permission. Capture B's field digest before testing.

**Allowed operation and limits.** One update to the allowlisted field with a
fixed harmless marker value; one independent readback; one reset and final
readback, repeated once from a fresh reset. Inputs are registry IDs and fixed
enum values only. No arbitrary JSON, field names, URLs, or model-provided data.
Common per-exchange byte/time limits apply. Two control cycles plus two trials
cannot fit the common 8-exchange default, so this family carries an
explicit reviewed family budget of exactly 12 exchanges:
| Exchange | Class | ID / parameter | HTTP |
| --- | --- | --- | --- |
| `oc-w-update` | positive availability control | B updates `control_object_b_id` allowed field | 1 |
| `oc-w-readback` | independent positive-control readback | read `control_object_b_id` as B | 1 |
| `sc-w-self` | session/operation wiring control | A updates and reads own `object_a_id` | 1 |
| `nc-w-deny` | negative security control | A attempts update of separate `negative_control_object_id` | 1 |
| `nc-w-readback` | negative-control effect readback | read `negative_control_object_id` as B | 1 |
| `baseline-w-digest` | baseline/ownership proof read | B reads `object_b_id`, records `baseline_value_digest` | 1 |
| `probe-w-t1` | trial 1 | A updates `object_b_id` (1) + independent B readback (1) | 2 |
| `probe-w-t2` | trial 2 after operator reset | A updates `object_b_id` (1) + independent B readback (1) | 2 |
| `retry-w-reserve` | reserved single retry | one failed technical exchange at most once | (1) |
| `cleanup-w-verify` | cleanup verification read | post-reset baseline digest confirmation | 1 |

Budget max 12. The reset between trials is the operator `reset_adapter_id`
fixture reload, never an unreviewed model write, and is not an HTTP exchange.
The reserved retry may go unused; using it for anything other than a failed
technical exchange is a contract violation.

**Verification and verdict.** A write response is only an acknowledgement.
`confirmed` requires the positive controls, the separate negative-control write
attempt leaving its control object unchanged, owner/permission proof, and an
independent read as B showing the exact marker persisted on B's object after
both repeats. `rejected` requires controls to work, both independent B readbacks
to retain the baseline value after A's attempted writes, and no other state
change. Inconclusive on unavailable control, unknown ownership, non-independent
readback, timeout/truncation, partial or inconsistent mutation, snapshot or
action mismatch, or failed cleanup.

**Cleanup.** Restore B's object using the operator reset adapter, verify its
baseline digest, confirm A's object and all unrelated fixture objects are
unchanged, and revoke sessions. Never use cleanup as an unreviewed write path.

**Contract examples.** Positive: the write returns, but only the independent
B readback observing the marker twice, with the negative-control object
untouched, confirms. Negative: writes are denied or ineffective and both
readbacks match baseline. Uncertain: update acknowledgement is received but
independent readback is truncated. Fixtures:
`evidence-owned-write-confirmed.synthetic.json`,
`evidence-owned-write-rejected.synthetic.json`,
`evidence-owned-write-inconclusive.synthetic.json`.

### R01-AUTH — authentication / authorization bypass

**Claim and scope.** Test one registered protected operation in exactly one
claim per run: (1) authentication bypass: an unauthenticated request obtains an
authenticated identity/effect; or (2) authorization bypass: authenticated role
A performs a named operation reserved to role B. Never conflate identity proof
with permission proof, and never test privilege acquisition outside the fixture.
One run tests one claim with its own controls; covering both claims requires two
separate bounded runs.

**Fixture and controls.** Pin `source_snapshot_id`, fixture/reset, target,
service, protected `endpoint_id`, candidate `operation_id`, anonymous identity
state, role A, role B, allowed/denied policy facts, and one harmless reversible
test object. The authorization negative control MUST NOT reuse the
candidate operation used by the probe: the operator pins a distinct,
known-B-reserved
`auth_control_operation_id` that is never the candidate and never verified by
this check, so no single request simultaneously expects denial and unauthorized
success. Positive controls: valid B session succeeds on the protected operation
(`oc-a-protected`, the only control exercising the real operation — it proves
availability for B); role A completes the A-allowed `sc-a-self` operation to
prove session wiring. Negative controls: `nc-a-anon` — an unauthenticated
request receives the plain denial expected of an auth-required operation;
`nc-a-different` — role A is denied the distinct B-reserved
`auth_control_operation_id`. The operator provisions isolated disposable
sessions; tests never guess credentials or reuse live tokens in artifacts.

**Allowed operation and limits.** One exact read or reversible marker operation
selected in the fixture. Session states are selected by opaque fixture ID
(`anonymous`, `role_a`, `role_b`), never by model-supplied token strings. Do not
test brute force, token prediction, account lockout, or production identity
providers. Because controls and the probe must be separate requests, two trials,
independent principal verification and cleanup exceed the common 8 exchanges, so
this family carries an explicit reviewed family budget of exactly 10 exchanges
(authentication-claim runs use exactly 9):

| Exchange | Class | ID / parameter | Claims | HTTP |
| --- | --- | --- | --- | --- |
| `oc-a-protected` | positive availability control | valid B session on `operation_id` | both | 1 |
| `sc-a-self` | session wiring + baseline of reversible test object | A-allowed operation | both | 1 |
| `nc-a-anon` | authentication negative control | anonymous state, expected plain denial | authn-only | 1 |
| `nc-a-different` | authorization negative control | role A on distinct `auth_control_operation_id` | authz-only | 1 |
| `sc-a-allowed` | authorization wiring control | role A completes A-allowed operation | authz-only | 1 |
| `probe-a-t1` | trial 1 unauthorized attempt | `anonymous` (authn) or `role_a` (authz) state on `operation_id` | both | 1 |
| `probe-a-t2` | trial 2 after operator reset | same unauthorized state and operation | both | 1 |
| `verify-a-s1` | independent session/principal state verification after trial 1 | benign A-allowed read of the reversible test object | both | 1 |
| `verify-a-s2` | independent session/principal state verification after trial 2 | same benign verification read | both | 1 |
| `retry-a-reserve` | reserved single retry | one failed technical exchange at most once | both | (1) |
| `cleanup-a-verify` | cleanup verification read | reversible test object baseline | both | 1 |

Budget max 10 for authorization-claim runs (all rows) and exactly 9 for
authentication-claim runs (`authz-only` rows are not executed). The reset is the
operator `reset_adapter_id`; session revocation is operator-side, never an
unreviewed model write.

**Verification and verdict.** Record the server-observed principal/role and
operation effect for every exchange, and bind the claim (`authentication` or
`authorization`) explicitly. `confirmed` requires the B positive control, the
applicable negative control observed denied on its distinct request
(`nc-a-different` for authorization, `nc-a-anon` for authentication), and both
unauthorized attempts to produce the protected synthetic data/effect with the
server-observed principal independently verified as unauthorized for the
operation. `rejected` requires controls to pass and both unauthorized attempts
to be denied with no protected data/effect. A token-shaped value or 2xx status
is not identity/effect proof, and a request whose success and denial are
expected at once proves nothing. Inconclusive on unknown principal, lost/rotated
session, failed controls, truncated output, technical error, binding mismatch,
or non-reversible side effects.

**Cleanup.** Reset the test object's baseline, revoke all fixture sessions, and
verify no privilege or account state changed. Record identity labels only, no
credentials, cookies, bearer values, or personal data.

**Contract examples.** Positive: the server independently identifies A and
records a B-only marker operation twice despite policy denying A, while the
distinct B-reserved control operation is denied for A and B's availability
control succeeds. Negative: the same calls are denied, B succeeds, and no effect
is present. Uncertain: the response resembles success but the principal cannot
be established. Fixtures:
`evidence-auth-confirmed.synthetic.json`,
`evidence-auth-rejected.synthetic.json`,
`evidence-auth-inconclusive.synthetic.json`.

### R01-REDIRECT — untrusted redirect destination

**Claim and scope.** Determine whether one registered redirect parameter causes
the application to emit an unauthorized destination to the operator's safe,
local sink. The check inspects the response `Location` value only; it MUST NOT
follow it or contact an external host. An application-approved local redirect
is not a finding.

**Fixture and controls.** Pin the source snapshot, target/service/endpoint IDs,
parameter ID, allowed destination ID, rejected destination ID, separate
negative-control destination ID, probe destination ID, local sink ID, and reset
fixture. The positive control is the operator-approved local destination
yielding its expected redirect. The negative security control uses a separate
disallowed destination that must be rejected or canonicalized to an approved
local route; it MUST NOT be the same request as the probe. The probe uses the
fixture's pinned probe destination whose canonical form is exactly the
operator-owned safe sink. One request never simultaneously expects both a denial
and an unauthorized redirect. The fixture maps destination IDs to pre-reviewed
literal test values, including an operator-owned safe sink; agent input cannot
supply URLs or hosts.

**Allowed operation and limits.** Read only status and raw `Location` header; do
not follow redirects, resolve DNS, load page content, contact the sink, or
contact any external host. Common per-exchange byte and timing limits apply. No
open proxy or external destination. The complete schedule — separate positive
control, negative control and probe requests, in-context allowed controls for
two trials and one cleanup counter read — totals 7 exchanges plus one reserved
retry, i.e. exactly 8 inside the common envelope:

| Exchange | Class | ID / parameter | HTTP |
| --- | --- | --- | --- |
| `oc-rd-allowed` | positive control | allowed local destination | 1 |
| `nc-rd-reject` | negative security control | rejected destination, expect denial/local canonical route | 1 |
| `probe-rd-t1a` | trial 1 in-context allowed control | allowed destination again with probe | 1 |
| `probe-rd-t1p` | trial 1 probe | probe destination, parse `Location`, never follow | 1 |
| `probe-rd-t2a` | trial 2 in-context allowed control after operator reset | allowed destination | 1 |
| `probe-rd-t2p` | trial 2 probe | probe destination | 1 |
| `retry-rd-reserve` | reserved single retry | one failed technical exchange at most once | (1) |
| `cleanup-rd-verify` | cleanup verification | fixture state cleared + local sink request counter read | 1 |

Budget max 8. The sink is never contacted by the check; the cleanup counter
proves zero sink requests via local counters, not by visiting the sink.

**Verification and verdict.** `confirmed` requires the allowed control to work,
the negative control (a request distinct from the probe) to be denied or
canonicalized to an approved local route, and both repeated probe responses to
contain a parsed `Location` that resolves exactly to the fixture's operator-owned
safe sink, after safe canonical parsing, while no redirect was followed.
`rejected` requires the allowed redirect control to work, the negative control
to be enforced, and both probes to be denied or mapped to an approved local
destination. Mere reflection in a body or query is not a redirect. Inconclusive
on malformed/truncated header, ambiguous normalization, failed control, binding
mismatch, error, or any evidence that a redirect was followed.

**Cleanup.** No destination is visited. Clear only the disposable fixture state
through the pinned `reset_adapter_id` (an operator-side adapter invocation, not
an HTTP exchange) and verify no network request reached the sink; record local
request counters.

**Contract examples.** Positive: the probe `Location` points to the pinned local
sink twice, the negative-control destination is denied or canonicalized on its
own request, and no redirect was followed. Negative: the negative control and
both probes are denied or locally canonicalized while the allowed control
succeeds. Uncertain: duplicate or malformed Location headers cannot be parsed
unambiguously. Fixtures:
`evidence-redirect-confirmed.synthetic.json`,
`evidence-redirect-rejected.synthetic.json`,
`evidence-redirect-inconclusive.synthetic.json`.

### R01-CODE — safe code-injection verification

**Claim and scope.** Determine whether a single allowlisted input reaches a
known evaluation/template boundary and is evaluated in a disposable, offline
container. This is not command injection, shell access, arbitrary code
execution, file access, network access, secret access, or a general payload
test. The only allowed input is an operator-defined inert marker expression
whose entire semantics are a fixed arithmetic operation over constants and a
unique synthetic marker.

**Fixture and controls.** Pin source snapshot, target/service/endpoint IDs,
fixture/reset IDs, parser/evaluation mode ID, exact harmless marker ID, and
expected constant result. Three controls are mandatory. The positive control
proves that the computed result is observable. The normal-output
control submits the literal non-evaluated marker and confirms normal output. The
negative security control uses the same input in a known non-evaluating/escaped
context and confirms it remains literal. The evaluation-observability positive
control runs the identical fixed inert arithmetic expression inside a separate
operator-allowlisted always-evaluating safe context (`oc-c-observable`) and must
return the expected marker-bound scalar there; this proves the computed result is
observable when evaluation truly happens, because a literal-only control cannot
distinguish evaluation from reflection. Literal reflection alone is never
sufficient. The expression grammar stays strictly fixed inert arithmetic over
constants plus the unique synthetic marker — no shell, no network, no secrets,
no calls, no file access. The disposable container has no network, no mounted
host paths, no secrets, no writable target filesystem, strict
CPU/memory/process/time/output limits, and is destroyed after each trial.
Operators audit the fixed expression grammar before enabling a fixture.

**Allowed operation and limits.** Input is an opaque, operator-owned marker ID
expanded by the fixture into a fixed inert expression; no free-form source,
payload, shell syntax, calls, loops, imports, file paths, or environment access.
Output is limited to the exact expected scalar and marker ID. Common per-exchange
byte/time limits apply, with stricter container resource limits set by the
operator. Each container evaluation invocation counts as one exchange. Controls
and probes are distinct invocations; the complete schedule totals exactly 6
counted invocations (5 plus one reserved retry), inside the common envelope:

| Exchange | Class | ID / parameter | HTTP |
| --- | --- | --- | --- |
| `oc-c-normal` | normal-output control | literal non-evaluated marker in normal context | 1 |
| `oc-c-observable` | evaluation-observability control | fixed expression in allowlisted safe evaluating context | 1 |
| `nc-c-literal` | negative security control | same input in non-evaluating/escaped context | 1 |
| `probe-c-t1` | trial 1 | marker at designated boundary in disposable container | 1 |
| `probe-c-t2` | trial 2 after the operator `reset_adapter_id` reset | same fixed marker ID | 1 |
| `retry-c-reserve` | reserved single retry | one failed technical exchange at most once | (1) |

Budget max 6. Cleanup verification (container destroyed/removed, snapshot
digests, zero network connections) uses operator runtime records, not HTTP
exchanges.

**Verification and verdict.** `confirmed` requires normal control success, the
evaluation-observability control returning the expected marker-bound scalar in
the safe evaluating context, the non-evaluation control remaining literal, and
both offline trials returning the exact computed scalar tied to the marker
through the designated evaluation boundary. Textual reflection alone never
confirms execution; a result distinguishable only by HTTP status or reflected
text is inconclusive. `rejected` requires controls to pass and the
evaluated-context trial to remain literal or be safely rejected on both repeats.
Inconclusive on marker reflection without evaluation, failed controls, container
escape/resource error, output truncation, unknown boundary, snapshot/binding
mismatch, or cleanup failure.

**Cleanup.** Destroy the disposable container and verify it is stopped/removed
using the operator runtime record. Verify target snapshot digests unchanged and
that no network connection, host mount, secret read, or filesystem mutation
occurred. Any unexpected side effect makes the run inconclusive and triggers
operator incident handling outside this specification.

**Contract examples.** Positive: the fixed expression returns its exact
constant-derived result twice in the offline disposable fixture, the
observability control shows the same scalar in the safe evaluating context, and
no arbitrary code is accepted. Negative: it remains literal/rejected while both
controls work. Uncertain: the marker is reflected but output is truncated before
evaluation can be distinguished. Fixtures:
`evidence-code-eval-confirmed.synthetic.json`,
`evidence-code-eval-rejected.synthetic.json`,
`evidence-code-eval-inconclusive.synthetic.json`.

## Catalog and reviewer rubric templates

The machine-readable files alongside this document are contract fixtures for
review by Лёха and later ground-truth adjudication. `catalog-template.yaml` and
`rubric-template.yaml` remain blank review templates; their `template_only`
status is intentional. `r01-family-specifications.synthetic.json` and the
per-family `evidence-*.synthetic.json` files are synthetic contract examples
that must match the schedules and criteria above; they are fixtures and spec
templates only, not a second production Evidence model, registered tool, or
benchmark ground truth. Do not infer severity from Semgrep ERROR/WARNING or
Juice Shop challenge stars. Record source links, pinned commit, exact
source/HTTP anchors, controls, and reviewer decision. CVSS stays `UNASSESSED`
until explicit metric inputs are independently justified and a deterministic
calculator supplies the score. Context Priority is a separate architecture
assessment with explicit known facts, contributions/reasons, and unknowns;
never combine it with CVSS.
Eligible fix remains false/unknown until a reviewer documents why the staged fix
verification contract can safely reproduce the original claim and restore the
fixture. Full benchmark truth requires separate L01/R02 review.

## Source references (primary, pinned where possible)

* OWASP WSTG v4.2, [WSTG-ATHZ-04 IDOR](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References/).
* OWASP WSTG v4.2, [WSTG-ATHZ-02 authorization schema bypass](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema/) and [WSTG-ATHN-04 authentication schema bypass](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/04-Authentication_Testing/04-Testing_for_Bypassing_Authentication_Schema/).
* OWASP WSTG v4.2, [WSTG-ATHN-09 weak password change/reset](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities/).
* OWASP WSTG v4.2, [WSTG-CLNT-04 client-side URL redirect](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect/). This is a category reference, not a claim that a server-side route has the same implementation.
* OWASP WSTG v4.2, [WSTG-INPV-11 code injection](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11-Testing_for_Code_Injection/). This spec deliberately narrows testing to inert offline evaluation.
* OWASP Juice Shop, [project](https://owasp.org/projects/juice-shop) and source at pinned target commit [`5658473cf8814459bf89000ce373b20ed0b4eb37`](https://github.com/juice-shop/juice-shop/tree/5658473cf8814459bf89000ce373b20ed0b4eb37). Relevant source anchors in that revision: `routes/basket.ts:18-30` (read ownership), `routes/basketItems.ts:37-49` (write/ownership binding), `routes/changePassword.ts:36-51` (reauthentication distinction), `routes/redirect.ts:13-19`, and `routes/userProfile.ts:57-65` (challenge/configuration-conditional evaluation). These are candidate source anchors only, not runtime proof or severity labels.
