# Juice Shop source detector pass

`pipeline/juice_source_detectors.py` is a bounded, deterministic candidate pass
for the pinned Juice Shop source. The preferred campaign entry point is:

```python
findings = detector.scan(profile, source)
```

where `source` is the existing projected `RepositorySource` built from the
trusted discovery inventory. The detector does not open target paths, execute
target code, call benchmark evaluators, read challenge solutions, or assign a
severity/verdict. Every result is a canonical `Finding` with
`source="juice_source_detector"`, an exact one-line anchor and source-bound
provenance. Parent orchestration may import these findings under its distinct
`source_detector` origin.

The current small rule set covers source signals for request-owned record
queries/writes, path-selected baskets/cards, client-controlled wallet amounts,
coupon state, CAPTCHA answer disclosure/replay, forwarded-IP rate-limit keys,
and direct metrics-registry responses. These are unverified candidates; a
runtime protocol and Evidence are still required.

The bounded extension also detects an optional current-password condition before
a password update, a role setter that persists its role parameter, a request
body id used directly as a review selector, and filename null-byte normalization
performed after extension allowlisting. Their explicit rule IDs are
`juice.authentication.optional-current-password`,
`juice.authorization.client-role-setter`,
`juice.nosql-injection.request-selector`, and
`juice.file-validation.filename-normalization`.

The default projection remains authoritative. In particular, benchmark-only
annotation regions are hidden before detection. Some server route wiring is
therefore intentionally unavailable to this pass, including the hidden region
that contains CAPTCHA verification registration and adjacent request
validation. The detector does not reconstruct those lines from raw source or
from labels; the resulting proof gap belongs to the later bounded runtime
campaign.

The source pass also reports an inconsistent parsed-basket selector when the
ownership guard uses basketIds[0] but the persisted BasketId uses the last
parsed value. It accepts a same-selector counterpart or an explicit duplicate
BasketId rejection as a safe source shape. The rule is
juice.access-control.inconsistent-basket-selector and anchors the persisted
BasketId field. Review updates receive a separate
juice.access-control.review-selector-without-owner candidate when their
request-controlled selector has no owner predicate in the local selector
window; this is distinct from the scalar/operator selector candidate.

The final bounded producer extension adds separate Angular source-flow
candidates for request query text and product descriptions passed to
bypassSecurityTrustHtml. It also checks dynamic req.query.fields selection in
currentUser.ts, the negative-quantity path across basketItems.ts and the
BasketItem model, the generated Finale Product resource when active POST and
DELETE controls coexist with no active PUT authorization control, and a
Feedback UserId model field only when server.ts registers Feedback with an
unfiltered generated resource. Safe counterparts with HTML sanitization,
field allowlists, non-negative guards, active Product PUT authorization, or
Feedback UserId exclusion do not emit these candidates.

The corresponding rule IDs are
juice.xss.request-query-trusted-html,
juice.xss.product-description-trusted-html,
juice.sensitive-data.client-selected-user-fields,
juice.business-logic.negative-quantity,
juice.authorization.generated-product-put, and
juice.access-control.generated-feedback-user-id.

The existing `RepositorySource` continues to own exclusions and budgets:
tests/oracle/benchmark/codefix directories, symlinks, unsafe paths, binary or
oversize files, and the fixed source-file/byte limits. Tests cover a safe
counterpart, annotation/comment filtering, source binding and an optional
smoke scan of the pinned checkout.
