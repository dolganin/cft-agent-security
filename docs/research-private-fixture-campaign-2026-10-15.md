# Private-fixture verification in the research campaign

## What was connected

The R05 campaign can now route a source-bound candidate into three closed,
operator-granted protocols:

| Grant | Fixed verification | Maximum campaign reservation |
|---|---|---:|
| `b05.own-read.v1` | B05 own-read with two independent B04 fixture generations | 238 HTTP exchanges |
| `b06.redirect.v1` | B06 redirect destination check with two independent generations | 38 HTTP exchanges |
| `b06.password-reauth.v1` | B06 password re-authentication check with two independent generations | 194 HTTP exchanges |

B05 write checks, ownership transfer and other B06 actions remain unsupported by
this bridge. A grant does not come from a model proposal or a target profile alone.
The operator must pass an explicit typed protocol grant. Missing grants, stale
source snapshots, insufficient HTTP budget, or insufficient wall-time leave the
candidate pending before fixture provisioning.

The bridge creates only the fixed registered `ActionProposal`, runs it through
the existing `Validator` and `Executor`, and accepts the verdict from typed
Evidence. It reads back the persisted execution and matching audit, binds both
the source verification and (for B06) fixture generation, and checks cleanup.
Fixture credentials and live handles remain inside the operator-owned Docker
workers; they are not included in model state. Readiness probes are capped at 16
per generation. The protocol wall-time grant bounds Docker operations, while
cleanup remains allowed after the execution deadline.

HTTP accounting reserves the full lifecycle before provisioning, including
preparation, controls, readiness and verification exchanges. The campaign summary
reports both reserved and observed exchanges; it charges the reservation to the
shared campaign quota. Fixed lifecycle HTTP caps remain enforced inside B04/B06.

## Real Docker integration acceptance

Acceptance was run against the pinned Juice Shop checkout at commit
`5658473cf8814459bf89000ce373b20ed0b4eb37` and the installed immutable images
specified by the existing B04/B06 operator profiles. The campaign runner used a
scripted research step so this verifies the real private fixture, canonical
approval, execution, Evidence, audit, accounting and cleanup path without calling
an LLM. It is an integration acceptance, not discovery-quality evidence or a
benchmark measurement.

| Protocol | Runtime verdict | HTTP reserved | HTTP observed | Cleanup |
|---|---|---:|---:|---|
| B05 own-read | confirmed | 238 | 135 | verified |
| B06 redirect | confirmed | 38 | 13 | verified |
| B06 password re-auth | confirmed | 194 | 118 | verified |

Each run has a matching persisted execution and audit, a campaign report linked
to the Evidence verdict, unchanged source, and a sealed file manifest. Separate
fail-closed checks confirm no fixture starts without an explicit grant or when
the full protocol reservation does not fit the remaining network budget. Docker
inventory was empty for both B04 and B06 fixture labels after acceptance.

Repository-wide verification on the preceding R09 integration revision was
**1307 passed, 24 skipped**. The profile-integrity hardening was then validated
by the separate opt-in private-fixture test (**3/3**). Re-run the repository-wide
suite on the final revision before merging.

The sealed outputs are in
`artifacts/research-fixture-campaign-2026-10-15-final5.zip` with a sibling
SHA-256 file. `tests/test_research_fixture_campaign.py` reproduces the campaign
integration against an operator-supplied pinned checkout. The test substitutes
only the model-driven research step; it does not mock the B05/B06 Docker
fixtures, Executor, audit, Evidence or cleanup.

Example:

```bash
CFT_RESEARCH_FIXTURE_ACCEPTANCE_CHECKOUT=artifacts/benchmark-target/juice-shop \
CFT_RESEARCH_FIXTURE_ACCEPTANCE_OUTPUT=artifacts/research-fixture-acceptance \
python -m pytest -q tests/test_research_fixture_campaign.py
```

This acceptance does not run the full SAST/research campaign, use Qwen, access
benchmark labels, establish Recall/Precision/FPR, measure reproducibility, or
evaluate MTTR. A positive result applies only to these three fixed protocols
against this pinned target and these operator fixtures.
