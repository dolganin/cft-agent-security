# C04 delivery evidence

`results.json` records the actual positive SQL and unsuccessful redirect campaigns,
the source commit, immutable fix image and complete bundle/seal digests.

- `sql-live.zip`: complete fresh C02 -> C03 -> C04 FIXED bundle. Extract to a new
  directory and run `python3 -m app.repair --replay <directory>` from the repo.
- `sql-live-final.zip`: additional fresh successful run after transport hardening
  at commit `04cdd5d`; 70.351 seconds, one real model proposal, all C03 stages passed.
- `offline-replay.json`: two identical offline replay results for each SQL bundle
  and the complete local redirect bundle. No Docker or provider call is involved.
- `redirect-history/`: copied attempt metadata, actual bounded model requests,
  accepted responses/reviews, feedback and terminal history. It is deliberately
  not a complete C03 replay bundle and does not substitute for independent proof.
- Complete redirect bundle: local
  `artifacts/c04-redirect-live-2026-10-16-01.zip`; exact ZIP/seal SHA256 in
  `results.json`. It remains local because the required before/after source
  snapshots contain Juice Shop's seeded private-key fixture. Actual provider
  credentials were absent from both campaigns' artifacts.
- `pytest.txt`, `ruff-scoped.txt`, `ruff-full.txt`, `docker-boundary.txt`,
  `app-main.txt`: final validation command outputs. Full Ruff's unrelated existing
  findings are retained and were not fixed under C04.
- `delivery-seal.json`: integrity inventory of this delivery, independent of
  the original C04 and nested C03 seals.
- `transport-timeout-observation.md`: earlier exit-137 observation, the discovered
  process-group risk and the subsequent passing regressions/real Docker rerun.

Actual outcomes: SQL FIXED in one proposal; redirect first failed the required
native test gate, then the model repeated the patch and C04 stopped as
`duplicate_patch`. Both originals and owned-resource cleanup passed. Redirect
has no canonical AFTER rejection and no verified-fix claim. A file-level native
failure is observed; its cause is not established by this acceptance.

The first C04 run (`artifacts/c04-sql-live-2026-10-16-01`) failed authentication.
The separate C03 image smoke (`artifacts/c04-c03-image-check-2026-10-16-01`) checked
an archived C02 proposal. Neither is counted as a fresh successful C04 campaign.

Run tests with the intended deterministic graph configuration, rather than
inheriting `CFT_AGENT_MODE=llm` from an operator's local `.env`:

```bash
CFT_AGENT_MODE=stub \
CFT_C04_FAILURE_ARTIFACTS=artifacts/c04-redirect-live-2026-10-16-01 \
PYTHONDONTWRITEBYTECODE=1 python3 -m pytest -q -ra
```

The opt-in negative-bundle regression can be skipped on another machine without
the private operator bundle; all synthetic cycle/negative tests and the complete
SQL fixture replay remain available without Docker or provider credentials.

Final validation: 1587 passed, 24 skipped; C04-only 99 passed; real Docker
boundary 6 passed. Full Ruff still reports 7 pre-existing issues in unchanged
files; changed-file Ruff is clean. The known full-lint gate is not hidden.
