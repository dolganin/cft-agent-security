# C03 acceptance evidence — 15 October 2026

`results.json` records the actual SQL FIXED and redirect REGRESSION runs,
mandatory native test output, original integrity, cleanup and replay seal hashes.
All upstream tests remain mandatory by Roman's explicit decision. These are
operator reference patch qualifications, not real LLM patch-generation claims.

Extract `sql-runtime.zip` into a fresh directory and run:

```text
python -m app.independent_fix --replay <extracted-directory>
```

Replay executes neither Docker nor target code. The SQL ZIP contains the complete
sealed run. Redirect is deliberately published as a summary projection, not a
standalone replay bundle: its full B01 source includes Juice Shop's seeded RSA
private-key fixture. The original complete sealed run remains in the local ignored
`artifacts/c03/redirect-01` directory and can be replayed there. Its seal hash is
preserved in results; the summary does not pretend to retain that full seal.

`pytest.txt`, `ruff.txt` and `app-main.txt` record project checks. Opt-in and
platform-only skips are listed in the pytest output. Native target test skips
remain visible separately in results; no additional native exclusions are enabled.

C03 is not declared complete while the redirect reference fails required tests.


## Subsequent authorized security-contract acceptance

The user explicitly authorized separate protected expectations for the two
vulnerability-requiring redirect assertions, while preserving original tests and
failures. Current results are in protected-contract-results.json; both SQL and
redirect are FIXED with independent replay, source/HTTP checks and cleanup.
protected-contract-seal.json binds the new delivery files. Native failures remain
recorded and do not by themselves establish a security verdict.

sql-protected-contract-runtime.zip is the new portable complete SQL bundle.
The old results.json, sql-runtime.zip and redirect REGRESSION remain historical
and unchanged. New full redirect evidence remains in local ignored
artifacts/c03-redirect-protected-contract-02; its bound helper includes the
seeded private-key fixture and is not published in a source archive.
