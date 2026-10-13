# B02 — reproducible Semgrep SAST

`sast/rules/juice-shop-v2/profile.yaml` selects the frozen A06-v5 Semgrep CE rules
plus the seven local rules in `sast/rules/juice-shop-v2/local-rules.yaml`. The
profile pins Semgrep `1.174.0`, the Juice Shop v20.2.0 commit, both rule-file
SHA-256 digests, and the scan exclusions. Profile loading fails on a missing or
changed config. The old `docs/demo/semgrep.yaml` remains a separate demo config.

Select the profile explicitly for a pipeline run:

```bash
python -m app.pipeline_run --sast-config sast/rules/juice-shop-v2/profile.yaml ...
```

The pipeline uses the existing `run_semgrep_scan()` and stores `semgrep.json`,
normalized `findings.json`, `summary.json`, and `manifest.json` in its SAST output
directory. Raw Semgrep errors and stderr are retained. A target-commit or version
mismatch makes the run technically invalid. A source alert stays an unverified
candidate; it does not set `confirmed`, CVSS, or an exploitation verdict.

| Rule ID | Family | Signal |
|---|---|---|
| `cft.node.weak-hash-md5-sha1` | weak-cryptography | MD5/SHA-1 application digest |
| `cft.node.dynamic-code-evaluation` | code-evaluation | `eval` / dynamic Function |
| `cft.node.nosql-where-interpolation` | nosql-injection | dynamic Mongo `$where` query |
| `cft.node.ssrf-request-url` | ssrf | dynamic outbound request URL |
| `cft.node.xml-external-entities` | xml-external-entities | XML entity/DTD flags |
| `cft.node.archive-path-write` | path-traversal | archive path to filesystem write |
| `cft.node.open-redirect-user-url` | open-redirect | dynamic redirect destination |

All local rules are code signals. Configuration rules and dependency/SCA alerts
are not part of this profile; dependency risk must not be represented as a
confirmed runtime CVE. Semgrep severity is not CVSS.

The DEV/original comparison can be regenerated against the pinned checkout:

```bash
python -m scripts.b02_sast_development --target /path/to/juice-shop-v20.2.0
```

It records A06-before, B02 agent-profile, and B02 baseline-profile raw JSON,
scorecards, scanner stderr and a manifest under `artifacts/b02-sast-development-*`.
Only the A01/A05 development/original slice enters scoring. Current report:
`artifacts/b02-sast-development-2026-10-13-final/report.md`. Semgrep parser diagnostics
are retained, including intermittent per-rule timeouts; those diagnostics may
vary across repeated scans even when alerts and scanned-file sets are identical.
