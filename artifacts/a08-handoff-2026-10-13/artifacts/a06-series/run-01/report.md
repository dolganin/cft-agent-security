# A06 scanner baseline acceptance

COMPLETED_WITH_LIMITATIONS

Scanner detections are not independently verified findings.
A07 repeated series and primary benchmark metrics have not been run.

Counts: {"sast": 94, "dast": 409, "union": 503}

SAST warning diagnostics: 56
All diagnostic details are retained in manifest and sast/coverage.json.
Coverage gaps do not remove cases from the benchmark denominator.

Role: anonymous. No authenticated or multi-user workflow coverage.
SAST uses the full frozen language/security pack, including default ignores.
ZAP uses bounded traditional/AJAX spiders and active/passive rules.
Time-limited crawl/active scan is partial coverage; see dast/coverage.json.
Only original samples scanned; patched/synthetic controls were not executed.

## Technical errors

