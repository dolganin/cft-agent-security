# C05 — measured fix slice

This directory is an explicitly partial public projection of the full series.
report.md / measurement.json / slots.csv contain all six planned slots, including
any unsuccessful outcomes. native-and-gates.json preserves native failures and
stage gates; three SQL ZIPs are complete individual C04 runs. Redirect source
snapshots contain Juice Shop seeded private-key material and stay only in the
complete local ZIP recorded in delivery.json. Do not pass this projection to the
full-series replay CLI or claim that it substitutes for that package.

The complete package preserves the full frozen B09 separately from the fix slice.
Extract it to a fresh directory, restore its b09-full-search.zip to the absent
repository artifacts/handoffs/b09-single-2026-10-15.zip after digest comparison,
and run python -m app.repair_measurement --replay --output <extracted-series>.
No model, Docker or target checkout is needed for replay. Repository C01/C03
protected evaluator assets and compatible Python dependencies remain required.

Historical C04 unsuccessful observations are retained separately and are not
pooled into this C05 series. Original sealed C01–C04 deliveries are unchanged.
The first pre-measurement setup failure made zero provider calls; its directory
is preserved locally and identified explicitly. No measured slot was replaced.
Latency means laboratory confirmed-input to independently verified patch;
production/historical MTTR remain N/A. All test skips are listed in pytest.txt.
