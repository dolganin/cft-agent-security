# C04 follow-up checks — 16 October 2026

This supplements the original sealed `docs/evidence/c04` delivery; it does not
rewrite historical acceptance results. There is no new provider or Docker repair
measurement in this follow-up because changes preserve runtime behavior.

`pytest.txt` records the complete project suite after lint corrections. The added
final-bundle regression is additionally covered by `focused-pytest.txt`, which
records all C04 tests: 97 passed, 3 skipped. Both real successful SQL bundles replay
offline with process execution and provider calls forbidden. The original run
and final transport-hardened run remain separate measurements.

Windows skips the two POSIX process-group tests. The complete private redirect
bundle is unavailable on this machine, so its opt-in replay test is skipped.
Its historical real unsuccessful run, bounded feedback, duplicate stop and partial
public readout remain under `docs/evidence/c04`; this follow-up does not claim a
fresh negative runtime acceptance or full replay of that partial readout.

`ruff.txt` and `ruff-core.txt` cover the whole repository with the installed rules
and explicit E4/E7/E9/F/I rules. Both pass. The frozen A04 scorecard is unchanged;
only its bootstrap-related E402 is exempted per file. `app-main.txt` records the
deterministic graph smoke. Every project test skip is listed in `pytest.txt`.

C04 remains bounded to real C02 proposals and independent C03 verification.
No original target changes, automatic merges, new protected-test exceptions or
C05 measurement claims are introduced.
