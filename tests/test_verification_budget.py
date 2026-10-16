import pytest

from pipeline.verification_budget import b05_http_ledger, verification_http_charge


def complete():
    return {"requests_reserved": 250, "requests_observed": 156,
        "request_accounting_complete": True, "origin": "canonical_fixed_B05_verifier",
        "executed": True, "worker_cleanup_verified": True, "status": "confirmed"}


def test_complete_fixed_ledger_releases_only_unused_reservation():
    assert verification_http_charge(complete()) == 156
    assert verification_http_charge({**complete(), "status": "rejected"}) == 156


@pytest.mark.parametrize("change", [
    {"executed": None}, {"executed": False}, {"worker_cleanup_verified": False},
    {"status": "inconclusive"}, {"origin": "model"},
    {"request_accounting_complete": False}, {"request_accounting_complete": 1},
])
def test_unknown_or_incomplete_work_keeps_full_reservation(change):
    assert verification_http_charge({**complete(), **change}) == 250


@pytest.mark.parametrize("observed", [-1, 0, 251, True, "156", None])
def test_malformed_complete_ledger_cannot_release_capacity(observed):
    with pytest.raises(ValueError):
        verification_http_charge({**complete(), "requests_observed": observed})


def test_archived_ledgers_without_completeness_keep_historical_charge():
    row = complete()
    del row["request_accounting_complete"]
    assert verification_http_charge(row) == 250
    assert verification_http_charge({"requests_reserved": 0}) == 0


def test_b05_ledger_includes_both_readiness_phases_and_counts_provision_delta_once():
    rows = []
    for generation in ("a", "b"):
        rows.extend([
            {"phase": "prepare", "generation": generation},
            {"phase": "readiness", "generation": generation, "readiness_probe_attempts": 1},
            {"phase": "prepare", "generation": generation, "context": {"status": "ready", "http_exchanges": 39}},
            {"phase": "control", "generation": generation, "context": {"status": "ready", "http_exchanges": 25}},
            {"phase": "b05-provision", "generation": generation, "context": {"status": "ready", "http_exchanges": 28}},
        ])
    assert b05_http_ledger(rows, 26) == (162, True)
    assert b05_http_ledger([r for r in rows if r["phase"] != "readiness"], 26) == (160, False)
    assert b05_http_ledger(rows + [rows[1]], 26) == (163, False)
    with pytest.raises(ValueError):
        b05_http_ledger(rows + [{"phase": "readiness", "generation": "a", "readiness_probe_attempts": -1}], 26)
    backwards = [*rows[:-1], {**rows[-1], "context": {"status": "ready", "http_exchanges": 24}}]
    with pytest.raises(ValueError, match="backwards"):
        b05_http_ledger(backwards, 26)
