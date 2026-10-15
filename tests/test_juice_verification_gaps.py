import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluation.juice_verification_gaps import audit, classify


def case(**updates):
    return SimpleNamespace(**{"confirmation_supported": False, "detected": True,
        "matched_observation_ids": ["f"], "family": "access-control", **updates})


@pytest.mark.parametrize(("value", "handoffs", "reviews", "profiles", "expected"), [
    (case(confirmation_supported=True), {}, {}, [], "runtime_confirmed"),
    (case(detected=False), {}, {}, [], "not_detected"),
    (case(family="weak-cryptography"), {}, {}, [], "source_property_review_required"),
    (case(), {}, {"f": {"executed": None}}, [], "execution_or_cleanup_failure"),
    (case(), {}, {"f": {"executed": True}}, [], "executed_without_sufficient_proof"),
    (case(), {"f": {"binding": {"route_id": "x"}}}, {}, [], "bound_protocol_not_executed"),
    (case(), {}, {}, [{"verification_routes": [{"family": "access-control",
        "sources": [{"file": "routes/x.ts"}]}]}], "source_binding_unavailable"),
    (case(), {}, {}, [], "no_registered_runtime_protocol"),
])
def test_readiness_is_not_a_security_verdict(value, handoffs, reviews, profiles, expected):
    findings = {"f": {"id": "f", "file": "routes/x.ts"}}
    assert classify(value, findings, handoffs, reviews, profiles) == expected


RUN = Path(__file__).resolve().parents[1] / "artifacts/juice-fixed-source-acceptance-retry-3-2026-10-15"


@pytest.mark.skipif(not RUN.exists(), reason="Saved sealed fixed verification run required")
def test_gap_audit_replays_evidence_and_preserves_input_bytes(tmp_path):
    before = {p.relative_to(RUN): p.read_bytes() for p in RUN.rglob("*") if p.is_file()}
    first = audit(RUN, tmp_path / "first")
    second = audit(RUN, tmp_path / "second")
    assert first == second
    assert (first["positive_cases"], first["runtime_confirmed"], first["unconfirmed"]) == (27, 7, 20)
    assert first["changes_verdicts"] is False and first["is_evidence"] is False
    assert len(first["cases"]) == 27 and all(row["candidate_observations"] for row in first["cases"])
    assert sum(first["blockers"].values()) == 27
    assert {p.relative_to(RUN): p.read_bytes() for p in RUN.rglob("*") if p.is_file()} == before
    persisted = json.loads((tmp_path / "first/gaps.json").read_text())
    assert persisted == first
    with pytest.raises(ValueError, match="fresh output"):
        audit(RUN, tmp_path / "first")


def test_gap_audit_rejects_tampered_input_before_scoring(tmp_path):
    (tmp_path / "seal.json").write_text(json.dumps({"result.json": "a" * 64}))
    (tmp_path / "result.json").write_text("{}")
    with pytest.raises(ValueError, match="digest mismatch"):
        audit(tmp_path, tmp_path.parent / (tmp_path.name + "-output"))
