from types import SimpleNamespace

import pytest

from agent.verification_routing import select_profile


def test_unique_profile(monkeypatch):
    profiles = [SimpleNamespace(id="a"), SimpleNamespace(id="b")]
    monkeypatch.setattr("agent.verification_routing.resolve_binding", lambda p, f:
        SimpleNamespace(status="bound" if p.id == "b" else "inconclusive", candidates=[]))
    selected, reason = select_profile(SimpleNamespace(), profiles)
    assert selected.id == "b"
    assert "Unique" in reason


@pytest.mark.parametrize("ambiguous", [True, False])
def test_ambiguous_profiles_fail_closed(monkeypatch, ambiguous):
    profiles = [SimpleNamespace(id="a"), SimpleNamespace(id="b")]
    monkeypatch.setattr("agent.verification_routing.resolve_binding", lambda p, f:
        SimpleNamespace(status="inconclusive" if ambiguous else "bound",
                        candidates=["route1", "route2"], reason="ambiguous"))
    selected, _ = select_profile(SimpleNamespace(), profiles)
    assert selected is None


def test_unregistered_finding_is_not_given_a_fallback_profile(monkeypatch):
    monkeypatch.setattr("agent.verification_routing.resolve_binding", lambda p, f:
        SimpleNamespace(status="inconclusive", candidates=[]))
    finding = SimpleNamespace(rule_id="cft.other", file="routes/other.ts")
    selected, _ = select_profile(finding, [SimpleNamespace(b06_verification=None)])
    assert selected is None
