from types import SimpleNamespace

import pytest

from agent.verification_routing import select_profile
from discovery.service import ProjectDiscovery
from schemas.target import TargetProfile


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


@pytest.mark.parametrize("rule", ["code-injection", "cft.node.dynamic-code-evaluation"])
def test_disabled_code_family_reaches_existing_operator_availability_guard(monkeypatch, rule):
    from app.pipeline_run import _unsupported_verification_reason

    monkeypatch.setattr("agent.verification_routing.resolve_binding", lambda p, f:
        SimpleNamespace(status="inconclusive", candidates=[]))
    finding = SimpleNamespace(rule_id=rule, file="routes/userProfile.ts")
    profile = SimpleNamespace(id="juice-b06-verification", b06_verification=object())
    selected, _ = select_profile(finding, [profile])
    assert selected is profile
    assert "unsupported in the pinned Docker" in _unsupported_verification_reason(profile, finding)
    finding.file = "routes/other.ts"
    assert select_profile(finding, [profile])[0] is None
    finding.file = "routes/userProfile.ts"
    assert select_profile(finding, [profile, profile])[0] is None


@pytest.mark.parametrize("name", ["juice-verification.yaml", "juice-b05-access-fixture.yaml",
                                  "juice-b06-verification.yaml"])
def test_discovery_preserves_operator_verification_configuration(tmp_path, name):
    (tmp_path / "package.json").write_text('{"dependencies":{"express":"4"}}')
    base = TargetProfile.from_yaml("targets/" + name, repository_path_override=tmp_path)
    discovery = ProjectDiscovery()
    result = discovery.build_profile(discovery.discover(tmp_path), base_profile=base)
    assert result.verification_routes == base.verification_routes
    assert result.access_fixture == base.access_fixture
    assert result.b06_verification == base.b06_verification
