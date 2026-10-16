"""Production detector lines, not operator header-only acceptance questions."""
from pathlib import Path

import pytest

from discovery.service import ProjectDiscovery
from pipeline.juice_source_detectors import detect_juice_source_candidates
from schemas.target import TargetProfile
from security.verification_binding import resolve_binding
from tools.repository_source import RepositorySource

ROOT = Path(__file__).resolve().parents[1]
TARGET = ROOT / "artifacts/benchmark-target/juice-shop"


@pytest.mark.skipif(not TARGET.exists(), reason="Pinned Juice Shop source checkout required")
@pytest.mark.parametrize(("rule", "route_id"), [
    ("juice.access-control.path-selected-record", "juice-basket-own-read"),
    ("juice.access-control.inconsistent-basket-selector", "juice-basket-insert-owner-check"),
    ("juice.access-control.review-selector-without-owner", "juice-review-own-write"),
    ("juice.nosql-injection.request-selector", "juice-review-nosql-selector"),
    ("juice.sensitive-data.client-selected-user-fields", "juice-user-private-fields"),
    ("juice.access-control.generated-feedback-user-id", "juice-feedback-owner"),
])
def test_detected_source_candidate_binds_to_its_exact_operator_route(rule, route_id):
    profile = TargetProfile.from_yaml(ROOT / "targets/juice-b05-access-fixture.yaml",
                                     repository_path_override=TARGET)
    source = RepositorySource(ProjectDiscovery().discover(TARGET), research_mode=True)
    candidates = detect_juice_source_candidates(profile, source)
    route = next(r for r in profile.verification_routes if r.id == route_id)
    finding, = [f for f in candidates if f.rule_id == rule
                and any(s.file == f.file for s in route.sources)]
    resolution = resolve_binding(profile, finding)
    assert resolution.status == "bound", resolution
    assert resolution.binding.route_id == route_id
    assert resolution.binding.finding_id == finding.id
    assert resolution.binding.line_start == finding.line_start
    assert resolution.binding.anchor_sha256 == finding.provenance.anchor_sha256
