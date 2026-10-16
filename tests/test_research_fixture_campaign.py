"""Opt-in real Docker checks for the private-fixture research campaign bridge."""
import json
import os
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.mark.parametrize(("protocol", "profile_file", "family", "tool", "route_id"), [
    ("b05.own-read.v1", "targets/juice-b05-access-fixture.yaml", "access-control",
     "verify_access_control", "juice-basket-own-read"),
    ("b05.basket-insert.v1", "targets/juice-b05-access-fixture.yaml", "access-control",
     "verify_access_control", "juice-basket-insert-owner-check"),
    ("b05.review-owner.v1", "targets/juice-b05-access-fixture.yaml", "access-control",
     "verify_access_control", "juice-review-own-write"),
    ("b05.review-nosql.v1", "targets/juice-b05-access-fixture.yaml", "nosql-injection",
     "verify_access_control", "juice-review-nosql-selector"),
    ("b06.redirect.v1", "targets/juice-b06-verification.yaml", "open-redirect",
     "verify_redirect_destination", "b06-redirect"),
    ("b06.password-reauth.v1", "targets/juice-b06-verification.yaml", "authentication",
     "verify_auth_reauthentication", "b06-reauthentication"),
])
@pytest.mark.skipif(not os.getenv("CFT_RESEARCH_FIXTURE_ACCEPTANCE_CHECKOUT"),
                    reason="Set an immutable Juice Shop checkout to run actual private fixtures")
def test_private_fixture_through_campaign(tmp_path, monkeypatch, protocol, profile_file, family, tool, route_id):
    from app import research_campaign as module
    from discovery.service import ProjectDiscovery
    from executor.access_fixture import WORKER_IMAGE
    from pipeline.juice_source_detectors import detect_juice_source_candidates
    from sast.identity import normalize_finding
    from schemas.finding import Finding
    from schemas.research import ResearchFile, ResearchScope
    from schemas.research_agent import ResearchProgress
    from schemas.research_campaign import CampaignLimits
    from schemas.research_fixtures import ResearchFixtureGrant
    from schemas.target import TargetProfile
    from security.verification_binding import resolve_binding

    checkout = Path(os.environ["CFT_RESEARCH_FIXTURE_ACCEPTANCE_CHECKOUT"]).resolve(strict=True)
    profile = TargetProfile.from_yaml(profile_file, repository_path_override=checkout)
    route = next(item for item in profile.verification_routes if item.id == route_id)
    source_findings = []
    if protocol in {"b05.review-owner.v1", "b05.review-nosql.v1"}:
        from tools.repository_source import RepositorySource

        source = RepositorySource(ProjectDiscovery().discover(checkout), research_mode=True)
        expected_rule = ("juice.access-control.review-selector-without-owner"
                         if protocol == "b05.review-owner.v1"
                         else "juice.nosql-injection.request-selector")
        source_findings = [finding for finding in detect_juice_source_candidates(profile, source)
                           if finding.rule_id == expected_rule]
        finding, = source_findings
    else:
        selector = next(item for item in route.sources if item.file != route.registration.file)
        source = checkout / selector.file
        lines = source.read_text(encoding="utf-8").splitlines()
        matches = [n for n, line in enumerate(lines, 1) if selector.anchor in line]
        assert len(matches) == 1
        finding = normalize_finding(Finding(id="fixture-campaign-" + protocol, source="operator_acceptance",
            rule_id=family, title="Fixed source-bound fixture check",
            description="Integration acceptance only; not a discovery result", file=selector.file,
            line_start=matches[0], line_end=matches[0]), repository_root=checkout)
    binding = resolve_binding(profile, finding).binding
    assert binding is not None and binding.route_id == route.id
    scoped_sources = {name: ResearchFile(original_sha256=digest, visible_sha256=digest)
                      for name, digest in binding.source_files.items()}
    research_profile = TargetProfile(id="research-fixture-acceptance", environment="sandbox",
        repository_path=checkout, services={"juice": {"internal_port": 3000}})
    research_scope = ResearchScope(target_id=research_profile.id, session_id="research-" + "a" * 32,
        worker_image="sha256:" + "b" * 64, worker_sha256="c" * 64, source_files=scoped_sources,
        max_http_requests=256, wall_seconds=600)

    def scripted_research(*, finding, **_kwargs):
        return {"finding": finding, "research_progress": ResearchProgress(),
                "research_scope": research_scope, "status": "inconclusive",
                "stop_reason": "scripted_acceptance", "workflow_errors": []}, {
                "model_calls": 0, "actions": 0, "http_requests": 0,
                "cleanup_verified": True, "stop_reason": "scripted_acceptance"}

    monkeypatch.setattr(module, "run_research", scripted_research)
    monkeypatch.setattr(module, "review_source_claims", lambda **_kwargs: [])
    monkeypatch.setattr(module, "attach_source_review", lambda state, *_args: state)
    monkeypatch.setattr(module, "build_final_report", lambda state: SimpleNamespace(model_dump=lambda **_kwargs: {
        "finding_id": state["finding"].id, "finding": state["finding"].model_dump(mode="json"),
        "status": state.get("status", "inconclusive"), "workflow_errors": []}))

    persistent = os.getenv("CFT_RESEARCH_FIXTURE_ACCEPTANCE_OUTPUT")
    output = (Path(persistent).resolve() / protocol.replace(".", "-") if persistent else
              tmp_path / protocol.replace(".", "-"))
    grant = ResearchFixtureGrant(protocol=protocol, wall_seconds=300,
        max_http_requests={"b05.own-read.v1": 238, "b05.basket-insert.v1": 238,
                           "b05.review-owner.v1": 250, "b05.review-nosql.v1": 250,
                           "b06.redirect.v1": 38,
                           "b06.password-reauth.v1": 194}[protocol])
    from pipeline.research_verification import verify_bound_candidate
    rejected_grant = verify_bound_candidate(finding=finding, profiles=(profile,), scope=research_scope,
        repository=checkout, output=tmp_path / "no-private-grant", max_http_requests=256,
        worker_image=WORKER_IMAGE, remaining_wall_seconds=600)
    assert rejected_grant["status"] == "review_pending"
    assert not (tmp_path / "no-private-grant").exists()
    rejected_budget = verify_bound_candidate(finding=finding, profiles=(profile,), scope=research_scope,
        repository=checkout, output=tmp_path / "insufficient-private-budget", max_http_requests=grant.max_http_requests - 1,
        worker_image=WORKER_IMAGE, fixture_grants=(grant,), remaining_wall_seconds=600)
    assert rejected_budget["status"] == "review_pending"
    assert not (tmp_path / "insufficient-private-budget").exists()
    result = module.campaign(profile=research_profile, configuration={"worker_image": WORKER_IMAGE},
        client=None, output=output, sast=[finding] if not source_findings else [], limits=CampaignLimits(max_questions=1,
            max_model_calls=1, max_actions=2, wall_seconds=600, max_http_requests=256),
        verification_profiles=(profile,), verification_worker_image=WORKER_IMAGE,
        fixture_grants=(grant,), source_detector_findings=source_findings,
        verification_only=bool(source_findings))
    assert result["canonical_runtime_review_counts"]["confirmed"] + \
           result["canonical_runtime_review_counts"]["rejected"] == 1
    assert result["canonical_verification_http_requests_observed"] <= \
           result["canonical_verification_http_requests_reserved"]
    assert result["http_request_budget_used"] == result["canonical_verification_http_budget_charged"]
    assert result["canonical_verification_http_budget_charged"] <= result["canonical_verification_http_requests_reserved"]
    assert result["cleanup_verified"] and result["source_unchanged"]
    reports = json.loads((output / "reports.json").read_text())
    review = reports[0]["canonical_runtime_review"]
    assert review["executed"] is True and review["worker_cleanup_verified"] is True
    assert review["evidence"]["verdict"] == review["status"]
    assert review["report"]["status"] == review["status"]
    execution_dir = output / "preverification" / "checks" / "0"
    assert (execution_dir / "audit.jsonl").is_file()
    assert list((execution_dir / "execution").glob("*.json"))
    events = [json.loads(line) for line in (execution_dir / "audit.jsonl").read_text().splitlines()]
    assert len(events) == 1 and events[0]["evidence_ref"] == review["execution"]["evidence_ref"]
    lifecycle = list(execution_dir.rglob("lifecycle.jsonl"))
    assert lifecycle
    for path in lifecycle:
        records = [json.loads(line) for line in path.read_text().splitlines()]
        destroys = [row for row in records if row.get("phase") == "destroy"]
        assert destroys and all(row.get("cleanup_complete") is True for row in destroys)
    if persistent:
        (output / "acceptance.json").write_text(json.dumps({"protocol": protocol, "result": result,
            "scripted_research_model": True, "full_benchmark_measurement": False}, indent=2) + "\n")
        seal = {path.relative_to(output).as_posix(): sha256(path.read_bytes()).hexdigest()
                for path in sorted(output.rglob("*")) if path.is_file() and path.name != "seal.json"}
        (output / "seal.json").write_text(json.dumps(seal, indent=2) + "\n")


@pytest.mark.skipif(not os.getenv("CFT_RESEARCH_FIXTURE_ACCEPTANCE_CHECKOUT"),
                    reason="Opt-in pinned Juice Shop Docker fixture acceptance")
def test_all_registered_fixture_lifecycles_fit_one_campaign(tmp_path):
    """All real independent protocols share a campaign, never a model session."""
    from app.research_campaign import campaign
    from app.research_diagnostic_run import FIXTURE_GRANTS
    from executor.access_fixture import WORKER_IMAGE
    from sast.identity import normalize_finding
    from schemas.finding import Finding
    from schemas.research_campaign import CampaignLimits
    from schemas.target import TargetProfile

    checkout = Path(os.environ["CFT_RESEARCH_FIXTURE_ACCEPTANCE_CHECKOUT"]).resolve(strict=True)
    access = TargetProfile.from_yaml("targets/juice-b05-access-fixture.yaml", repository_path_override=checkout)
    auth = TargetProfile.from_yaml("targets/juice-b06-verification.yaml", repository_path_override=checkout)
    selections = ((access, "juice-basket-own-read"), (access, "juice-basket-insert-owner-check"),
                  (access, "juice-review-own-write"),
                  (access, "juice-review-nosql-selector"),
                  (auth, "b06-redirect"), (auth, "b06-reauthentication"))
    findings = []
    for profile, route_id in selections:
        route = next(r for r in profile.verification_routes if r.id == route_id)
        selector = next(s for s in route.sources if s.file != route.registration.file)
        lines = (checkout / selector.file).read_text().splitlines()
        line, = [n for n, text in enumerate(lines, 1) if selector.anchor in text]
        findings.append(normalize_finding(Finding(id="acceptance-" + route_id,
            source="operator_acceptance", rule_id=route.family, title="Fixed protocol acceptance",
            description="Operator-supplied test question, not a discovered vulnerability",
            file=selector.file, line_start=line, line_end=line), repository_root=checkout))
    persistent = os.getenv("CFT_RESEARCH_FIXTURE_ACCEPTANCE_OUTPUT")
    output = Path(persistent).resolve() / "combined-fixtures" if persistent else tmp_path / "combined"
    result = campaign(profile=TargetProfile(id="combined-acceptance", environment="sandbox",
        repository_path=checkout, services={"juice": {"internal_port": 3000}}),
        configuration={"worker_image": WORKER_IMAGE}, client=None, output=output,
        sast=findings, verification_profiles=(access, auth), verification_worker_image=WORKER_IMAGE,
        fixture_grants=FIXTURE_GRANTS,
        limits=CampaignLimits(max_questions=1, max_model_calls=1, max_actions=6,
                              wall_seconds=1200, max_http_requests=1024))
    reviews = json.loads((output / "canonical-runtime-reviews.json").read_text())
    assert len(reviews) == 6
    assert all(row["status"] == "confirmed" for row in reviews), reviews
    assert all(row["worker_cleanup_verified"] for row in reviews)
    assert result["canonical_verification_http_requests_reserved"] == 1208
    assert result["canonical_verification_http_requests_observed"] <= 1024
    assert result["canonical_verification_http_budget_charged"] == result["canonical_verification_http_requests_observed"]
    assert result["http_request_budget_used"] <= 1024
    assert all(row["request_accounting_complete"] for row in reviews)
    assert result["model_calls"] == 0
    assert result["source_unchanged"] and result["cleanup_verified"]
    seal = {p.relative_to(output).as_posix(): sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.rglob("*")) if p.is_file() and p.name != "seal.json"}
    (output / "seal.json").write_text(json.dumps(seal, indent=2) + "\n")
