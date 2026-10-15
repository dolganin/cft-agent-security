"""S02 source containment, portable identity and lossless deduplication."""
import itertools
import json
import sqlite3
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

from agent.verification import register_source_artifacts
from api.service import RunOrchestrator
from api.store import ApiStore
from app.pipeline_run import _resolve_findings
from discovery.scout import merge_scout_candidates, validate_scout_candidates
from reporting.builder import build_final_report
from sast.identity import deduplicate_findings, normalize_finding
from sast.normalizer import normalize_semgrep_payload, normalize_semgrep_result


@pytest.mark.parametrize(("rule", "family"), [
    ("juice.nosql-injection.request-selector", "nosql-injection"),
    ("nosql-injection", "nosql-injection"),
    ("juice.captcha.replayable-verification", "anti-automation"),
    ("juice.authorization.client-role-setter", "authorization"),
    ("juice.access-control.review-selector-without-owner", "access-control"),
    ("juice.file-validation.filename-normalization", "file-validation"),
    ("sql-injection", "sql-injection"),
])
def test_specific_source_families_do_not_collapse_into_neighboring_taxonomy(rule, family):
    from sast.identity import rule_family

    assert rule_family(rule) == family
from sast.repository import JsonFindingRepository
from schemas.discovery import ProjectDiscoveryResult
from schemas.finding import Finding
from schemas.report import FinalReport
from schemas.scout import CandidateFinding
from schemas.target import TargetProfile
from security.source_paths import normalize_source_path

FIXTURES = Path(__file__).resolve().parents[1] / "contracts/examples/s02/paths.json"


def raw(path="routes/search.ts", *, start=1, end=1, column=1, end_column=15):
    return {
        "check_id": "vendor.sequelize-injection", "path": path,
        "start": {"line": start, "col": column}, "end": {"line": end, "col": end_column},
        "extra": {"message": "Synthetic request-to-query observation", "severity": "WARNING"},
    }


def candidate(path="routes/search.ts", *, line=1, end=1, rule="sql-injection"):
    return CandidateFinding(
        rule_id=rule, title="Model observation", description="Independent model observation",
        file=path, line_start=line, line_end=end, provenance_paths=[path],
        rationale="Trace the source to the sink; runtime verification still required",
    )


def source(tmp_path):
    path = tmp_path / "routes/search.ts"
    path.parent.mkdir()
    path.write_text("query(req.query.q); query(req.body.q)\nother(req.body)\nlast()\n")
    return path


@pytest.mark.parametrize("case", json.loads(FIXTURES.read_text()))
def test_portable_path_fixtures_preserve_case_and_dotfiles(case):
    assert normalize_source_path(case["raw"], case.get("root")) == case["expected"]


@pytest.mark.parametrize("path", [
    "../secret", "src/../secret", "src\\..\\secret", "C:secret", "C:/foreign/file.ts",
    "/etc/passwd", "src/file.ts:stream", "", ".", "src/\x00file", "src/\nfile",
])
def test_unsafe_or_foreign_paths_are_rejected(tmp_path, path):
    with pytest.raises(ValueError):
        normalize_source_path(path, tmp_path)


def test_absolute_containment_is_component_based_and_keeps_case(tmp_path):
    assert normalize_source_path(str(tmp_path / "src/Case.ts"), tmp_path) == "src/Case.ts"
    assert normalize_source_path("src/Case.ts") != normalize_source_path("src/case.ts")
    with pytest.raises(ValueError):
        normalize_source_path(str(tmp_path) + "-other/src/Case.ts", tmp_path)
    with pytest.raises(ValueError):
        normalize_source_path(str(tmp_path / "src/Case.ts"))


@pytest.mark.parametrize("link_parent", [True, False])
def test_symlink_escape_and_in_repo_links_are_rejected(tmp_path, link_parent):
    inside = tmp_path / "inside"
    inside.mkdir()
    (inside / "file.ts").write_text("query(x)\n")
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.mkdir()
    (outside / "file.ts").write_text("external\n")
    for target in (inside, outside):
        link = tmp_path / ("internal" if target == inside else "external")
        try:
            link.symlink_to(target if link_parent else target / "file.ts", target_is_directory=link_parent)
        except OSError:
            pytest.skip("Symlink support is required")
        with pytest.raises(ValueError, match="Linked"):
            normalize_source_path(str(link / "file.ts") if link_parent else str(link), tmp_path)


def test_one_defect_from_sast_and_scout_preserves_both_origins(tmp_path):
    source(tmp_path)
    sast = normalize_semgrep_result(raw(), repository_root=tmp_path)
    merged, duplicates = merge_scout_candidates(
        [sast], [candidate(".\\routes\\search.ts")], repository_root=tmp_path,
        service_resolver=lambda _: "backend",
    )
    assert duplicates == 1 and len(merged) == 1
    finding = merged[0]
    assert finding.source == "semgrep" and finding.id == sast.id
    assert finding.provenance.anchor_status == "source_bound"
    assert finding.provenance.file_sha256 == sha256((tmp_path / finding.file).read_bytes()).hexdigest()
    assert {o.source for o in finding.provenance.observations} == {"semgrep", "model_scout"}
    assert any(o.rationale for o in finding.provenance.observations)
    assert sast.service is None and len(sast.provenance.observations) == 1


def test_path_spelling_has_stable_primary_id_and_fingerprint(tmp_path):
    path = source(tmp_path)
    values = [normalize_semgrep_result(raw(name), repository_root=tmp_path) for name in (
        "routes/search.ts", "./routes/search.ts", "routes\\search.ts", str(path),
    )]
    assert len({f.id for f in values}) == len({f.provenance.fingerprint for f in values}) == 1
    assert [f.provenance.observations[0].original_file for f in values][-1] == str(path)


def test_overlap_or_adjacent_ranges_are_not_duplicates(tmp_path):
    source(tmp_path)
    findings = [normalize_semgrep_result(raw(end=2), repository_root=tmp_path)]
    merged, duplicates = merge_scout_candidates(
        findings, [candidate(end=1), candidate(line=2, end=2)], repository_root=tmp_path,
    )
    assert duplicates == 0 and len(merged) == 3


def test_services_families_and_source_versions_are_distinct(tmp_path):
    path = source(tmp_path)
    first = normalize_semgrep_result(raw(), repository_root=tmp_path)
    other_service = normalize_finding(first.model_copy(update={"service": "other"}))
    other_family = normalize_finding(first.model_copy(update={"rule_id": "xss"}))
    path.write_text("changed source\n")
    other_version = normalize_semgrep_result(raw(), repository_root=tmp_path)
    merged, duplicates = deduplicate_findings([first, other_service, other_family, other_version])
    assert len(merged) == 4 and duplicates == 0 and len({f.id for f in merged}) == 4
    with pytest.raises(ValueError, match="digest changed"):
        normalize_finding(first, repository_root=tmp_path)


def test_columnless_scout_does_not_choose_between_two_sinks(tmp_path):
    source(tmp_path)
    sast = [normalize_semgrep_result(raw(column=col, end_column=col + 10), repository_root=tmp_path)
            for col in (1, 20)]
    outputs = []
    for order in itertools.permutations(sast):
        merged, duplicates = merge_scout_candidates(list(order), [candidate()], repository_root=tmp_path)
        assert len(merged) == 3 and duplicates == 0
        assert len({f.id for f in merged}) == 3
        outputs.append([f.model_dump() for f in merged])
    assert outputs[0] == outputs[1]


def test_dedup_is_lossless_and_idempotent(tmp_path):
    source(tmp_path)
    items = [normalize_semgrep_result(raw(p), repository_root=tmp_path)
             for p in ("routes/search.ts", ".\\routes\\search.ts")]
    first, duplicates = deduplicate_findings(items)
    again, repeated = deduplicate_findings(first)
    assert duplicates == 1 and repeated == 0
    assert first == again and len(first[0].provenance.observations) == 2


def test_unanchored_findings_are_not_guessed_duplicates():
    legacy = Finding(id="legacy", source="semgrep", rule_id="rule", title="T", description="D", file="a.py")
    first = normalize_finding(legacy)
    merged, count = deduplicate_findings([first, first])
    assert count == 0 and len(merged) == 2 and len({item.id for item in merged}) == 2


def test_missing_source_does_not_claim_cross_scanner_cause_equivalence():
    finding = normalize_semgrep_result(raw())
    merged, count = merge_scout_candidates([finding], [candidate()])
    assert count == 0 and len(merged) == 2
    assert all(item.provenance.anchor_status == "location_only" for item in merged)
    assert len({item.provenance.fingerprint for item in merged}) == 2


def test_payload_deduplicates_sast_and_preserves_all_spellings(tmp_path):
    source(tmp_path)
    findings = normalize_semgrep_payload({"results": [raw(), raw("routes\\search.ts")]}, repository_root=tmp_path)
    assert len(findings) == 1 and len(findings[0].provenance.observations) == 2


def test_colliding_ids_are_portable_across_path_spellings(tmp_path):
    source(tmp_path)
    outputs = [normalize_semgrep_payload({"results": [raw(path, column=1), raw(path, column=20)]}, repository_root=tmp_path)
               for path in ("routes/search.ts", "routes\\search.ts")]
    assert [f.id for f in outputs[0]] == [f.id for f in outputs[1]]
    assert len({f.id for f in outputs[0]}) == 2


def test_relative_root_still_checks_symlinks(tmp_path, monkeypatch):
    source(tmp_path)
    try:
        (tmp_path / "alias.ts").symlink_to(tmp_path / "routes/search.ts")
    except OSError:
        pytest.skip("Symlink support is required")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(ValueError, match="Linked"):
        normalize_source_path("alias.ts", ".")


def test_old_api_row_remains_readable_after_migration(tmp_path):
    store = ApiStore(tmp_path / "meta.db")
    profile = TargetProfile.from_yaml("targets/sberlab.yaml")
    store.upsert_project(profile_path=Path("targets/sberlab.yaml"), profile=profile)
    store.create_run(run_id="old-run", target_id=profile.id, agent_mode="stub", max_iterations=1, artifact_dir=tmp_path)
    old = Finding(id="old-id", source="semgrep", rule_id="rule", title="T", description="D", file="a.py")
    report = build_final_report({"finding": old})
    store.replace_results("old-run", reports=[(report, tmp_path / "old-report.json")])
    with sqlite3.connect(store.path) as connection:
        connection.execute("ALTER TABLE findings DROP COLUMN provenance_json")
    migrated = ApiStore(store.path)
    finding = migrated.get_finding("old-run", "old-id")
    assert finding.provenance is None and finding.finding_id == "old-id"


def test_trusted_docker_root_translation_is_explicit(tmp_path):
    source(tmp_path)
    finding = normalize_semgrep_result(raw("/src/routes/search.ts"), repository_root=tmp_path, scanner_root="/src")
    assert finding.file == "routes/search.ts"
    with pytest.raises(ValueError):
        normalize_semgrep_result(raw("/other/routes/search.ts"), repository_root=tmp_path, scanner_root="/src")


def test_legacy_import_is_copied_and_historical_alias_resolves(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    source(repo)
    original = tmp_path / "old.json"
    old = Finding(id="historical-id", source="semgrep", rule_id="sql-injection", title="T", description="D", file=".\\routes\\search.ts", line_start=1)
    serialized = json.dumps([old.model_dump()])
    original.write_text(serialized)
    output = _resolve_findings(existing_findings=str(original), target=repo, sast_config="unused", output_dir=tmp_path / "sast", service_resolver=lambda _: "backend")
    assert original.read_text() == serialized and output != original
    finding = JsonFindingRepository(output).get_finding("historical-id")
    assert finding.id == "historical-id" and finding.file == "routes/search.ts"
    assert finding.provenance.anchor_status == "source_bound"


def test_ambiguous_historical_id_refuses_arbitrary_match(tmp_path):
    source(tmp_path)
    findings = normalize_semgrep_payload({"results": [raw(), raw(column=20)]}, repository_root=tmp_path)
    file = tmp_path / "findings.json"
    file.write_text(json.dumps([f.model_dump() for f in findings]))
    with pytest.raises(ValueError, match="Ambiguous"):
        JsonFindingRepository(file).get_finding("vendor.sequelize-injection:routes/search.ts:1")


def test_provenance_reaches_report_and_public_api_without_host_path(tmp_path):
    path = source(tmp_path)
    finding = normalize_semgrep_result(raw(str(path)), repository_root=tmp_path)
    report = build_final_report({"finding": finding, "status": "inconclusive"})
    saved = tmp_path / "report.json"
    saved.write_text(report.model_dump_json())
    restored = FinalReport.model_validate_json(saved.read_text())
    assert restored.finding.provenance == finding.provenance
    reader = SimpleNamespace(_require_completed=lambda _: None, store=SimpleNamespace(report_path=lambda *_: saved))
    public = RunOrchestrator.get_report(reader, "r1", finding.id)
    assert all(str(tmp_path) not in value for value in public.finding.provenance.aliases)
    assert all(str(tmp_path) not in item.original_file and str(tmp_path) not in item.source_id
               for item in public.finding.provenance.observations)
    # Compare decoded values: JSON escapes Windows backslashes in its raw text.
    assert json.loads(saved.read_text())["finding"]["provenance"]["observations"][0]["original_file"] == str(path)


def test_api_store_migrates_old_table_and_preserves_public_provenance(tmp_path):
    db = tmp_path / "meta.db"
    store = ApiStore(db)
    # Simulate the previous schema, leaving existing tables/data intact.
    with sqlite3.connect(db) as connection:
        connection.execute("ALTER TABLE findings DROP COLUMN provenance_json")
    store = ApiStore(db)
    source(tmp_path)
    profile = TargetProfile.from_yaml("targets/sberlab.yaml")
    store.upsert_project(profile_path=Path("targets/sberlab.yaml"), profile=profile)
    store.create_run(run_id="r1", target_id=profile.id, agent_mode="stub", max_iterations=1, artifact_dir=tmp_path)
    finding = normalize_semgrep_result(raw(str(tmp_path / "routes/search.ts")), repository_root=tmp_path)
    report = build_final_report({"finding": finding})
    report_path = tmp_path / "report.json"
    report_path.write_text(report.model_dump_json())
    store.replace_results("r1", reports=[(report, report_path)])
    api_finding = store.get_finding("r1", finding.id)
    assert api_finding.provenance.fingerprint == finding.provenance.fingerprint
    assert str(tmp_path) not in api_finding.model_dump_json()
    store = ApiStore(db)
    assert store.get_finding("r1", finding.id).provenance == api_finding.provenance


def test_scout_and_artifact_registry_reject_symlink_inventory(tmp_path):
    source(tmp_path)
    try:
        (tmp_path / "alias.ts").symlink_to(tmp_path / "routes/search.ts")
    except OSError:
        pytest.skip("Symlink support is required")
    discovery = ProjectDiscoveryResult(repository_root=tmp_path, project_files=["alias.ts"])
    assert validate_scout_candidates([candidate("alias.ts")], discovery) == []
    profile = TargetProfile.from_yaml("targets/sberlab.yaml")
    linked = Finding(id="l", source="semgrep", rule_id="r", title="T", description="D", file="alias.ts")
    registered = register_source_artifacts(profile, [linked], tmp_path)
    assert registered.artifacts == profile.artifacts
