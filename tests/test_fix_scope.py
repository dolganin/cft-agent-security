import json
import zipfile
from pathlib import Path

import pytest

from fix_verification import scope
from fix_verification.scope_source import expressions
from fix_verification.workspace import digest
from schemas.fix import ProposedPatch


def test_published_baseline_replays_two_families_without_claiming_fixes():
    report = scope.assess_scope()
    assert (report.eligible, report.failed, report.ineligible) == (2, 0, 6)
    assert report.fixes_attempted == 0 and not report.security_verified
    assert all(e.evidence_refs for e in report.entries if e.status == "eligible")


def test_protected_evaluator_mutation_fails_closed(tmp_path, monkeypatch):
    root = tmp_path
    registry = root / "contracts/c01"
    registry.mkdir(parents=True)
    (registry / "evaluator.cjs").write_text("tampered")
    (registry / "lock.json").write_text(json.dumps({"files": {
        "contracts/c01/evaluator.cjs": "0" * 64}}))
    monkeypatch.setattr(scope, "ROOT", root)
    monkeypatch.setattr(scope, "SCOPE", registry)
    with pytest.raises(ValueError, match="digest mismatch"):
        scope.load_scope()


@pytest.mark.parametrize("file", ["test/server/search.unit.test.ts", "../routes/search.ts",
    "evaluation/ground_truth.yaml", "contracts/c01/evaluator.cjs", "package.json",
    "routes/login.ts", "lib/insecurity.ts"])
def test_sql_patch_cannot_change_evaluator_baseline_or_other_application_file(tmp_path, file):
    patch = ProposedPatch(finding_id="x", rationale="scope test",
        unified_diff=f"--- a/{file}\n+++ b/{file}\n@@ -1 +1 @@\n-old\n+new\n")
    with pytest.raises(ValueError, match="explicitly allowed"):
        scope.validate_candidate(family_id="sql-search", proposal=patch,
                                 source_root=tmp_path, source_sha256="0" * 64)


def test_patch_accepts_exact_existing_file_and_rejects_stale_snapshot(tmp_path):
    file = tmp_path / "routes/search.ts"
    file.parent.mkdir()
    file.write_text("old\n")
    patch = ProposedPatch(finding_id="x", rationale="scope test",
        unified_diff="--- a/routes/search.ts\n+++ b/routes/search.ts\n@@ -1 +1 @@\n-old\n+new\n")
    expected = digest(file.read_bytes())
    assert "+new" in scope.validate_candidate(family_id="sql-search", proposal=patch,
        source_root=tmp_path, source_sha256=expected)
    file.write_text("changed\n")
    with pytest.raises(ValueError, match="snapshot mismatch"):
        scope.validate_candidate(family_id="sql-search", proposal=patch,
            source_root=tmp_path, source_sha256=expected)


@pytest.mark.parametrize("name", ["../outside", "/absolute", "C:/outside", "a\\outside"])
def test_baseline_archive_cannot_escape_extraction(tmp_path, name):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr(name, b"x")
        z.writestr("MANIFEST-SHA256.json", json.dumps({name: digest(b"x")}))
    with pytest.raises(ValueError, match="Unsafe baseline|membership mismatch"):
        scope._verified_archive(archive, tmp_path / "destination")


def test_baseline_archive_tampering_is_not_confirmation(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as z:
        z.writestr("run/report.json", "tampered")
        z.writestr("MANIFEST-SHA256.json", json.dumps({"run/report.json": "0"*64}))
    with pytest.raises(ValueError, match="digest mismatch"):
        scope._verified_archive(archive, tmp_path / "destination")


def test_missing_persisted_evidence_is_counted_failed(monkeypatch):
    monkeypatch.setattr(scope, "observations_from_artifacts", lambda root: [])
    report = scope.assess_scope()
    assert (report.eligible, report.failed, report.ineligible) == (0, 2, 6)
    assert all(e.status != "eligible" for e in report.entries)


def test_ast_extraction_uses_unique_query_and_no_line_number(tmp_path):
    (tmp_path / "routes").mkdir()
    (tmp_path / "lib").mkdir()
    search = tmp_path / "routes/search.ts"
    search.write_text("// inserted line\nmodels.sequelize.query(`SELECT ${criteria}`).then(x=>x)\n")
    (tmp_path / "lib/insecurity.ts").write_text(
        "export const redirectAllowlist=new Set(['https://allowed.invalid']);\n"
        "export const isRedirectAllowed=(url: string)=>redirectAllowlist.has(url);\n")
    extracted = expressions(tmp_path)
    assert extracted["sql"] == "models.sequelize.query(`SELECT ${criteria}`)"
    assert ": string" not in extracted["redirect"]
    search.write_text(search.read_text() + "models.sequelize.query(`${criteria}`)\n")
    with pytest.raises(ValueError, match="ambiguous"):
        expressions(tmp_path)


def test_published_qualification_detects_original_cause_and_shortcuts():
    path = Path(__file__).resolve().parents[1] / "docs/evidence/c01/qualification.json"
    result = json.loads(path.read_text())
    assert result["qualified"] and result["cleanup_complete"] and result["original_unchanged"]
    assert not result["security_verified"]
    variants = {v["variant"]: v for v in result["variants"]}
    assert variants["reference-parameterized-exact"]["exit_code"] == 0
    assert all(variants[name]["exit_code"] == 1
               for name in ("original", "deny-all", "recorded-probe-only"))
