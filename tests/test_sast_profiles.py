from __future__ import annotations

import shutil
import hashlib
import json
from pathlib import Path

import pytest
import yaml

from evaluation.b02_baseline_adapter import observations_semgrep_b02
from sast.identity import rule_family
from sast.profiles import load_scan_profile
from sast.semgrep_runner import SemgrepError, run_semgrep_scan
from sast.normalizer import normalize_semgrep_result
from sast.profiles import classify_diagnostics, validate_target_snapshot

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / "sast/rules/juice-shop-v2/profile.yaml"
RULES = ROOT / "sast/rules/juice-shop-v2/local-rules.yaml"


def test_b02_profile_locks_frozen_base_and_local_rules() -> None:
    profile = load_scan_profile(PROFILE)

    assert profile["id"] == "juice-shop-v2"
    assert profile["semgrep_version"] == "1.174.0"
    assert profile["config_files"] == [
        str((ROOT / "benchmarks/baselines-a06-v5/semgrep-rules.yaml").resolve()),
        str(RULES.resolve()),
    ]
    assert profile["config_sha256"]["../../../benchmarks/baselines-a06-v5/semgrep-rules.yaml"] == (
        "a1d0c4640085395aa39d09389d9cff7e673184daaa713b3f49f02806f0272dc6"
    )
    assert profile["profile_sha256"] == "93303d3677dcd41c773d7ddaa59e1215d1659bb8ab70d272ff454d06b24f4ae6"


def test_b02_family_ids_normalize_without_changing_old_ids() -> None:
    cases = {
        "cft.node.weak-hash-md5-sha1": "weak-cryptography",
        "cft.node.dynamic-code-evaluation": "code-evaluation",
        "cft.node.nosql-where-interpolation": "nosql-injection",
        "cft.node.ssrf-request-url": "ssrf",
        "cft.node.xml-external-entities": "xml-external-entities",
        "cft.node.archive-path-write": "path-traversal",
        "cft.node.open-redirect-user-url": "open-redirect",
        "javascript.express.security.audit.express-open-redirect": "open-redirect",
    }
    assert {rule: rule_family(rule) for rule in cases} == cases


def test_semgrep_observations_classify_local_rules_and_never_confirm() -> None:
    raw = {
        "results": [{
            "check_id": "cft.node.dynamic-code-evaluation",
            "path": "routes/example.ts",
            "start": {"line": 4}, "end": {"line": 4},
            "extra": {"metadata": {"cwe": ["CWE-95"], "signal": "code"}},
        }],
    }

    observation = observations_semgrep_b02(raw)[0]
    assert observation["family"] == "code-evaluation"
    assert observation["signal_type"] == "code"
    assert observation["cwe"] == ["CWE-95"]
    assert observation["verification"] == "not_run"
    assert observation["evidence_backed"] is False


def test_profile_rejects_changed_config_digest(tmp_path: Path, monkeypatch) -> None:
    base = tmp_path / "base.yaml"
    local = tmp_path / "local-rules.yaml"
    base.write_text("rules: []\n", encoding="utf-8")
    local.write_text("rules: []\n", encoding="utf-8")
    value = {
        "schema": "cft.semgrep-profile.v1", "id": "juice-shop-v2", "version": 1,
        "semgrep_version": "1.174.0", "target_commit": "a" * 40,
        "config_files": ["base.yaml", "local-rules.yaml"],
        "config_sha256": {"base.yaml": "0" * 64, "local-rules.yaml": "0" * 64},
        "exclude": [".venv", "node_modules", "dist", "build"],
        "signal_types": {"code": "implemented", "configuration": "unsupported_by_local_ruleset",
                         "dependency": "unsupported_no_sca"},
    }
    profile_path = tmp_path / "profile.yaml"
    text = yaml.safe_dump(value)
    profile_path.write_text(text, encoding="utf-8")
    (tmp_path / "profile.lock.json").write_text(json.dumps({
        "schema": "cft.semgrep-profile-lock.v1",
        "profile_sha256": hashlib.sha256(text.encode()).hexdigest(),
    }), encoding="utf-8")
    monkeypatch.setattr("sast.profiles.ROOT", tmp_path)
    with pytest.raises(ValueError, match="config digest mismatch"):
        load_scan_profile(profile_path)


def test_normalizer_preserves_code_and_configuration_metadata() -> None:
    code = normalize_semgrep_result({
        "check_id": "cft.node.dynamic-code-evaluation", "path": "routes/example.ts",
        "start": {"line": 7, "col": 1}, "end": {"line": 7, "col": 10},
        "extra": {"message": "dynamic code", "severity": "ERROR",
                   "metadata": {"cwe": ["CWE-95"], "signal": "code"}},
    })
    config = normalize_semgrep_result({
        "check_id": "yaml.github-actions.security.test", "path": ".github/workflows/ci.yml",
        "start": {"line": 2, "col": 1}, "end": {"line": 2, "col": 10},
        "extra": {"message": "workflow setting", "severity": "WARNING",
                   "metadata": {"cwe": ["CWE-123"]}},
    })

    assert code.provenance.observations[0].signal_type == "code"
    assert code.provenance.observations[0].cwe == ["CWE-95"]
    assert config.provenance.observations[0].signal_type == "configuration"


def test_target_snapshot_rejects_dirty_and_untracked_files(tmp_path: Path) -> None:
    import subprocess

    target = tmp_path / "target"
    target.mkdir()
    subprocess.run(["git", "init", "-q", str(target)], check=True)
    subprocess.run(["git", "-C", str(target), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(target), "config", "user.name", "Test"], check=True)
    (target / "app.js").write_text("const safe = true\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(target), "add", "app.js"], check=True)
    subprocess.run(["git", "-C", str(target), "commit", "-qm", "fixture"], check=True)
    commit = subprocess.run(
        ["git", "-C", str(target), "rev-parse", "HEAD"], check=True,
        capture_output=True, text=True,
    ).stdout.strip()

    clean = validate_target_snapshot(target, commit)
    assert clean["tracked_files"] == 1
    (target / "extra.js").write_text("const untracked = true\n", encoding="utf-8")
    with pytest.raises(ValueError, match="clean"):
        validate_target_snapshot(target, commit)


def test_only_known_partial_parse_warnings_are_coverage_limitations() -> None:
    coverage, fatal = classify_diagnostics({"errors": [
        {"level": "warn", "type": "Syntax error", "code": 3},
        {"level": "warn", "type": "Timeout", "code": 2},
        {"level": "warn", "type": "Unknown error", "code": 3},
        {"level": "error", "type": "Timeout", "code": 2},
    ]})
    assert len(coverage) == 2
    assert len(fatal) == 2


def test_pipeline_preserves_raw_diagnostics_and_fails_closed_on_profile_mismatch(
    monkeypatch, tmp_path: Path,
) -> None:
    pytest.importorskip("tree_sitter_typescript")
    from app.pipeline_run import _resolve_findings

    raw = {
        "version": "0.0.0", "results": [],
        "errors": [{"level": "warn", "type": "Syntax error", "path": "bad.ts"}],
        "paths": {"scanned": ["good.ts"]},
    }
    monkeypatch.setattr(
        "app.pipeline_run.run_semgrep_scan",
        lambda *_args, **_kwargs: type("Scan", (), {"raw": raw, "findings": [], "stderr": "parser warning"})(),
    )
    monkeypatch.setattr(
        "app.pipeline_run.validate_target_snapshot",
        lambda *_args, **_kwargs: {"commit": "a" * 40, "tracked_files": 1, "files_sha256": "b" * 64},
    )
    output = tmp_path / "sast"

    with pytest.raises(SemgrepError, match="profile validation failed"):
        _resolve_findings(
            existing_findings=None, target=tmp_path, sast_config=str(PROFILE),
            output_dir=output, service_resolver=lambda _path: None,
        )

    saved_raw = yaml.safe_load((output / "semgrep.json").read_text(encoding="utf-8"))
    summary = yaml.safe_load((output / "summary.json").read_text(encoding="utf-8"))
    manifest = yaml.safe_load((output / "manifest.json").read_text(encoding="utf-8"))
    assert saved_raw["errors"] == raw["errors"]
    assert summary["files_scanned"] == 1
    assert summary["semgrep_errors"] == 1
    assert summary["scanner_stderr"] == "parser warning"
    assert manifest["technically_valid"] is False
    assert manifest["validation_errors"]


@pytest.mark.skipif(shutil.which("semgrep") is None, reason="Semgrep CLI is an optional SAST extra")
def test_local_rules_have_positive_and_negative_fixtures(tmp_path: Path) -> None:
    fixtures = ROOT / "sast/rules/juice-shop-v2/fixtures"
    for name in ("positive.js", "negative.js"):
        shutil.copyfile(fixtures / name, tmp_path / name)

    result = run_semgrep_scan(tmp_path, config=str(RULES))
    alerts = {(item.rule_id, Path(item.file).name) for item in result.findings}
    positive_ids = {rule for rule, name in alerts if name == "positive.js"}

    assert positive_ids == {
        "cft.node.weak-hash-md5-sha1",
        "cft.node.dynamic-code-evaluation",
        "cft.node.nosql-where-interpolation",
        "cft.node.ssrf-request-url",
        "cft.node.xml-external-entities",
        "cft.node.archive-path-write",
        "cft.node.open-redirect-user-url",
    }
    assert not {name for _, name in alerts if name == "negative.js"}
    assert all(item.source == "semgrep" for item in result.findings)
