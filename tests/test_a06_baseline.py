"""A06 adapters, immutable configuration, isolation and failure semantics."""
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from evaluation import baseline_adapter as adapter
from evaluation import scanner_baseline as runner
from evaluation.baseline_freeze import freeze
from schemas.baseline import ScannerProfile


def semgrep_item(path="routes/example.ts", cwe="CWE-89: SQL Injection"):
    return {"check_id": "upstream.sql", "path": path,
            "start": {"line": 3, "col": 1}, "end": {"line": 5, "col": 9},
            "extra": {"metadata": {"cwe": [cwe]}, "severity": "ERROR"}}


def zap_item(url="http://juice:3000/rest/products/search?q=apple"):
    return {"id": "1", "pluginId": "40018", "cweid": "89", "url": url,
            "method": "GET", "param": "q", "attack": "scanner-payload",
            "risk": "High", "confidence": "High"}


def test_source_adapter_is_order_independent_and_keeps_not_run():
    item = semgrep_item("/src/routes/example.ts")
    result = adapter.observations_semgrep({"results": [item, item]})
    assert len(result) == 1
    assert result[0]["source_file"] == "routes/example.ts"
    assert result[0]["family"] == "sql-injection"
    assert result[0]["verification"] == "not_run"
    assert result[0]["evidence_backed"] is False
    assert "severity" not in result[0]  # scanner ERROR never becomes independent CVSS
    assert "http_endpoint" not in result[0]


@pytest.mark.parametrize("path", ["../secret", "/host/secret", "C:/secret", "a/../../b"])
def test_source_adapter_rejects_untrusted_paths(path):
    with pytest.raises(ValueError):
        adapter.observations_semgrep({"results": [semgrep_item(path)]})


def test_ambiguous_cwe_does_not_invent_family():
    assert adapter.family(["CWE-89", "CWE-79"], "rule") == "rule"
    assert adapter.family(["CWE-89", "CWE-9999"], "rule") == "sql-injection"
    assert adapter.family("0", "zap-1") == "zap-1"


def test_http_adapter_retains_http_anchor_and_never_creates_source_lines():
    result, rejected = adapter.observations_zap({"alerts": [zap_item()]})
    assert not rejected
    item, = result
    assert item["http_endpoint"] == "/rest/products/search"
    assert item["http_method"] == "GET" and item["http_parameter"] == "q"
    assert item["verification"] == "not_run" and not item["evidence_backed"]
    assert not {"source_file", "line_start", "line_end"} & item.keys()


@pytest.mark.parametrize("url", ["https://juice:3000/", "http://evil/", "http://juice:3000.evil/",
                                 "http://juice:3000@evil/", "http://127.0.0.1:8080/"])
def test_http_adapter_rejects_foreign_origins(url):
    result, rejected = adapter.observations_zap({"alerts": [zap_item(url)]})
    assert not result and rejected == ["1"]


def test_union_retains_source_and_http_observations_for_case_level_deduplication():
    sast = adapter.observations_semgrep({"results": [semgrep_item()]})
    dast, _ = adapter.observations_zap({"alerts": [zap_item()]})
    result = adapter.combined(sast, dast)
    assert len(result) == 2 and result == sorted(result, key=lambda o: o["id"])
    with pytest.raises(ValueError):
        adapter.combined(sast, sast)


@pytest.mark.parametrize("seed", ["//evil/", "https://evil", "/a b", "/a\\b", "/a\n"])
def test_operator_profile_rejects_foreign_seed(seed):
    profile, _ = runner.load_profile()
    payload = profile.model_dump()
    payload["seeds"] = [seed]
    with pytest.raises(ValueError):
        ScannerProfile.model_validate(payload)


def test_profile_requires_pinned_scanners_and_bounded_times():
    profile, _ = runner.load_profile()
    payload = profile.model_dump()
    payload["zap_image"] = "ghcr.io/zaproxy/zaproxy:stable"
    with pytest.raises(ValueError):
        ScannerProfile.model_validate(payload)
    payload = profile.model_dump()
    payload["budgets"]["active_seconds"] = 100000
    with pytest.raises(ValueError):
        ScannerProfile.model_validate(payload)


def test_freeze_never_overwrites_lock(tmp_path):
    (tmp_path / "scanners.lock.json").write_text("existing")
    with pytest.raises(ValueError, match="cannot be overwritten"):
        freeze(tmp_path)


def test_docker_timeout_removes_container_and_retains_partial_output(tmp_path, monkeypatch):
    calls = []

    def fake(argv, **kwargs):
        calls.append(argv)
        if argv[:2] == ["docker", "run"]:
            raise subprocess.TimeoutExpired(argv, 1, output=b"partial raw", stderr=b"partial err")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(runner, "command", fake)
    result = runner.run_container(["docker", "run"], "test-owned", tmp_path, 1)
    assert result["timed_out"] and result["exit_code"] is None
    assert (tmp_path / "stdout.log").read_text() == "partial raw"
    assert calls[-1] == ["docker", "rm", "-f", "test-owned"]


def test_scanner_container_is_networkless_and_target_readonly(tmp_path, monkeypatch):
    profile, _ = runner.load_profile()
    captured = []

    def fake(argv, name, destination, timeout):
        captured.extend(argv)
        (destination / "stdout.log").write_text(json.dumps({"results": [], "errors": [], "paths": {"scanned": ["routes/example.ts"]}}))
        return {"exit_code": 0, "timed_out": False, "seconds": 1}

    monkeypatch.setattr(runner, "run_container", fake)
    monkeypatch.setattr(runner, "stage_source", lambda *a: tmp_path / "source.tar")
    monkeypatch.setattr(runner, "command", lambda *a, **kw: SimpleNamespace(stdout="", returncode=0))
    result, observations = runner.sast(tmp_path / "target", tmp_path, profile, "a06-test")
    assert not result["errors"] and not observations
    assert "--network=none" in captured and "--read-only" in captured
    assert "--pull=never" in captured and "--metrics=off" in captured
    assert any("dst=/src,readonly" in a for a in captured)
    assert "--env-file" not in captured
    assert any("volume-nocopy" in a for a in captured)
    assert "--user=0:0" in captured


def test_parse_error_is_technical_failure_not_empty_success(tmp_path, monkeypatch):
    profile, _ = runner.load_profile()

    def fake(argv, name, destination, timeout):
        (destination / "stdout.log").write_text(json.dumps(
            {"results": [semgrep_item()], "errors": [{"type": "ParseError"}]}))
        return {"exit_code": 0, "timed_out": False, "seconds": 1}

    monkeypatch.setattr(runner, "run_container", fake)
    monkeypatch.setattr(runner, "stage_source", lambda *a: tmp_path / "source.tar")
    monkeypatch.setattr(runner, "command", lambda *a, **kw: SimpleNamespace(stdout="", returncode=0))
    result, observations = runner.sast(tmp_path / "target", tmp_path, profile, "a06-test")
    assert result["errors"] and len(observations) == 1


def test_failed_preflight_persists_attempt_and_never_runs_scanners(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("Docker unavailable")
    monkeypatch.setattr(runner, "preflight", fail)
    result = runner.run_baselines(tmp_path / "target", tmp_path / "attempt", retry_of="old-attempt")
    assert result["status"] == "TECHNICALLY_INVALID"
    assert result["retry_of"] == "old-attempt"
    assert result["technical_errors"]
    assert (tmp_path / "attempt/seal.json").is_file()
    assert json.loads((tmp_path / "attempt/union-observations-v2.json").read_text()) == []
    with pytest.raises(ValueError, match="new output"):
        runner.run_baselines(tmp_path / "target", tmp_path / "attempt")


@pytest.mark.parametrize("kind,code,level,limited", [
    ("Syntax error", 3, "warn", True),
    (["PartialParsing", [{"path": "routes/example.ts"}]], 3, "warn", True),
    ("Timeout", 2, "warn", True),
    ("Timeout", 2, "error", False),
    ("Rule parse error", 4, "warn", False),
    ("Unknown error", 3, "warn", False),
])
def test_warning_coverage_gaps_are_visible_but_fatal_diagnostics_fail(
    tmp_path, monkeypatch, kind, code, level, limited
):
    profile, _ = runner.load_profile()
    diagnostic = {"type": kind, "code": code, "level": level}

    def fake(argv, name, destination, timeout):
        (destination / "stdout.log").write_text(json.dumps({
            "results": [semgrep_item()], "errors": [diagnostic],
            "paths": {"scanned": ["routes/example.ts"]},
        }))
        return {"exit_code": 0, "timed_out": False, "seconds": 1}

    monkeypatch.setattr(runner, "run_container", fake)
    monkeypatch.setattr(runner, "stage_source", lambda *a: tmp_path / "source.tar")
    monkeypatch.setattr(runner, "command", lambda *a, **kw: SimpleNamespace(stdout="", returncode=0))
    result, observations = runner.sast(tmp_path / "target", tmp_path, profile, "a06-test")
    assert bool(result["coverage_limitations"]) is limited
    assert bool(result["errors"]) is not limited
    assert len(observations) == 1
    assert json.loads((tmp_path / "sast/coverage.json").read_text())["errors"] == [diagnostic]


def test_dast_start_failure_cleans_only_owned_resources(tmp_path, monkeypatch):
    profile, _ = runner.load_profile()
    calls = []

    def fake(argv, **kwargs):
        calls.append(argv)
        if argv[:3] == ["docker", "run", "-d"]:
            raise RuntimeError("Target failed")
        return SimpleNamespace(stdout="", stderr="", returncode=0)
    monkeypatch.setattr(runner, "command", fake)
    with pytest.raises(RuntimeError, match="Target failed"):
        runner.dast(tmp_path, profile, "a06-owned")
    assert ["docker", "rm", "-f", "a06-owned-juice"] in calls
    assert ["docker", "network", "rm", "a06-owned-net"] in calls
    assert all("prune" not in call for call in calls)
    creation = next(call for call in calls if call[:3] == ["docker", "network", "create"])
    assert "--internal" in creation


def test_command_does_not_forward_provider_secrets(monkeypatch):
    monkeypatch.setenv("NSU_OPENWEBUI_KEY", "secret")
    captured = {}
    def fake(argv, **kwargs):
        captured.update(kwargs)
        return SimpleNamespace(returncode=0, stdout="", stderr="")
    monkeypatch.setattr(subprocess, "run", fake)
    runner.command(["docker", "version"])
    assert "NSU_OPENWEBUI_KEY" not in captured["env"]


def test_a05_observation_wire_keys_are_compatible():
    # This branch does not import/reimplement unmerged A05 schemas.
    allowed = {"id", "source", "family", "service", "sample_kind", "source_file", "line_start",
               "line_end", "http_method", "http_endpoint", "http_parameter", "verification",
               "reported_verdict", "evidence_backed", "evidence", "capability", "severity",
               "context_priority"}
    source = adapter.observations_semgrep({"results": [semgrep_item()]})
    http, _ = adapter.observations_zap({"alerts": [zap_item()]})
    for observation in source + http:
        assert observation.keys() <= allowed
        assert {"id", "source", "family"} <= observation.keys()


def test_snapshot_does_not_use_expected_labels():
    profile, lock = runner.load_profile()
    provenance = json.loads((runner.PROFILE_DIR / "rules-provenance.json").read_text())
    assert provenance["rule_count"] > 100
    assert provenance["selection"]["target_or_expected_label_filters"] is False
    assert not any("ground_truth" in path or "catalog" in path for path in lock["inputs"])
    # Configuration mounted into ZAP contains neither case IDs nor holdout labels.
    assert "holdout" not in json.dumps(profile.model_dump())


def test_changed_scanner_input_is_rejected(monkeypatch):
    actual = runner.input_sha
    monkeypatch.setattr(runner, "input_sha", lambda path: "0" * 64
                        if path.name == "profile.yaml" else actual(path))
    with pytest.raises(ValueError, match="frozen input mismatch"):
        runner.load_profile()


def test_target_unicode_names_and_hidden_worktree_mutation(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    file = target / "unicode-коллекция with spaces.txt"
    file.write_bytes(b"frozen\n")
    prefix = ["git", "-c", "core.autocrlf=false", "-c", "user.name=Test",
              "-c", "user.email=test@example.invalid", "-C", str(target)]
    runner.command([*prefix, "init"])
    runner.command([*prefix, "add", "."])
    runner.command([*prefix, "commit", "-m", "fixture"])
    commit = runner.command([*prefix, "rev-parse", "HEAD"]).stdout.strip()
    profile, _ = runner.load_profile()
    profile = profile.model_copy(update={"target_commit": commit})
    assert file.name in runner.validate_target(target, profile)
    runner.command([*prefix, "update-index", "--assume-unchanged", file.name])
    file.write_bytes(b"changed\n")
    with pytest.raises(ValueError, match="bytes differ"):
        runner.validate_target(target, profile)


def test_output_cannot_overlap_original_target(tmp_path):
    with pytest.raises(ValueError, match="outside the target"):
        runner.run_baselines(tmp_path / "target", tmp_path / "target/attempt")


def test_source_stager_refuses_host_execution(monkeypatch):
    from evaluation.semgrep_baseline_worker import run
    monkeypatch.delenv("CFT_A06_CONTAINER", raising=False)
    with pytest.raises(RuntimeError, match="Docker-only"):
        run()


def test_zap_driver_refuses_host_execution(monkeypatch):
    from evaluation.zap_baseline_worker import run
    monkeypatch.delenv("CFT_A06_CONTAINER", raising=False)
    with pytest.raises(RuntimeError, match="Docker-only"):
        run()


def test_empty_scan_is_not_success(tmp_path, monkeypatch):
    profile, _ = runner.load_profile()
    def fake(argv, name, destination, timeout):
        (destination / "stdout.log").write_text(json.dumps({"results": [], "errors": []}))
        return {"exit_code": 0, "timed_out": False, "seconds": 1}
    monkeypatch.setattr(runner, "run_container", fake)
    monkeypatch.setattr(runner, "stage_source", lambda *a: tmp_path / "source.tar")
    monkeypatch.setattr(runner, "command", lambda *a, **kw: SimpleNamespace(stdout="", returncode=0))
    result, _ = runner.sast(tmp_path / "target", tmp_path, profile, "a06-test")
    assert any("scanned no files" in error for error in result["errors"])


def test_cleanup_audit_runs_after_preflight_failure(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("preflight failed")
    calls = []
    def fake(argv, **kwargs):
        calls.append(argv)
        return SimpleNamespace(stdout="owned-resource", returncode=0)
    monkeypatch.setattr(runner, "preflight", fail)
    monkeypatch.setattr(runner, "command", fake)
    result = runner.run_baselines(tmp_path / "target", tmp_path / "attempt")
    assert not result["cleanup_complete"]
    assert len(calls) == 3
    assert result["status"] == "TECHNICALLY_INVALID"


def test_cleanup_unknown_when_docker_unavailable(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise RuntimeError("Docker unavailable")
    monkeypatch.setattr(runner, "preflight", fail)
    monkeypatch.setattr(runner, "command", fail)
    result = runner.run_baselines(tmp_path / "target", tmp_path / "attempt")
    assert not result["cleanup_complete"]
    assert sum("Cleanup audit" in e for e in result["technical_errors"]) == 3


def test_ajax_initial_stopped_is_not_completion(tmp_path, monkeypatch):
    from evaluation import zap_baseline_worker as worker
    profile, _ = runner.load_profile()
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(profile.model_dump_json())
    native_path = Path
    monkeypatch.setattr(worker, "Path", lambda p: profile_path if p == "/input/profile.json"
                        else tmp_path if p == "/.dockerenv" else native_path(p))
    monkeypatch.setenv("CFT_A06_CONTAINER", "1")
    monkeypatch.setattr(worker, "OUT", tmp_path)
    monkeypatch.setattr(worker.subprocess, "Popen", lambda *a, **k: SimpleNamespace(
        terminate=lambda: None, wait=lambda **kw: None))
    statuses = iter(["stopped", "running", "stopped", "stopped"])
    seen = []
    def api(component, kind, operation, **params):
        seen.append((component, operation))
        if component == "ajaxSpider" and operation == "status":
            return {"status": next(statuses)}
        if operation == "numberOfResults":
            return {"numberOfResults": 1 if seen.count(("ajaxSpider", "status")) >= 2 else 0}
        return {"version": "test", "contextId": "1", "scan": "1", "status": 100,
                "recordsToScan": 0, "alerts": [], "urls": [], "accessUrl": []}
    monkeypatch.setattr(worker, "api", api)
    def wait(predicate, seconds):
        return any(predicate() for _ in range(4))
    monkeypatch.setattr(worker, "wait_until", wait)
    assert worker.run() == 0
    assert seen.count(("ajaxSpider", "status")) == 4
    assert ("ascan", "scan") in seen
