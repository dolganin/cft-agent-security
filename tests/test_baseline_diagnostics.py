"""Synthetic K02 fixtures: these are not live runs or Juice Shop findings."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from evaluation.baseline_diagnostics import (
    create_attempt,
    diagnose_artifacts,
    redact_text,
    redact_value,
    run_attempt_stage,
    validate_stage_name,
)


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value), encoding="utf-8")


def test_valid_chain_is_observed_and_stays_artifact_diagnostic(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "sast" / "raw-findings.json", {"finding_id": "f-1", "file": "routes/search.ts"})
    write_json(root / "normalized" / "findings.json", {"finding_id": "f-1", "aliases": ["alias-1"]})
    write_json(root / "bindings" / "binding.json", {"finding_id": "f-1", "endpoint": "/rest/products/search"})
    write_json(root / "actions" / "proposal.json", {"finding_id": "f-1", "action_id": "a-1"})
    write_json(root / "audit" / "validation.json", {"finding_id": "f-1", "action_id": "a-1", "status": "approved"})
    write_json(root / "execution.json", {"finding_id": "f-1", "action_id": "a-1", "status": "completed"})
    write_json(root / "evidence" / "e.json", {"finding_id": "f-1", "action_id": "a-1", "session_id": "s-1"})
    write_json(root / "reports" / "report.json", {"finding_id": "f-1", "action_id": "a-1", "status": "confirmed"})

    report = diagnose_artifacts(root, target="juice-shop-v20.2.0")

    assert report["classification"] == "artifact_diagnostic_not_a_run"
    assert report["findings"][0]["finding_id"] == "f-1"
    assert all(item["status"] == "observed" for item in report["findings"][0]["chain"])


def test_action_id_joins_execution_back_to_final_report(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "reports" / "finding.json", {
        "finding_id": "f-1",
        "verification": {"action_id": "a-1"},
        "evidence": [{"action_id": "a-1", "artifact_refs": ["execution/execution-1.json"]}],
    })
    write_json(root / "execution" / "execution-1.json", {"action_id": "a-1", "run_id": "r-1"})
    report = diagnose_artifacts(root, target="local")
    finding = report["findings"][0]
    assert finding["chain"][5]["status"] == "observed"
    assert finding["chain"][7]["status"] == "observed"


def test_semgrep_raw_result_maps_by_exact_source_anchor(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "pipeline" / "sast" / "findings.json", [{
        "id": "f-1", "source": "semgrep", "rule_id": "rule.sql", "file": "routes/search.ts", "line_start": 23,
    }])
    write_json(root / "pipeline" / "sast" / "semgrep.json", {
        "results": [{
            "check_id": "rule.sql", "path": "/tmp/juice/routes/search.ts", "start": {"line": 23},
        }],
    })
    report = diagnose_artifacts(root, target="juice-shop-v20.2.0")
    finding = report["findings"][0]
    assert finding["finding_id"] == "f-1"
    assert finding["chain"][0]["status"] == "observed"
    assert finding["chain"][1]["status"] == "observed"


def test_lost_binding_is_explicit_and_unresolved(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "sast" / "raw-findings.json", {"finding_id": "f-1"})
    report = diagnose_artifacts(root, target="local")
    assert any(reason["category"] == "binding" for reason in report["findings"][0]["reasons"])
    assert report["findings"][0]["chain"][2]["status"] == "missing"


def test_missing_canonical_action_proposal_is_not_inferred_from_action_id(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "sast" / "raw-findings.json", {"finding_id": "f-1"})
    write_json(root / "audit" / "validation.json", {"finding_id": "f-1", "action_id": "a-1", "status": "approved"})
    report = diagnose_artifacts(root, target="local")
    finding = report["findings"][0]
    assert finding["chain"][3]["status"] == "missing"
    assert any(reason["category"] == "binding" for reason in finding["reasons"])


@pytest.mark.parametrize("status", ["denied", "policy_blocked"])
def test_validator_deny_is_permission_reason(tmp_path: Path, status: str) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "audit" / "validation.json", {"finding_id": "f-1", "status": status})
    report = diagnose_artifacts(root, target="local")
    assert any(reason["category"] == "permission" for reason in report["findings"][0]["reasons"])


def test_timeout_is_kept_as_observed_category(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "reports" / "report.json", {"finding_id": "f-1", "status": "timeout"})
    report = diagnose_artifacts(root, target="local")
    assert any(reason["category"] == "timeout" for reason in report["findings"][0]["reasons"])


def test_malformed_evidence_schema_is_reported_not_repaired(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "reports" / "report.json", {
        "finding_id": "f-1",
        "evidence": [{"id": "e-1", "action_id": "a-1", "type": "runtime", "source": "runtime", "details": {"invented": True}}],
    })
    report = diagnose_artifacts(root, target="local")
    assert report["evidence_schema_issues"]
    assert "details" in report["evidence_schema_issues"][0]["error"]


def test_unknown_cause_stays_unresolved(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "reports" / "report.json", {"finding_id": "f-1", "status": "inconclusive"})
    report = diagnose_artifacts(root, target="local")
    assert any(reason["category"] == "unresolved" for reason in report["findings"][0]["reasons"])


def test_duplicate_alias_is_preserved_as_alias_not_extra_finding(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "sast" / "raw-findings.json", [
        {"finding_id": "canonical-1", "aliases": ["alias-a"]},
        {"finding_id": "canonical-1", "aliases": ["alias-b"]},
    ])
    report = diagnose_artifacts(root, target="local")
    assert len(report["findings"]) == 1
    assert report["findings"][0]["aliases"] == ["alias-a", "alias-b"]


def test_missing_artifact_reference_is_not_fabricated(tmp_path: Path) -> None:
    root = tmp_path / "artifacts"
    write_json(root / "reports" / "report.json", {
        "finding_id": "f-1",
        "evidence": [{"artifact_refs": ["absent-execution.json"]}],
    })
    report = diagnose_artifacts(root, target="local")
    assert report["missing_artifact_references"][0]["reference"] == "absent-execution.json"


def test_secret_like_failure_text_is_redacted() -> None:
    assert redact_text("request failed Bearer abcdefghijklmnop api_key=secret-value") == (
        "request failed Bearer [REDACTED] api_key=[REDACTED]"
    )


def test_attempt_id_exists_before_stage_and_attempt_cannot_be_reused(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt-001"
    attempt = create_attempt(
        attempt_dir,
        kind="stage2-v1",
        target="juice-shop-v20.2.0",
        configuration={"synthetic_fixture": True},
        command=[sys.executable, "-c", "raise SystemExit(7)"],
    )
    assert attempt_dir.joinpath("attempt.json").is_file()
    event = run_attempt_stage(attempt_dir, stage="preflight", command=[sys.executable, "-c", "raise SystemExit(7)"])
    assert event["status"] == "PREFLIGHT_FAILED"
    assert event["exit_code"] == 7
    assert json.loads((attempt_dir / "attempt.json").read_text())["attempt_id"] == attempt["attempt_id"]
    with pytest.raises(FileExistsError):
        run_attempt_stage(attempt_dir, stage="preflight", command=[sys.executable, "-c", "pass"])
    with pytest.raises(FileExistsError):
        create_attempt(
            attempt_dir,
            kind="stage1",
            target="local",
            configuration={},
            command=["ignored"],
        )


def test_timeout_is_preserved_under_existing_attempt(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt-timeout"
    create_attempt(attempt_dir, kind="stage1", target="local", configuration={}, command=["sleep"])
    event = run_attempt_stage(
        attempt_dir,
        stage="run",
        command=[sys.executable, "-c", "import time; time.sleep(2)"],
        timeout_seconds=0.01,
    )
    assert event["timed_out"] is True
    assert event["launch_failure"] is False
    assert event["status"] == "FAILED"


def test_missing_executable_is_recorded_as_launch_failure(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt-missing-binary"
    create_attempt(attempt_dir, kind="stage1", target="local", configuration={}, command=["definitely-missing-binary"])
    event = run_attempt_stage(attempt_dir, stage="run", command=["definitely-missing-binary"])
    assert event["status"] == "FAILED"
    assert event["launch_failure"] is True
    assert event["timed_out"] is False
    assert event["exit_code"] is None
    assert event["duration_seconds"] >= 0
    assert "Launch failed" in (attempt_dir / "run.stderr.txt").read_text(encoding="utf-8")
    stored = json.loads((attempt_dir / "attempt.json").read_text(encoding="utf-8"))
    assert stored["status"] == "FAILED"
    assert stored["events"][0]["status"] == "FAILED"
    assert stored["events"][0]["exit_code"] is None


def test_missing_executable_in_preflight_is_preflight_failed(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt-missing-binary-preflight"
    create_attempt(attempt_dir, kind="stage2-v1", target="local", configuration={}, command=["missing-binary"])
    event = run_attempt_stage(attempt_dir, stage="preflight", command=["missing-binary"])
    assert event["status"] == "PREFLIGHT_FAILED"
    assert event["launch_failure"] is True
    assert event["exit_code"] is None
    assert json.loads((attempt_dir / "attempt.json").read_text(encoding="utf-8"))["status"] == "PREFLIGHT_FAILED"


def test_inaccessible_cwd_is_recorded_as_launch_failure(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt-missing-cwd"
    create_attempt(attempt_dir, kind="stage1", target="local", configuration={}, command=[sys.executable])
    event = run_attempt_stage(
        attempt_dir,
        stage="run",
        command=[sys.executable, "-c", "pass"],
        cwd=tmp_path / "this-directory-does-not-exist",
    )
    assert event["status"] == "FAILED"
    assert event["launch_failure"] is True
    assert event["timed_out"] is False
    assert event["exit_code"] is None
    assert json.loads((attempt_dir / "attempt.json").read_text(encoding="utf-8"))["status"] == "FAILED"


def test_launch_failure_output_is_redacted(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt-redacted-launch"
    secret = "sk-abcdefghijklmnop"
    create_attempt(attempt_dir, kind="stage1", target="local", configuration={}, command=["missing-binary"])
    run_attempt_stage(attempt_dir, stage="run", command=[f"missing-binary-{secret}"])
    recorded = (attempt_dir / "run.stderr.txt").read_text(encoding="utf-8") + (
        attempt_dir / "attempt.json"
    ).read_text(encoding="utf-8")
    assert secret not in recorded
    assert "[REDACTED]" in recorded


@pytest.mark.parametrize("stage", ["../escape", "a/b", "/absolute", "..", "with\\back", "with space", "", "x" * 65])
def test_unsafe_stage_name_is_rejected_before_any_write(tmp_path: Path, stage: str) -> None:
    attempt_dir = tmp_path / "attempt-unsafe-stage"
    create_attempt(attempt_dir, kind="stage1", target="local", configuration={}, command=[sys.executable])
    with pytest.raises(ValueError):
        run_attempt_stage(attempt_dir, stage=stage, command=[sys.executable, "-c", "pass"])
    assert validate_stage_name("preflight") == "preflight"
    assert validate_stage_name("stage2-v1.run_1") == "stage2-v1.run_1"
    assert not (tmp_path / "escape.stdout.txt").exists()
    assert not any(path.name.endswith((".stdout.txt", ".stderr.txt")) for path in attempt_dir.iterdir())
    stored = json.loads((attempt_dir / "attempt.json").read_text(encoding="utf-8"))
    assert stored["status"] == "CREATED"
    assert stored["events"] == []


def test_attempt_configuration_drops_credential_values(tmp_path: Path) -> None:
    attempt_dir = tmp_path / "attempt-config-redaction"
    attempt = create_attempt(
        attempt_dir,
        kind="stage2-v1",
        target="local",
        configuration={
            "api_key": "sk-live-token-value",
            "nested": {"password": "hunter2", "images": {"python:3.12-alpine": {"id": "sha256:aaaa"}}},
            "route": "Bearer abcdefghijklmnop",
            "wall_clock_budget_seconds": 1800,
        },
        command=[sys.executable],
    )
    rendered = json.dumps(attempt["configuration"])
    assert "hunter2" not in rendered and "sk-live-token-value" not in rendered and "abcdefghijklmnop" not in rendered
    assert redact_value({"token": "abc"}) == {"token": "[REDACTED]"}
    assert redact_value({"target": "keep-me"}) == {"target": "keep-me"}
    assert json.loads((attempt_dir / "attempt.json").read_text(encoding="utf-8"))["configuration"]["nested"][
        "password"
    ] == "[REDACTED]"


def test_cli_returns_nonzero_when_stage_cannot_launch(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from evaluation.baseline_diagnostics import main

    attempt_dir = tmp_path / "attempt-cli-launch"
    create_attempt(attempt_dir, kind="stage1", target="local", configuration={}, command=["missing-binary"])
    exit_code = main([
        "run",
        "--attempt-dir",
        str(attempt_dir),
        "--stage",
        "run",
        "--",
        "definitely-missing-binary",
    ])
    assert exit_code != 0
    assert json.loads(capsys.readouterr().out)["launch_failure"] is True


def test_cli_returns_underlying_zero_exit_code(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    from evaluation.baseline_diagnostics import main

    attempt_dir = tmp_path / "attempt-cli"
    create_attempt(attempt_dir, kind="stage1", target="local", configuration={}, command=[sys.executable])
    exit_code = main([
        "run",
        "--attempt-dir",
        str(attempt_dir),
        "--stage",
        "run",
        "--",
        sys.executable,
        "-c",
        "pass",
    ])
    assert exit_code == 0
    assert json.loads(capsys.readouterr().out)["status"] == "COMPLETED"
