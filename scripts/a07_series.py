"""Bounded A07 orchestration around the canonical CI pipeline and A05 scorer.

This module does not implement detection or matching. It freezes existing inputs,
runs one fresh CI pipeline attempt at a time and seals its outputs for the
existing offline v2 scorer. Scoring and series aggregation are separate steps.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "a07-series"
TARGET = ROOT / "artifacts" / "benchmark-target" / "juice-shop"
PROFILE = ROOT / "targets" / "juice-presentation.yaml"
DATASET = ROOT / "benchmarks" / "juice-shop-v20.2.0-v2" / "ground_truth.yaml"
CONFIG = ARTIFACTS / "a07-config.json"
LOCK = ARTIFACTS / "a07.lock.json"
BASELINE_ROOT = ROOT / "artifacts" / "a06-series"
BASELINE_RUNS = [BASELINE_ROOT / f"run-{number:02d}" for number in (1, 2, 3)]
REQUIRED_TARGET_COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha_file(path: Path) -> str:
    return sha_bytes(path.read_bytes())


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def command(argv: list[str], *, cwd: Path = ROOT, timeout: int = 120,
            env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, check=False, env=env)


def producer_environment(config: dict[str, Any]) -> dict[str, str]:
    """Apply frozen non-secret settings; credentials remain operator-owned."""
    env = os.environ.copy()
    for key, value in config["agent"]["settings"].items():
        if not re.fullmatch(r"[a-z][a-z0-9_]*", key) or not isinstance(value, (str, int, float, bool)):
            raise ValueError("Invalid frozen producer setting")
        env[f"CFT_{key.upper()}"] = str(value).lower() if isinstance(value, bool) else str(value)
    env["CFT_POLICY_FILE"] = str(ROOT / config["agent"]["policy"])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def llm_statistics(attempts: list[dict[str, Any]]) -> dict[str, int]:
    # ProviderFailoverClient uses request_failed/auth_or_access/schema_validation_failed,
    # not just the generic error/failed names. Fallback is not a successful model call.
    return {
        "llm_request_count": sum(item.get("status") != "fallback" for item in attempts),
        "llm_success_count": sum(item.get("status") == "ok" for item in attempts),
        "llm_failure_count": sum(item.get("status") not in {"ok", "fallback"} for item in attempts),
        "timeout_count": sum("timeout" in str(item.get("status", "")) for item in attempts),
        "fallback_count": sum(item.get("status") == "fallback" for item in attempts),
    }


def git(*args: str) -> str:
    result = command(["git", *args])
    if result.returncode:
        raise RuntimeError(f"git {args[0]} failed: {result.stderr[-1000:]}")
    return result.stdout.strip()


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def validate_prerequisites(*, full_target: bool = True) -> dict[str, Any]:
    results: dict[str, Any] = {}
    a01 = command([sys.executable, "-m", "evaluation.benchmark_protocol"])
    results["a01"] = {"exit_code": a01.returncode, "output": a01.stdout.strip(), "error": a01.stderr[-1000:]}
    if a01.returncode:
        raise RuntimeError("A01 protocol/lock validation failed")
    a04_args = [sys.executable, "-m", "evaluation.benchmark_freeze", "validate"]
    if full_target:
        a04_args.extend(["--target", str(TARGET)])
    a04 = command(a04_args, timeout=300)
    results["a04"] = {"exit_code": a04.returncode, "output": a04.stdout.strip(), "error": a04.stderr[-1000:]}
    if a04.returncode:
        raise RuntimeError("A04 dataset/target validation failed")
    a06 = command([sys.executable, "-m", "app.scanner_baseline", "validate", "--target", str(TARGET)], timeout=300)
    results["a06"] = {"exit_code": a06.returncode, "output": a06.stdout.strip(), "error": a06.stderr[-1000:]}
    if a06.returncode:
        raise RuntimeError("A06 scanner/dataset lock validation failed")
    preflight = command([sys.executable, "-m", "app.scanner_baseline", "preflight", "--target", str(TARGET)], timeout=600)
    results["a06_preflight"] = {"exit_code": preflight.returncode, "output": preflight.stdout.strip(), "error": preflight.stderr[-1000:]}
    if preflight.returncode:
        raise RuntimeError("A06 runtime/image preflight failed")
    return results


def a06_reuse_inventory() -> dict[str, Any]:
    protocol = read_yaml(ROOT / "benchmarks" / "juice-shop-v20.2.0-v2" / "protocol.yaml")
    dataset_lock_sha = sha_file(ROOT / "benchmarks" / "juice-shop-v20.2.0-v2" / "dataset.lock.json")
    matcher_sha = sha_file(ROOT / "evaluation" / "benchmark_v2.py")
    profile_path = ROOT / "benchmarks" / "baselines-a06-v5" / "profile.yaml"
    scanner_lock_path = profile_path.parent / "scanners.lock.json"
    profile_sha = sha_file(profile_path)
    rules_sha = sha_file(profile_path.parent / "semgrep-rules.yaml")
    scanner_lock_sha = sha_file(scanner_lock_path)
    expected_profile = read_yaml(profile_path)
    manifests: list[dict[str, Any]] = []
    valid = True
    for run_path in BASELINE_RUNS:
        manifest_path = run_path / "manifest.json"
        seal_path = run_path / "seal.json"
        if not manifest_path.is_file() or not seal_path.is_file():
            valid = False
            manifests.append({"run_id": run_path.name, "valid": False, "reason": "missing manifest or seal"})
            continue
        manifest = read_json(manifest_path)
        seal = read_json(seal_path)
        actual = {
            path.relative_to(run_path).as_posix(): sha_file(path)
            for path in sorted(run_path.rglob("*"))
            if path.is_file() and path != seal_path
        }
        seal_valid = seal == actual
        match = (
            manifest.get("status") == "COMPLETED_WITH_LIMITATIONS"
            and manifest.get("agent_commit") == git("rev-parse", "HEAD")
            and manifest.get("dataset_lock_sha256") == dataset_lock_sha
            and manifest.get("profile") == expected_profile
            and manifest.get("scanner_lock") == read_json(scanner_lock_path)
            and manifest.get("target_files_sha256")
            and manifest.get("original_unchanged") is True
            and manifest.get("cleanup_complete") is True
            and seal_valid
        )
        valid = valid and bool(match)
        manifests.append({
            "run_id": manifest.get("attempt_id"),
            "status": manifest.get("status"),
            "manifest_sha256": sha_file(manifest_path),
            "seal_file_sha256": sha_file(seal_path),
            "seal_valid": seal_valid,
            "matching_frozen_inputs": bool(match),
            "target_file_count": len(manifest.get("target_files_sha256") or {}),
        })
    return {
        "reused": valid and len(manifests) == 3,
        "run_ids": [item.get("run_id") for item in manifests],
        "runs": manifests,
        "comparison": {
            "dataset_lock_sha256": dataset_lock_sha,
            "matcher_sha256": matcher_sha,
            "profile_id": expected_profile.get("schema_version"),
            "profile_sha256": profile_sha,
            "rules_sha256": rules_sha,
            "scanner_lock_sha256": scanner_lock_sha,
            "target_commit": expected_profile.get("target_commit"),
            "target_image": expected_profile.get("target_image"),
            "role": expected_profile.get("role"),
            "budgets": expected_profile.get("budgets"),
            "protocol_scanner_reference": protocol.get("freeze", {}).get("scanners"),
        },
    }


def frozen_configuration() -> dict[str, Any]:
    protocol_dir = ROOT / "benchmarks" / "juice-shop-v20.2.0-v2"
    protocol = read_yaml(protocol_dir / "protocol.yaml")
    legacy = read_yaml(ROOT / "benchmarks" / "juice-shop-v20.2.0" / "benchmark.yaml")
    scanner_dir = ROOT / "benchmarks" / "baselines-a06-v5"
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    target_head = command(["git", "-C", str(TARGET), "rev-parse", "HEAD"])
    if target_head.returncode or target_head.stdout.strip() != REQUIRED_TARGET_COMMIT:
        raise RuntimeError("Pinned target commit mismatch")
    target_status = command(["git", "-C", str(TARGET), "status", "--porcelain=v1", "--untracked-files=all"])
    if target_status.returncode or target_status.stdout.strip():
        raise RuntimeError("Pinned target checkout is not clean")
    docker = command(["docker", "version", "--format", "{{.Server.Version}}/{{.Server.Os}}/{{.Server.Arch}}"])
    if docker.returncode:
        raise RuntimeError("Docker Engine is unavailable")
    baseline = a06_reuse_inventory()
    config: dict[str, Any] = {
        "schema_version": "a07.configuration.v1",
        "frozen_at": datetime.now(UTC).isoformat(),
        "project": {
            "commit": git("rev-parse", "HEAD"),
            "status_porcelain": status,
            "status_sha256": sha_bytes(status.encode("utf-8")),
        },
        "protocol": {
            "id": protocol.get("dataset_id"),
            "version": protocol.get("schema_version"),
            "sha256": sha_file(protocol_dir / "protocol.yaml"),
            "lock_sha256": sha_file(protocol_dir / "protocol.lock.json"),
            "baseline_settings": protocol.get("baseline", {}).get("settings"),
            "max_iterations": protocol.get("baseline", {}).get("max_iterations"),
            "transport": protocol.get("baseline", {}).get("llm_transport"),
            "legacy_rule_profile": legacy.get("rules"),
        },
        "dataset": {
            "id": protocol.get("dataset_id"),
            "lock_sha256": sha_file(protocol_dir / "dataset.lock.json"),
            "ground_truth_sha256": sha_file(DATASET),
            "case_count": 41,
            "development_count": 28,
            "holdout_count": 13,
            "identities": "bound by the A04 dataset lock; evaluator-only, never passed to producer",
        },
        "matcher": {
            "path": "evaluation/benchmark_v2.py",
            "sha256": sha_file(ROOT / "evaluation" / "benchmark_v2.py"),
            "scorer_path": "evaluation/offline_rescore.py",
            "scorer_sha256": sha_file(ROOT / "evaluation" / "offline_rescore.py"),
        },
        "target": {
            "name": "OWASP Juice Shop v20.2.0",
            "commit": REQUIRED_TARGET_COMMIT,
            "profile": str(PROFILE.relative_to(ROOT)).replace("\\", "/"),
            "profile_sha256": sha_file(PROFILE),
            "image": "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b",
            "target_git_status": target_status.stdout.strip(),
            "target_git_tree": command(["git", "-C", str(TARGET), "rev-parse", "HEAD^{tree}"]).stdout.strip(),
            "runtime_constraints": read_yaml(PROFILE).get("constraints"),
            "compose_sha256": sha_file(TARGET / "docker-compose.presentation.yml"),
        },
        "runtime": {
            "docker_server": docker.stdout.strip(),
            "host_os": os.name,
            "python": sys.version.split()[0],
            "fresh_compose_project_per_run": True,
            "compose_network": "internal; no published ports per profile and sandbox validator",
            "executor_worker_image": protocol.get("baseline", {}).get("settings", {}).get("sandbox_image"),
        },
        "agent": {
            "settings": protocol.get("baseline", {}).get("settings"),
            "transport": protocol.get("baseline", {}).get("llm_transport"),
            "target_profile": legacy.get("profile"),
            "policy": legacy.get("policy"),
            "policy_sha256": sha_file(ROOT / legacy.get("policy")),
            "sast_profile": legacy.get("rules"),
            "sast_profile_sha256": sha_file(ROOT / legacy.get("rules")),
            "max_iterations": protocol.get("baseline", {}).get("max_iterations"),
            "commands": ["python", "-m", "app.ci_pipeline", "--agent-mode", "llm", "--max-iterations", "2"],
            "executor_limits": {key: protocol.get("baseline", {}).get("settings", {}).get(key) for key in (
                "executor_timeout_seconds", "executor_cpu_time_seconds", "executor_memory_mb",
                "executor_max_file_bytes", "executor_max_processes", "executor_max_output_bytes",
                "executor_max_runs_per_action", "executor_max_concurrent_runs",
            )},
            "evidence_sources": {
                path: sha_file(ROOT / path) for path in (
                    "evidence/evidence.py", "evidence/guard.py", "evidence/interpreter.py",
                    "executor/executor.py", "executor/worker.py", "agent/prompts.py",
                    "agent/repository_scout.py", "agent/llm_model.py",
                ) if (ROOT / path).is_file()
            },
        },
        "scanner_baseline": {
            "profile_path": "benchmarks/baselines-a06-v5/profile.yaml",
            "profile_sha256": sha_file(scanner_dir / "profile.yaml"),
            "rules_sha256": sha_file(scanner_dir / "semgrep-rules.yaml"),
            "lock_sha256": sha_file(scanner_dir / "scanners.lock.json"),
            "provenance": baseline,
            "reused_baseline_series": baseline["reused"],
        },
    }
    config["configuration_digest"] = sha_bytes(canonical(config))
    return config


def freeze() -> dict[str, Any]:
    ARTIFACTS.mkdir(parents=True, exist_ok=True)
    prereq = validate_prerequisites(full_target=True)
    config = frozen_configuration()
    write_json(CONFIG, config)
    lock = {
        "schema_version": "a07.lock.v1",
        "configuration_digest": config["configuration_digest"],
        "created_at": config["frozen_at"],
        "prerequisites": prereq,
        "input_files": {
            path: sha_file(ROOT / path) for path in (
                "benchmarks/juice-shop-v20.2.0-v2/protocol.yaml",
                "benchmarks/juice-shop-v20.2.0-v2/protocol.lock.json",
                "benchmarks/juice-shop-v20.2.0-v2/dataset.lock.json",
                "benchmarks/juice-shop-v20.2.0-v2/ground_truth.yaml",
                "evaluation/benchmark_v2.py", "evaluation/offline_rescore.py",
                "evaluation/benchmark.py", "benchmarks/juice-shop-v20.2.0/benchmark.yaml",
                "scripts/a07_series.py",
                "targets/juice-presentation.yaml", "policies/default.yaml",
                "docs/demo/semgrep.yaml", "benchmarks/baselines-a06-v5/profile.yaml",
                "benchmarks/baselines-a06-v5/semgrep-rules.yaml",
                "benchmarks/baselines-a06-v5/scanners.lock.json",
            )
        },
        "target_commit": REQUIRED_TARGET_COMMIT,
        "target_tree": config["target"]["target_git_tree"],
        "target_image": config["target"]["image"],
    }
    write_json(LOCK, lock)
    return {"status": "frozen", "configuration_digest": config["configuration_digest"], "lock": str(LOCK)}


def verify_freeze() -> dict[str, Any]:
    config = read_json(CONFIG)
    lock = read_json(LOCK)
    recorded_digest = config.pop("configuration_digest", None)
    computed_digest = sha_bytes(canonical(config))
    config["configuration_digest"] = recorded_digest
    if computed_digest != recorded_digest or lock.get("configuration_digest") != recorded_digest:
        raise RuntimeError("A07 configuration digest mismatch")
    for relative, expected in lock["input_files"].items():
        if sha_file(ROOT / relative) != expected:
            raise RuntimeError(f"A07 frozen input changed: {relative}")
    if git("rev-parse", "HEAD") != config["project"]["commit"]:
        raise RuntimeError("A07 project commit changed")
    current_status = git("status", "--porcelain=v1", "--untracked-files=all")
    if current_status != config["project"]["status_porcelain"]:
        raise RuntimeError("A07 project Git status changed")
    if a06_reuse_inventory() != config["scanner_baseline"]["provenance"]:
        raise RuntimeError("A06 sealed baseline provenance changed")
    validate_prerequisites(full_target=True)
    return config


def _seal(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): sha_file(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and path.name != "seal.json"
    }


def _jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
            except json.JSONDecodeError:
                rows.append({"status": "malformed_record"})
    return rows


def run_one(name: str) -> dict[str, Any]:
    config = verify_freeze()
    if not re.fullmatch(r"agent-run-0[123](?:-retry-[0-9]{2})?", name):
        raise ValueError("run name must be agent-run-01..03, optionally with -retry-NN")
    run_root = ARTIFACTS / name
    if run_root.exists():
        raise FileExistsError(f"Refusing to overwrite existing A07 attempt: {run_root}")
    run_root.mkdir(parents=True)
    started = datetime.now(UTC)
    start_clock = time.monotonic()
    attempt_id = f"{name}-{started.strftime('%Y%m%dT%H%M%SZ')}"
    config_snapshot = {"configuration_digest": config["configuration_digest"]}
    write_json(run_root / "configuration.json", config_snapshot)
    manifest: dict[str, Any] = {
        "schema_version": "a07.agent-run.v1",
        "run_id": name,
        "attempt_id": attempt_id,
        "retry_of": name.split("-retry-")[0] if "-retry-" in name else None,
        "status": "running",
        "started_at": started.isoformat(),
        "project_commit": config["project"]["commit"],
        "dataset_id": config["dataset"]["id"],
        "dataset_lock_sha256": config["dataset"]["lock_sha256"],
        "matcher_sha256": config["matcher"]["sha256"],
        "target_commit": REQUIRED_TARGET_COMMIT,
        "target_image": config["target"]["image"],
        "configuration_digest": config["configuration_digest"],
        "snapshot": {"dataset": {"id": config["dataset"]["id"]}},
        "model_configuration": config["agent"]["transport"],
        "fresh_target_reset": True,
        "fresh_evaluator_session": True,
        "fresh_artifact_directory": True,
    }
    write_json(run_root / "manifest.json", manifest)
    pipeline = run_root / "pipeline"
    argv = [
        sys.executable, "-m", "app.ci_pipeline", "--target", str(TARGET),
        "--profile", str(PROFILE), "--sast-config", str(ROOT / "docs" / "demo" / "semgrep.yaml"),
        "--output-dir", str(pipeline), "--agent-mode", "llm", "--max-iterations", str(config["agent"]["max_iterations"]),
    ]
    result = command(argv, timeout=7200, env=producer_environment(config))
    (run_root / "runner.stdout.log").write_text(result.stdout, encoding="utf-8")
    (run_root / "runner.stderr.log").write_text(result.stderr, encoding="utf-8")
    duration = time.monotonic() - start_clock
    finished = datetime.now(UTC)
    attempts = _jsonl(pipeline / "audit" / "llm-attempts.jsonl")
    statistics = llm_statistics(attempts)
    successes = statistics["llm_success_count"]
    traces = list((pipeline / "traces").glob("*.json")) if (pipeline / "traces").is_dir() else []
    proposals = allowed = denied = executions = 0
    evidence_outcomes: dict[str, int] = {}
    iteration_total = 0
    for trace_path in traces:
        try:
            trace = read_json(trace_path)
        except (OSError, json.JSONDecodeError):
            continue
        iteration_total += int(trace.get("iterations", 0)) if isinstance(trace, dict) else 0
        for action in trace.get("actions", []) if isinstance(trace, dict) else []:
            proposals += int(bool(action.get("action")))
            validation = action.get("validation") or {}
            allowed += int(validation.get("approved") is True)
            denied += int(validation.get("approved") is False)
            executions += int(bool(action.get("execution")))
        for evidence in trace.get("evidence", []) if isinstance(trace, dict) else []:
            verdict = str(evidence.get("verdict", "unknown"))
            evidence_outcomes[verdict] = evidence_outcomes.get(verdict, 0) + 1
    ci_summary = read_json(pipeline / "ci-summary.json") if (pipeline / "ci-summary.json").is_file() else {}
    gate = read_json(pipeline / "gate.json") if (pipeline / "gate.json").is_file() else {}
    session_id = ci_summary.get("session_id")
    cleanup = None
    if session_id:
        project = f"cft-sandbox-{str(session_id)[:12]}"
        cleanup = {}
        for kind, argv_kind in (("containers", ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"]),
                                ("networks", ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"]),
                                ("volumes", ["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"])):
            audit = command(argv_kind)
            cleanup[kind] = {"exit_code": audit.returncode, "remaining": [line for line in audit.stdout.splitlines() if line.strip()]}
    target_status = command(["git", "-C", str(TARGET), "status", "--porcelain=v1", "--untracked-files=all"])
    integrity = target_status.returncode == 0 and not target_status.stdout.strip()
    cleanup_complete = bool(cleanup) and all(
        item["exit_code"] == 0 and not item["remaining"] for item in cleanup.values()
    )
    valid = (
        ci_summary.get("status") == "completed" and result.returncode in {0, 1}
        and successes > 0 and integrity and cleanup_complete
        and bool(gate) and not gate.get("technical_errors")
        and not gate.get("errors") and not gate.get("stage_errors")
    )
    manifest.update({
        "finished_at": finished.isoformat(),
        "duration_seconds": round(duration, 3),
        "status": "completed" if valid else "technically_invalid",
        "pipeline_exit_code": result.returncode,
        **statistics,
        "retry_count": 0,
        "fallback_reasons": [item.get("category") for item in attempts if item.get("status") == "fallback"],
        "scout_iterations": (read_json(pipeline / "scout" / "summary.json").get("iterations") if (pipeline / "scout" / "summary.json").is_file() else None),
        "agent_iterations": iteration_total,
        "action_proposal_count": proposals,
        "validator_allowed_count": allowed,
        "validator_denied_count": denied,
        "executor_action_count": executions,
        "evidence_outcomes": evidence_outcomes,
        "policy_block_count": denied,
        "technical_errors": gate.get("technical_errors", []) if isinstance(gate, dict) else [],
        "sandbox_session_id": session_id,
        "cleanup": cleanup,
        "cleanup_complete": cleanup_complete,
        "original_target_integrity": integrity,
    })
    write_json(run_root / "metrics.json", {"status": "completed" if manifest["status"] == "completed" else "technically_invalid", "diagnostics": [] if manifest["status"] == "completed" else ["CI pipeline failed or required stage incomplete"]})
    write_json(run_root / "manifest.json", manifest)
    write_json(run_root / "run-status.json", {"status": manifest["status"], "finished_at": manifest["finished_at"], "exit_code": result.returncode})
    write_json(run_root / "seal.json", _seal(run_root))
    return {"run_id": name, "attempt_id": attempt_id, "status": manifest["status"], "duration_seconds": manifest["duration_seconds"], "llm_requests": manifest["llm_request_count"], "fallbacks": manifest["fallback_count"], "policy_blocks": manifest["policy_block_count"], "seal_valid": read_json(run_root / "seal.json") == _seal(run_root)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("freeze", "verify", "run"))
    parser.add_argument("name", nargs="?")
    args = parser.parse_args()
    if args.command == "freeze":
        print(json.dumps(freeze(), indent=2))
    elif args.command == "verify":
        config = verify_freeze()
        print(json.dumps({"status": "valid", "configuration_digest": config["configuration_digest"]}, indent=2))
    else:
        if not args.name:
            parser.error("run requires a run name")
        print(json.dumps(run_one(args.name), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
