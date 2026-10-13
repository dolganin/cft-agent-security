from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline.subprocess_runner import run_cancellable_process
from sast.normalizer import normalize_semgrep_payload
from schemas.finding import Finding


class SemgrepError(RuntimeError):
    """Ошибка, когда локальный скан Semgrep не удалось запустить или завершить."""


_DOCKER_SEMGREP_IMAGE = (
    "semgrep/semgrep@sha256:f1f7b71861c7b28b6e0f661225a2c4f58a484f5d0f182465c6d6b3b22f972ade"
)


@dataclass(frozen=True)
class SemgrepScanResult:
    target: Path
    config: str
    raw: dict[str, Any]
    findings: list[Finding]
    stderr: str


def run_semgrep_scan(
    target: str | Path,
    *,
    config: str = "auto",
    timeout_seconds: int = 600,
    service_resolver: Callable[[str], str | None] | None = None,
) -> SemgrepScanResult:
    """Запустить скан SAST Semgrep только для чтения по локальному дереву исходников.

    Таргет используется только как рабочий каталог процесса. Сервер приложения не
    запускается, и этот код не отправляет сетевые запросы к таргету.
    """
    target_path = Path(target).expanduser().resolve()
    if not target_path.is_dir():
        raise SemgrepError(f"SAST target directory does not exist: {target_path}")

    executable = shutil.which("semgrep") or _environment_semgrep()
    scanner_root = None
    if executable is None:
        docker = shutil.which("docker") if sys.platform == "win32" else None
        config_path = _local_config_path(config)
        if docker is None or config_path is None:
            raise SemgrepError(
                "Semgrep CLI was not found. Activate the project venv and install "
                'the SAST extra: python -m pip install -e ".[dev,sast]"'
            )
        command = _docker_command(target_path, config_path, docker=docker)
        scanner_root = "/src"
    else:
        command = [
            executable,
            "scan",
            "--config",
            config,
            "--json",
            "--no-rewrite-rule-ids",
            "--exclude",
            ".venv",
            "--exclude",
            "node_modules",
            "--exclude",
            "dist",
            "--exclude",
            "build",
            ".",
        ]

    # SAST запускается только для чтения в каталоге таргета
    try:
        completed = run_cancellable_process(
            command,
            cwd=target_path,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepError(f"Semgrep timed out after {timeout_seconds} seconds") from exc
    except OSError as exc:
        raise SemgrepError(f"Failed to start Semgrep: {exc}") from exc

    if completed.returncode != 0 and _needs_windows_docker_fallback(completed):
        scanner_root = "/src"
        config_path = _local_config_path(config)
        if config_path is None:
            raise SemgrepError("Docker Semgrep fallback requires a local config file")
        completed = run_cancellable_process(
            _docker_command(target_path, config_path), cwd=target_path, timeout=timeout_seconds
        )

    if completed.returncode != 0:
        detail = completed.stderr.strip() or completed.stdout.strip()
        raise SemgrepError(
            f"Semgrep exited with code {completed.returncode}: {detail[:2000]}"
        )

    try:
        raw = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise SemgrepError("Semgrep did not return valid JSON") from exc

    if not isinstance(raw, dict):
        raise SemgrepError("Semgrep JSON root must be an object")

    try:
        findings = normalize_semgrep_payload(raw, service_resolver=service_resolver,
                                             repository_root=target_path, scanner_root=scanner_root)
    except (TypeError, ValueError) as exc:
        raise SemgrepError("Semgrep returned invalid or unsafe source locations") from exc

    return SemgrepScanResult(
        target=target_path,
        config=config,
        raw=raw,
        findings=findings,
        stderr=completed.stderr,
    )


def _environment_semgrep() -> str | None:
    """uv может не добавить Scripts в PATH, но CLI лежит рядом с его Python."""
    directory = Path(sys.executable).resolve().parent
    names = ("semgrep.exe", "semgrep") if sys.platform == "win32" else ("semgrep",)
    for name in names:
        candidate = directory / name
        if candidate.is_file():
            return str(candidate)
    return None


def _needs_windows_docker_fallback(completed: subprocess.CompletedProcess[str]) -> bool:
    """Windows semgrep-core иногда падает до scan, тогда уходим в Linux container."""
    diagnostic = f"{completed.stdout}\n{completed.stderr}".lower()
    return sys.platform == "win32" and "semgrep-core" in diagnostic and shutil.which("docker")


def _local_config_path(config: str) -> Path | None:
    if config == "auto":
        return None
    path = Path(os.path.abspath(Path(config).expanduser()))
    return path if path.is_file() else None


def _docker_command(
    target_path: Path,
    config_path: Path,
    *,
    docker: str = "docker",
) -> list[str]:
    """Target только читаем, Semgrep получает tmpfs для своего cache и git config."""
    return [
        docker,
        "run",
        "--pull=never",
        "--rm",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--network",
        "none",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,size=64m",
        "--tmpfs",
        "/root:rw,noexec,nosuid,size=32m",
        "-v",
        f"{target_path}:/src:ro",
        "-v",
        f"{config_path}:/semgrep-config.yaml:ro",
        "-w",
        "/src",
        _DOCKER_SEMGREP_IMAGE,
        "semgrep",
        "scan",
        "--config",
        "/semgrep-config.yaml",
        "--json",
        "--no-rewrite-rule-ids",
        "--exclude",
        ".venv",
        "--exclude",
        "node_modules",
        "--exclude",
        "dist",
        "--exclude",
        "build",
        ".",
    ]
