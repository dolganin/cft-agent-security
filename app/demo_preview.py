"""Lifecycle for the loopback-only browser preview of the presentation target."""
from __future__ import annotations

import json
import subprocess
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from pipeline.subprocess_runner import run_cancellable_process


class OrderStorePreview:
    """Run a view-only target container beside, but separate from, agent sessions."""

    project_name = "cft-demo-order-store-preview"
    preview_url = "http://127.0.0.1:8090"

    def __init__(self, target_directory: str | Path) -> None:
        self.target_directory = Path(target_directory).resolve(strict=True)
        self.compose_file = self.target_directory / "compose.yaml"
        self.preview_override = self.target_directory / "compose.preview.yaml"
        self._started = False
        self._status = "starting"
        self._message = ""

    def public_status(self) -> dict[str, str]:
        result = {"status": self._status, "url": self.preview_url}
        if self._message:
            result["message"] = self._message
        return result

    def _compose(self, *args: str, timeout: float = 30) -> subprocess.CompletedProcess[str]:
        if not self.compose_file.is_file():
            raise FileNotFoundError("Demo Compose file is missing")
        from app.ci_pipeline import target_subprocess_environment

        result = run_cancellable_process(
            [
                "docker", "compose", "--project-name", self.project_name,
                "--file", str(self.compose_file),
                "--file", str(self.preview_override), *args,
            ],
            cwd=self.target_directory,
            timeout=timeout,
            environment=target_subprocess_environment(),
        )
        if result.returncode:
            raise RuntimeError("Docker Compose could not start the local demo preview")
        return result

    def start(self) -> None:
        self._status = "starting"
        # Mark before `up`: Compose can create some resources and still fail.
        self._started = True
        try:
            self._compose("up", "--build", "--detach", timeout=600)
            deadline = time.monotonic() + 35
            while time.monotonic() < deadline:
                try:
                    with urlopen(f"{self.preview_url}/health", timeout=1) as response:
                        payload = json.loads(response.read(1024))
                    if payload == {"status": "ok", "app": "cft-order-store-demo", "version": "1.0"}:
                        self._status = "ready"
                        self._message = ""
                        return
                except (OSError, URLError, ValueError, json.JSONDecodeError):
                    pass
                time.sleep(0.25)
            raise TimeoutError("Local demo preview did not become ready")
        except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError):
            self._status = "unavailable"
            self._message = "Не удалось поднять предпросмотр. Проверьте, что Docker запущен и порт 8090 свободен."
            self.stop()
            self._status = "unavailable"

    def stop(self) -> None:
        if not self._started:
            return
        try:
            self._compose("down", "--volumes", "--remove-orphans", timeout=45)
        except (OSError, RuntimeError, subprocess.SubprocessError, TimeoutError):
            # The agent's disposable run still owns its independent cleanup path.
            pass
        finally:
            self._started = False
            if self._status != "unavailable":
                self._status = "stopped"
