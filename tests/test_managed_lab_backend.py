"""Managed CI labs keep generic agent commands inside the Docker boundary."""

from unittest.mock import MagicMock

from agent.lab import ManagedAgentLab
from executor.executor import SafeExecutor


def test_managed_lab_initializes_docker_executor(monkeypatch) -> None:
    captured = {}
    executor = MagicMock()

    def fake_from_config(**kwargs):
        captured.update(kwargs)
        return executor

    monkeypatch.setattr(SafeExecutor, "from_config", fake_from_config)
    lab = ManagedAgentLab(target=MagicMock(), runtime_services=MagicMock())

    assert captured["backend_override"] == "docker"
    assert lab.executor is executor
