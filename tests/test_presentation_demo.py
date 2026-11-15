import argparse
import json

import pytest

from app import demo
from app.config import settings


def test_demo_runner_keeps_canonical_pipeline_and_records_limited_scope(tmp_path, monkeypatch):
    previous = settings.scout_max_turns
    captured = {}

    def runner(args):
        captured.update(config=args.sast_config, scout_turns=settings.scout_max_turns)
        return 1

    monkeypatch.setattr(demo, "run_ci_pipeline", runner)
    args = argparse.Namespace(
        profile=str(demo.PROFILE), output_dir=str(tmp_path),
        agent_mode="llm", max_iterations=2,
    )
    assert demo.run_demo_pipeline(args) == 1
    assert captured == {"config": str(demo.RULES), "scout_turns": 2}
    assert settings.scout_max_turns == previous
    manifest = json.loads((tmp_path / "demo-scope.json").read_text())
    assert manifest["full_benchmark"] is False
    assert manifest["scout_max_candidates"] == 4
    assert manifest["max_output_tokens"] == 8192
    assert manifest["reasoning_effort"] == "low"


def test_demo_runner_does_not_accept_arbitrary_profiles(tmp_path):
    with pytest.raises(ValueError, match="registered demo profile"):
        demo.run_demo_pipeline(argparse.Namespace(profile=str(tmp_path / "untrusted.yaml")))


def test_order_demo_uses_separate_policy_and_restores_settings(tmp_path, monkeypatch):
    import yaml

    original = settings.policy_file
    captured = {}

    def runner(args):
        captured["policy"] = settings.policy_file
        captured["workers"] = args.reasoning_prefetch_workers
        captured["coalesce"] = args.coalesce_bound_scout
        return 0

    monkeypatch.setattr(demo, "run_ci_pipeline", runner)
    args = argparse.Namespace(profile=str(demo.ORDER_PROFILE), output_dir=str(tmp_path),
                              agent_mode="stub", max_iterations=2)
    assert demo.run_demo_pipeline(args) == 0
    assert captured["policy"] == demo.ROOT / "policies/demo-order-store.yaml"
    assert captured["workers"] == 2 and captured["coalesce"]
    assert settings.policy_file == original
    default = yaml.safe_load((demo.ROOT / "policies/default.yaml").read_text())
    scoped = yaml.safe_load(captured["policy"].read_text())
    assert "verify_demo_idor" not in default["tools"]["allowed"]
    assert "verify_demo_idor" in scoped["tools"]["allowed"]
