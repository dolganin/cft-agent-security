"""Thin entrypoint checks and opt-in real Docker replay."""
import argparse
import json
import os
from pathlib import Path

import pytest

from app import stage1_e2e
from schemas.fix import FixVerificationArtifact, ProposedPatch


def test_image_preflight_resolves_only_installed_digest(monkeypatch):
    calls = []
    def inspect(argv):
        calls.append(argv)
        return json.dumps(["image@sha256:" + "a" * 64])
    monkeypatch.setattr(stage1_e2e, "_command", inspect)
    assert stage1_e2e.pinned_image("image:local") == "image@sha256:" + "a" * 64
    assert calls[0][:3] == ["docker", "image", "inspect"]


def test_image_without_digest_is_refused(monkeypatch):
    monkeypatch.setattr(stage1_e2e, "_command", lambda _: "[]")
    with pytest.raises(ValueError, match="immutable"):
        stage1_e2e.pinned_image("image:local")


def test_registered_sql_proposal_is_bounded_and_has_no_execution_interface():
    query = "models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`)"
    client = stage1_e2e.IntegrationPatchClient("prefix\n" + query + "\nsuffix\n")
    proposal = client.complete_model(operation="propose_patch")
    assert isinstance(proposal, ProposedPatch)
    assert ":criteria" in proposal.unified_diff and "replacements" in proposal.unified_diff
    with pytest.raises(ValueError):
        client.complete_model(operation="execute")


@pytest.mark.integration
@pytest.mark.skipif(os.getenv("CFT_RUN_STAGE1_E2E") != "1",
                    reason="Set CFT_RUN_STAGE1_E2E=1 with provisioned Juice Shop and pinned images")
def test_real_juice_fix_verification_replays_without_leftover_runtime(tmp_path):
    target = Path(os.getenv("CFT_JUICE_TARGET", str(stage1_e2e.ROOT / "artifacts/stage1-juice-shop")))
    args = argparse.Namespace(target=str(target), fix_image=None, worker_image=None,
                              report=None, review=None, output_dir=str(tmp_path))
    artifacts = []
    for _ in range(2):
        assert stage1_e2e.run(args) == 0
    for path in tmp_path.glob("stage1-*/fix-verification.json"):
        result = FixVerificationArtifact.model_validate_json(path.read_text(encoding="utf-8"))
        assert result.status == "FIXED" and result.security_verified and result.applied
        assert result.before_evidence.verdict == "confirmed"
        assert result.after_evidence.verdict == "rejected"
        assert result.original_unchanged and result.cleanup_complete
        assert len(result.stages) == 10 and all(s.status == "passed" for s in result.stages)
        before = json.loads((path.parent / "original-before.json").read_text())
        after = json.loads((path.parent / "original-after.json").read_text())
        assert before == after
        artifacts.append(result)
    assert len(artifacts) == 2
    assert artifacts[0].workspace_id != artifacts[1].workspace_id
    assert artifacts[0].before_evidence.sandbox_session_id != artifacts[1].before_evidence.sandbox_session_id
    assert artifacts[0].after_evidence.sandbox_session_id != artifacts[1].after_evidence.sandbox_session_id
    assert artifacts[0].trusted_binding == artifacts[1].trusted_binding
