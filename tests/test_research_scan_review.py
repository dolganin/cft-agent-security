import json
import os

import pytest

from evidence.research_scan_review import review_scanner_source_conditions
from sast.identity import normalize_finding
from schemas.finding import Finding


def candidate(root, *, algorithm="md5"):
    source = "import crypto from 'node:crypto'\nexport const hash = (data: string) => crypto.createHash('" + algorithm + "').update(data).digest('hex')\n"
    path = root / "lib/insecurity.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source)
    raw = Finding(id="scanner-md5", source="semgrep", rule_id="cft.node.weak-hash-md5-sha1",
        title="Weak MD5 digest", description="Weak digest invocation", file="lib/insecurity.ts",
        line_start=2, line_end=2)
    return normalize_finding(raw, repository_root=root)


def test_scanner_source_review_confirms_only_source_condition(tmp_path):
    finding = candidate(tmp_path)
    output = review_scanner_source_conditions(root=tmp_path, findings=[finding], output=tmp_path / "review")
    report = output["reviews"][0]
    assert report["review"]["status"] == "confirmed"
    assert report["scope"] == "source_condition"
    assert report["runtime_verdict_changed"] is False
    assert output["runtime_verdicts_changed"] is False
    assert json.loads((tmp_path / "review/reviews.json").read_text()) == output


def test_scanner_source_review_rejects_strong_digest_without_runtime_verdict(tmp_path):
    finding = candidate(tmp_path, algorithm="sha256")
    output = review_scanner_source_conditions(root=tmp_path, findings=[finding], output=tmp_path / "review")
    assert output["reviews"][0]["review"]["status"] == "rejected"
    assert output["reviews"][0]["runtime_verdict_changed"] is False


def test_scanner_source_review_does_not_accept_stale_source_binding(tmp_path):
    finding = candidate(tmp_path)
    (tmp_path / "lib/insecurity.ts").write_text("changed\n")
    output = review_scanner_source_conditions(root=tmp_path, findings=[finding], output=tmp_path / "review")
    assert output["reviews"][0]["review"]["status"] == "review_pending"
    assert "file" not in output["reviews"][0]


def test_password_chain_is_additional_source_proof_not_runtime(tmp_path):
    from hashlib import sha256

    finding = candidate(tmp_path)
    model = tmp_path / "models/user.ts"
    model.parent.mkdir()
    model.write_text("import * as security from '../lib/insecurity'\n"
                     "class User {}\nUser.init({ password: { set(value: string) {"
                     "this.setDataValue('password', security.hash(value)) } } })\n")
    hashes = {name: sha256((tmp_path / name).read_bytes()).hexdigest()
              for name in ("models/user.ts", "lib/insecurity.ts")}
    result = review_scanner_source_conditions(root=tmp_path, findings=[finding],
        output=tmp_path / "review", source_sha256=hashes)
    assert result["password_storage_review"]["status"] == "confirmed"
    assert result["password_storage_review"]["runtime_exploit_verified"] is False
    assert result["runtime_verdicts_changed"] is False
    assert result["reviewed_findings"] == 1


@pytest.mark.skipif(not os.getenv("CFT_RESEARCH_BRIDGE_TARGET"), reason="Opt-in pinned Juice Shop source check")
def test_real_juice_shop_md5_helper_gets_source_only_proof(tmp_path):
    from pathlib import Path

    from app.research_juice_smoke import COMMIT
    from sast.profiles import validate_target_snapshot

    root = Path(os.environ["CFT_RESEARCH_BRIDGE_TARGET"]).resolve()
    validate_target_snapshot(root, COMMIT)
    line = next(index for index, value in enumerate((root / "lib/insecurity.ts").read_text().splitlines(), 1)
                if "createHash('md5')" in value)
    finding = normalize_finding(Finding(id="pinned-md5", source="semgrep", rule_id="cft.node.weak-hash-md5-sha1",
        title="Weak digest", description="Source candidate", file="lib/insecurity.ts",
        line_start=line, line_end=line), repository_root=root)
    output = review_scanner_source_conditions(root=root, findings=[finding], output=tmp_path / "review")
    assert output["reviews"][0]["review"]["status"] == "confirmed"
    assert output["reviews"][0]["review"]["scope"] == "source_condition"
    assert output["runtime_verdicts_changed"] is False
