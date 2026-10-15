from hashlib import sha256
from pathlib import Path

import pytest

from evidence.password_storage_review import review_password_storage

MODEL = """import * as security from '../lib/insecurity'
class User {}
User.init({ password: { set (value: string) {
  this.setDataValue('password', security.hash(value))
} } })
"""
HELPER = """import crypto from 'node:crypto'
export const hash = (data: string) => crypto.createHash('md5').update(data).digest('hex')
"""


def fixture(root, model=MODEL, helper=HELPER):
    for name, source in (("models/user.ts", model), ("lib/insecurity.ts", helper)):
        path = root / name
        path.parent.mkdir(exist_ok=True)
        path.write_text(source)
    return {name: sha256((root / name).read_bytes()).hexdigest()
            for name in ("models/user.ts", "lib/insecurity.ts")}


def check(root, hashes):
    return review_password_storage(root=root, model_file="models/user.ts",
        helper_file="lib/insecurity.ts", source_sha256=hashes)


def test_password_proof_binds_setter_import_helper_and_storage(tmp_path):
    result = check(tmp_path, fixture(tmp_path))
    assert result["status"] == "confirmed", result
    assert result["scope"] == "source_condition"
    assert result["runtime_exploit_verified"] is False
    assert result["controls"]["password_storage_bound"] is True
    assert result["algorithm"] == "md5"
    assert "data" not in result and "password" not in result


@pytest.mark.parametrize(("model", "helper"), [
    (MODEL.replace("security.hash(value)", "security.hash(value + salt)"), HELPER),
    (MODEL.replace("'password', security", "'username', security"), HELPER),
    (MODEL.replace("../lib/insecurity", "../other/insecurity"), HELPER),
    (MODEL + "\nsecurity.hash = anotherFunction\n", HELPER),
    (MODEL + "\nsecurity['hash'] = anotherFunction\n", HELPER),
    (MODEL, HELPER.replace("'md5'", "'sha256'")),
    (MODEL, HELPER.replace(".update(data)", ".update(salt).update(data)")),
    (MODEL, HELPER.replace(".update(data)", ".update(data + salt)")),
    (MODEL, HELPER.replace("crypto.createHash", "other.createHash")),
    (MODEL, HELPER + "\nexport const hash = other\n"),
    (MODEL, HELPER.replace("export const hash", "const hash")),
    (MODEL, HELPER + "\nhash = other\n"),
    (MODEL.replace("security.hash(value)", "value"), HELPER),
    (MODEL.replace("security.hash(value)", "security.hash('value')"), HELPER),
    (MODEL, HELPER.replace(".update(data)", ".update('data')")),
])
def test_unproven_or_safe_counterpart_never_becomes_confirmed(tmp_path, model, helper):
    assert check(tmp_path, fixture(tmp_path, model, helper))["status"] == "review_pending"


def test_stale_snapshot_or_symlink_cannot_be_proof(tmp_path):
    hashes = fixture(tmp_path)
    (tmp_path / "models/user.ts").write_text(MODEL + "// mutation\n")
    assert check(tmp_path, hashes)["status"] == "review_pending"
    fixture(tmp_path)
    (tmp_path / "lib/insecurity.ts").unlink()
    (tmp_path / "helper.ts").write_text(HELPER)
    (tmp_path / "lib/insecurity.ts").symlink_to(tmp_path / "helper.ts")
    assert check(tmp_path, hashes)["status"] == "review_pending"


TARGET = Path(__file__).resolve().parents[1] / "artifacts/benchmark-target/juice-shop"


@pytest.mark.skipif(not TARGET.exists(), reason="Pinned Juice Shop checkout required")
def test_actual_pinned_password_storage_source_chain():
    hashes = {name: sha256((TARGET / name).read_bytes()).hexdigest()
              for name in ("models/user.ts", "lib/insecurity.ts")}
    result = check(TARGET, hashes)
    assert result["status"] == "confirmed", result
    assert result["setter"]["line_start"] == 72
    assert result["helper"]["line_start"] == 41
