import json
import zipfile

import pytest

from app.b09_package import package


def test_package_has_exact_manifest_and_cannot_overwrite(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    (run / "summary.json").write_text('{"repetitions":1}')
    output = tmp_path / "handoff.zip"
    result = package(run, [], output)
    assert result["files"] == 1
    with zipfile.ZipFile(output) as archive:
        assert set(json.loads(archive.read("MANIFEST-SHA256.json"))) == {"run/summary.json"}
    with pytest.raises(FileExistsError):
        package(run, [], output)


@pytest.mark.parametrize("name", [".env", ".env.local", "session.json"])
def test_private_files_cannot_be_published(tmp_path, name):
    run = tmp_path / "run"
    run.mkdir()
    (run / name).write_text("private")
    with pytest.raises(ValueError):
        package(run, [], tmp_path / "output.zip")


def test_active_key_cannot_be_published(tmp_path, monkeypatch):
    run = tmp_path / "run"
    run.mkdir()
    monkeypatch.setenv("NSU_OPENWEBUI_KEY", "disposable-test-credential")
    (run / "log.txt").write_text("disposable-test-credential")
    with pytest.raises(ValueError, match="Credential"):
        package(run, [], tmp_path / "output.zip")
