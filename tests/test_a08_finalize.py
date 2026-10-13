import hashlib
import json
from types import SimpleNamespace

import pytest

from scripts.a08_finalize import loss_rows, seal_review


def test_missing_source_is_explicit_not_a_full_seal_pass(tmp_path):
    (tmp_path / "manifest.json").write_text("{}")
    (tmp_path / "seal.json").write_text(json.dumps({
        "manifest.json": hashlib.sha256(b"{}").hexdigest(), "sast/source.tar": "a" * 64,
    }))
    with pytest.raises(ValueError):
        seal_review(tmp_path)
    result = seal_review(tmp_path, ["sast/source.tar"])
    assert not result["full_seal_verified"]
    assert result["available_files_verified"]
    assert result["declared_missing"] == ["sast/source.tar"]
    (tmp_path / "manifest.json").write_text('{"changed":true}')
    with pytest.raises(ValueError):
        seal_review(tmp_path, ["sast/source.tar"])


def test_loss_map_separates_wrong_binding_from_unexecuted_controls():
    anchor = SimpleNamespace(file="lib/a.ts", line_start=41, line_end=41, role="sink")
    positive = SimpleNamespace(id="POS", family="weak-cryptography", split="development",
                               sample_kind="original", expected="vulnerable", source_anchors=[anchor])
    control = SimpleNamespace(id="SAFE", family="weak-cryptography", split="development",
                              sample_kind="patched", expected="safe", source_anchors=[anchor])
    results = [SimpleNamespace(case_id=c.id, detected=False, verification="not_detected",
                               confirmation_supported=False, matched_observation_ids=[]) for c in (positive, control)]
    observation = SimpleNamespace(id="wrong-family", source_file="lib/a.ts", line_start=41,
                                  line_end=41, sample_kind="original")
    scope = {c.id: {"runtime_eligible": True} for c in (positive, control)}
    rows = loss_rows(SimpleNamespace(cases=[positive, control]),
                     [SimpleNamespace(cases=results)], [observation], {"reviewed_ranges": []}, scope)
    assert rows[0]["loss_stage"] == "binding_family_mismatch"
    assert rows[1]["loss_stage"] == "control_not_executed_in_a07"
