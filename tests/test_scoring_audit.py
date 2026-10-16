"""The reference packet is blinded and unknown architecture facts remain unknown."""
from app.scoring_audit import annotation_packet, architecture_preview
from schemas.benchmark_v2 import BenchmarkDatasetV2


def test_reference_packet_has_no_predicted_labels_and_binds_original_sources(tmp_path):
    source = tmp_path / "handler.ts"
    source.write_text("const handler = 1;\n")
    dataset = BenchmarkDatasetV2.model_validate({"id": "test", "target_commit": "a" * 40,
        "status": "synthetic", "cases": [{"id": "TEST-001", "expected": "vulnerable",
        "family": "test", "independence_group": "one", "sample_kind": "original", "split": "development",
        "source_anchors": [{"file": "handler.ts", "line_start": 1, "line_end": 1}],
        "expected_context_priority": "HIGH"}]})
    packet = annotation_packet(dataset, "b" * 64, tmp_path)
    assert packet["status"] == "draft_unreviewed"
    assert packet["cases"][0]["expected_context_priority"] is None
    assert packet["cases"][0]["reviewed_by"] is None
    assert len(packet["cases"][0]["source_anchors"][0]["file_sha256"]) == 64


def test_database_access_cannot_invent_exposure_criticality_or_blast_radius(tmp_path):
    (tmp_path / "models").mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "models/index.ts").write_text("dialect: 'sqlite'\n")
    (tmp_path / "data/mongodb.ts").write_text("export const orders = new MarsDB.Collection('orders')\n")
    preview = architecture_preview(tmp_path, {"target": {"commit": "a" * 40}})
    assert preview["priority_preview"]["assessment_status"] == "partial"
    assert set(preview["priority_preview"]["unknown_inputs"]) >= {"public_exposure", "criticality", "blast_radius"}
    assert preview["priority_preview"]["score"] == 2
    assert preview["accuracy_claimed"] is False
