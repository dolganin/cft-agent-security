import json

import pytest

from app import juice_run_preflight


def test_frozen_benchmark_preflight_uses_canonical_a04_validation():
    from app.research_diagnostic_run import COMMIT, ROOT

    report = juice_run_preflight.verify_frozen_benchmark(ROOT, expected_commit=COMMIT)
    assert report["dataset_id"] == "juice-shop-v20.2.0-v2"
    assert report["original_case_count"] == 35
    assert report["positive_count"] == 27
    assert report["safe_control_count"] == 8
    assert report["current_implementation_verified"] is False
    assert "historical_implementation_revision" in report
    assert not {"case_ids", "labels", "findings"} & report.keys()


def test_frozen_benchmark_preflight_rejects_wrong_expected_target():
    from app.research_diagnostic_run import ROOT

    with pytest.raises(ValueError, match="target or identity mismatch"):
        juice_run_preflight.verify_frozen_benchmark(ROOT, expected_commit="a" * 40)


def test_candidate_catalog_drift_reports_fields_without_disclosing_candidate_ids(tmp_path, monkeypatch):
    from app.research_diagnostic_run import ROOT
    from evaluation import positive_catalog

    target = tmp_path / "target"
    target.mkdir()
    catalog_path = ROOT / "benchmarks/juice-shop-v20.2.0-v2/catalog/candidates.generated.yaml"
    import yaml

    generated = yaml.safe_load(catalog_path.read_text(encoding="utf-8"))
    generated["candidates"][0]["route_ids"] = []
    monkeypatch.setattr(positive_catalog, "extract_candidates", lambda _target: generated)
    result = juice_run_preflight.check_candidate_catalog_reproducibility(target, root=ROOT)

    assert result["status"] == "generator_drift"
    assert result["changed_fields_by_candidate_count"] == {"route_ids": 1}
    assert not {"candidate_ids", "ids", "labels", "findings"} & result.keys()


def test_image_preflight_requires_local_image_digest_and_matching_id():
    image_id = "sha256:" + "b" * 64
    digest = "python@sha256:" + "c" * 64
    row = {"Id": image_id, "RepoDigests": [digest], "Architecture": "arm64", "Os": "linux"}
    check = juice_run_preflight.require_immutable_image(digest, lambda args: json.dumps([row]))
    assert check["image_id"] == image_id and check["architecture"] == "arm64"
    with pytest.raises(ValueError, match="pinned"):
        juice_run_preflight.require_immutable_image("python:latest", lambda _args: json.dumps([row]))
    with pytest.raises(ValueError, match="different image"):
        juice_run_preflight.require_immutable_image("sha256:" + "d" * 64, lambda _args: json.dumps([row]))
    with pytest.raises(ValueError, match="absent"):
        juice_run_preflight.require_immutable_image("python@sha256:" + "e" * 64, lambda _args: json.dumps([row]))
