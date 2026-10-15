"""Read-only readiness checks for the pinned Juice Shop optimization runner."""
from __future__ import annotations

import json
import re
from hashlib import sha256
from pathlib import Path

import yaml

from evaluation.benchmark_freeze import validate as _canonical_validation


def verify_frozen_benchmark(root: Path, *, expected_commit: str, target: Path | None = None) -> dict:
    """Use the canonical A04 validator; return aggregate metadata, never case labels."""
    root = root.resolve(strict=True)
    base = root / "benchmarks/juice-shop-v20.2.0-v2"
    lock_path = base / "dataset.lock.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    validation = _canonical_validation(directory=base, target=target)
    if (validation.get("status") != "valid_frozen_a04"
            or lock.get("target_commit") != expected_commit
            or lock.get("dataset_id") != "juice-shop-v20.2.0-v2"):
        raise ValueError("Frozen Juice Shop dataset target or identity mismatch")
    protocol_path = base / "protocol.yaml"
    protocol_lock_path = base / "protocol.lock.json"
    protocol_lock = json.loads(protocol_lock_path.read_text(encoding="utf-8"))
    protocol_digest = sha256(protocol_path.read_bytes()).hexdigest()
    if (lock.get("protocol_sha256") != protocol_digest
            or protocol_lock.get("protocol_sha256") != protocol_digest
            or protocol_lock.get("target_commit") != expected_commit
            or protocol_lock.get("dataset_id") != lock["dataset_id"]):
        raise ValueError("Frozen Juice Shop dataset/protocol lock mismatch")
    dataset = yaml.safe_load((base / "ground_truth.yaml").read_text(encoding="utf-8"))
    original = [row for row in dataset["cases"] if row["sample_kind"] == "original"]
    positive = sum(row["expected"] == "vulnerable" for row in original)
    safe = sum(row["expected"] == "safe" for row in original)
    if len(original) != 35 or positive != 27 or safe != 8:
        raise ValueError("Frozen Juice Shop original denominator is not 27 positive plus 8 safe cases")
    return {"dataset_id": lock["dataset_id"], "target_commit": expected_commit,
        "dataset_lock_sha256": sha256(lock_path.read_bytes()).hexdigest(),
        "protocol_sha256": protocol_digest, "verified_input_files": validation["inputs_bound"],
        "total_dataset_entries": validation["case_count"], "original_case_count": len(original),
        "positive_count": positive, "safe_control_count": safe,
        "historical_implementation_revision": validation["historical_implementation_revision"],
        "current_implementation_verified": validation["current_implementation_verified"]}


def check_candidate_catalog_reproducibility(target: Path, *, root: Path) -> dict:
    """Report current A02 extractor drift separately from the frozen A04 lock."""
    from collections import Counter

    from evaluation.positive_catalog import extract_candidates

    root, target = root.resolve(strict=True), target.resolve(strict=True)
    catalog = root / "benchmarks/juice-shop-v20.2.0-v2/catalog/candidates.generated.yaml"
    saved = yaml.safe_load(catalog.read_text(encoding="utf-8"))
    generated = extract_candidates(target)
    matches = generated == saved
    frozen_rows = {row["key"]: row for row in saved.get("candidates", [])}
    generated_rows = {row["key"]: row for row in generated.get("candidates", [])}
    drift = Counter()
    if set(frozen_rows) != set(generated_rows):
        drift["candidate_set"] = len(set(frozen_rows) ^ set(generated_rows))
    for key in set(frozen_rows) & set(generated_rows):
        left, right = frozen_rows[key], generated_rows[key]
        drift.update(field for field in set(left) | set(right) if left.get(field) != right.get(field))
    return {"status": "reproducible" if matches else "generator_drift",
        "current_extractor_matches_frozen_output": matches,
        "changed_fields_by_candidate_count": dict(sorted(drift.items())),
        "scope": "A02 source-candidate extractor only; not A04 truth or runtime evidence"}


def require_immutable_image(reference: str, inspect) -> dict:
    """Require a local image addressed by digest or immutable full image ID."""
    if not isinstance(reference, str) or not (
        re.search(r"@sha256:[0-9a-f]{64}$", reference)
        or re.fullmatch(r"sha256:[0-9a-f]{64}", reference)
    ):
        raise ValueError("Docker image must be pinned by digest or full image ID")
    raw = inspect(["image", "inspect", reference])
    try:
        records = json.loads(raw)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError("Docker image inspection returned invalid metadata") from exc
    if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
        raise ValueError("Docker image inspection did not resolve one local image")
    row = records[0]
    image_id = row.get("Id")
    if not isinstance(image_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("Docker image inspection returned no immutable image ID")
    if reference.startswith("sha256:") and reference != image_id:
        raise ValueError("Requested Docker image ID resolved to a different image")
    repo_digests = row.get("RepoDigests") or []
    if "@" in reference:
        digest = reference.rsplit("@", 1)[1]
        if not any(str(item).endswith("@" + digest) for item in repo_digests):
            raise ValueError("Requested Docker digest is absent from the local image metadata")
    return {"reference": reference, "image_id": image_id,
        "repo_digests": sorted(str(item) for item in repo_digests),
        "architecture": row.get("Architecture"), "os": row.get("Os")}
