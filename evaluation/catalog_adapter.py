"""Minimal A02/A03 to A05 adapter; catalogs remain provisional until A04."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from schemas.benchmark_v2 import (
    BenchmarkDatasetV2,
    BenchmarkEvaluationCaseV2,
    BenchmarkHTTPAnchorV2,
    BenchmarkSourceAnchorV2,
)
from schemas.benchmark_catalog import PositiveCatalog
from schemas.benchmark_control_expansion import ExpandedControl
from schemas.benchmark_controls import ControlCatalog


FAMILY_ALIASES = {
    "sql-injection": ["sql_injection"],
    "sensitive-data-exposure": ["sensitive_data"],
    "open-redirect": ["redirect"],
}


def _sample(value: str) -> str:
    return value.removesuffix("_safe")


def _legacy_http(values: list[str]) -> list[BenchmarkHTTPAnchorV2]:
    anchors = []
    for value in values:
        method = None
        route = value.strip()
        match = re.match(r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(.+)$", route)
        if match:
            method, route = match.groups()
        for endpoint in re.split(r"\s+and\s+", route):
            anchors.append(BenchmarkHTTPAnchorV2(method=method, endpoint=endpoint.strip()))
    return anchors


def load_catalog_dataset(
    positives_path: Path,
    controls_path: Path,
    expanded_controls_path: Path | None = None,
) -> BenchmarkDatasetV2:
    positives = PositiveCatalog.model_validate(
        yaml.safe_load(positives_path.read_text(encoding="utf-8"))
    )
    controls = ControlCatalog.model_validate(
        yaml.safe_load(controls_path.read_text(encoding="utf-8"))
    )
    if positives.target_commit != controls.target_commit:
        raise ValueError("A02 and A03 target commits differ")
    cases = [
        BenchmarkEvaluationCaseV2(
            id=item.id,
            expected="vulnerable",
            family=item.category,
            cwe=item.cwe,
            independence_group=item.independence_group,
            sample_kind="original",
            split=item.split,
            service=item.service,
            source_anchors=[
                BenchmarkSourceAnchorV2(
                    file=anchor.file,
                    line_start=anchor.line_start,
                    line_end=anchor.line_end,
                    role=anchor.role,
                )
                for anchor in item.source_anchors
                if anchor.role not in {"provenance", "registration"}
            ],
            http_anchors=[
                BenchmarkHTTPAnchorV2(
                    method=anchor.method,
                    endpoint=anchor.endpoint,
                    parameter=anchor.parameter,
                )
                for anchor in item.http_anchors
            ],
        )
        for item in positives.cases
    ]

    def safe_case(item):
        return BenchmarkEvaluationCaseV2(
            id=item.id,
            expected="safe",
            family=item.family.replace("_", "-"),
            independence_group=item.independence_group,
            sample_kind=_sample(item.control_type),
            split=item.split,
            service=item.service,
            source_anchors=[
                BenchmarkSourceAnchorV2(
                    file=anchor.file,
                    line_start=anchor.start,
                    line_end=anchor.end,
                    role="source",
                )
                for anchor in item.source_anchors
            ],
            http_anchors=_legacy_http(item.http_anchors),
        )

    cases.extend(safe_case(item) for item in controls.controls)
    if expanded_controls_path is not None:
        document = yaml.safe_load(expanded_controls_path.read_text(encoding="utf-8"))
        if document.get("schema_version") != "a03.1.controls.v1":
            raise ValueError("Unsupported expanded control catalog")
        cases.extend(safe_case(ExpandedControl.model_validate(item)) for item in document["controls"])
    return BenchmarkDatasetV2(
        id="juice-shop-v20.2.0-v2-catalog-adapter",
        target_commit=positives.target_commit,
        status="catalog_adapter_pending_a04",
        family_aliases=FAMILY_ALIASES,
        cases=cases,
    )
