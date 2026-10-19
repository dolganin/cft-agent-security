"""A04 evaluator-only freeze/preflight. No target execution or model calls.

Render emits proposed files to stdout; applying them is an explicit operator
step. Existing freezes cannot be regenerated in place. Validation is read-only.
The A05-compatible scorer projection is accompanied by mandatory scope metadata;
it is NOT permission to pool original, patched, synthetic or source-only cases.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from collections import Counter
from pathlib import Path, PurePosixPath

import yaml

from evaluation.benchmark_protocol import ROOT, load_protocol, split_group
from evaluation.control_catalog import anchor as grounded_anchor
from evaluation.control_expansion import validate as validate_controls
from evaluation.control_expansion_runtime import make_patch
from evaluation.historical_baseline import (
    BASELINE_REVISION,
    frozen_presentation_input,
    historical_input,
)
from evaluation.positive_catalog import validate_catalog

DIRECTORY = ROOT / "benchmarks/juice-shop-v20.2.0-v2"
OUTPUTS = {"ground_truth.yaml", "scope.yaml", "review.yaml", "rubric.yaml", "dataset.lock.json"}
HELPERS = [
    ".gitattributes",
    "evaluation/benchmark_freeze.py", "evaluation/benchmark_protocol.py",
    "evaluation/positive_catalog.py", "evaluation/control_catalog.py",
    "evaluation/control_expansion.py", "evaluation/control_expansion_sources.py",
    "evaluation/control_expansion_runtime.py", "evaluation/control_expansion_oracle.cjs",
    "evaluation/control_bootstrap.cjs", "evaluation/control_source.py",
    "schemas/benchmark.py", "schemas/benchmark_catalog.py",
    "schemas/benchmark_controls.py", "schemas/benchmark_control_expansion.py",
]
# Narrow reviewed ordinal labels, not CVSS scores or official Juice Shop labels.
SEVERITY = {
    "JS-SQL-001": ("HIGH", "Unbound search SQL can expose application database records; read-impact rubric."),
    "JS-SQL-002": ("HIGH", "Unbound authentication query can bypass credential validation; authentication-impact rubric."),
    "JS-AUTHZ-001": ("HIGH", "Public generated product update lacks authentication, permitting unauthorized persistent changes."),
    "JS-AUTHZ-002": ("HIGH", "Public registration accepts an administrative role, permitting privilege escalation."),
}
FAMILY_ALIASES = {
    "sql-injection": ["sql_injection"],
    "sensitive-data-exposure": ["sensitive_data"],
    "open-redirect": ["redirect"],
}


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_yaml(path: Path):
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def safe_input(relative: str) -> Path:
    path = PurePosixPath(relative)
    if not path.parts or path.is_absolute() or ".." in path.parts or path.as_posix() != relative:
        raise ValueError("Noncanonical freeze input")
    current = ROOT
    for part in path.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("Linked freeze input")
    if not current.resolve().is_relative_to(ROOT) or not current.is_file():
        raise ValueError("Missing freeze input: " + relative)
    return current


def source_inputs() -> list[str]:
    files = [p.relative_to(ROOT).as_posix() for p in DIRECTORY.rglob("*")
             if p.is_file() and p.name not in OUTPUTS and "__pycache__" not in p.parts]
    return sorted(set(files + HELPERS))


def source_anchor(anchor: dict) -> dict:
    return {"file": anchor["file"], "line_start": anchor.get("line_start", anchor.get("start")),
            "line_end": anchor.get("line_end", anchor.get("end")), "role": anchor.get("role", "source")}


def http_controls(values: list[str]) -> list[dict]:
    result = []
    for value in values:
        # A03 has prose combined paths; only explicit individual paths are admissible.
        if " and " in value:
            continue
        method, path = value.split(" ", 1) if " " in value else (None, value)
        if path.startswith("/") and not any(c.isspace() for c in path):
            result.append({"method": method, "endpoint": path, "parameter": None})
    return result


def corpus() -> tuple[list[dict], list[dict]]:
    positives = read_yaml(DIRECTORY / "catalog/positives.reviewed.yaml")["cases"]
    controls = read_yaml(DIRECTORY / "controls/controls.reviewed.yaml")["controls"]
    controls += read_yaml(DIRECTORY / "controls/expansion/controls.reviewed.yaml")["controls"]
    return positives, controls


def reviewed_anchors(record: dict, target: Path) -> list[dict]:
    """Narrow overly broad A02/A03 anchors without rewriting historical inputs."""
    id_ = record["id"]
    if id_ == "JS-FILE-001":
        # One concrete directory-publication cause. Keys/logs need future cases.
        return [source_anchor(grounded_anchor(target, "server.ts", 288, 289))]
    if id_ == "JS-SAFE-REDIRECT-101":
        return [{"file": "lib/insecurity.ts", "line_start": 133, "line_end": 139, "role": "sink"}]
    if id_ == "JS-SAFE-NOSQL-101":
        # After the frozen four-line insertion, not the original whole file.
        return [{"file": "routes/updateProductReviews.ts", "line_start": 17, "line_end": 25, "role": "sink"}]
    synthetic = {"JS-SAFE-XSS-101": "render_text", "JS-SAFE-PATH-102": "archive_destination",
                 "JS-SAFE-XXE-101": "parse_document", "JS-SAFE-CODE-101": "profile_label"}
    if id_ in synthetic:
        file = "benchmarks/juice-shop-v20.2.0-v2/controls/expansion/synthetic/fixtures.py"
        tree = ast.parse(safe_input(file).read_text(encoding="utf-8"))
        node, = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == synthetic[id_]]
        return [{"file": file, "line_start": node.lineno, "line_end": node.end_lineno, "role": "sink"}]
    return [source_anchor(a) for a in record["source_anchors"]]


def render(target: Path) -> dict[str, str]:
    if any((DIRECTORY / name).exists() for name in OUTPUTS):
        raise ValueError("Freeze exists: create a new version, never overwrite it")
    protocol = load_protocol()
    positive_checks = validate_catalog(target)
    control_checks = validate_controls(target)
    positives, controls = corpus()
    cases, scopes, reviews, labels = [], [], [], []
    for record in sorted(positives + controls, key=lambda r: r["id"]):
        positive = record["expected"] == "vulnerable" if "expected" in record else False
        kind = "original" if positive else record["control_type"].removesuffix("_safe")
        family = record["category"] if positive else record["family"].replace("_", "-")
        family = next((canonical for canonical, aliases in FAMILY_ALIASES.items()
                       if family in [a.replace("_", "-") for a in aliases]), family)
        http = ([{k: a[k] for k in ("method", "endpoint", "parameter")} for a in record["http_anchors"]]
                if positive else http_controls(record["http_anchors"]))
        label, reason = SEVERITY.get(record["id"], (None,
            "Insufficient independently reviewed impact/precondition metrics; no inferred CVSS or scanner severity."))
        if record["id"] == "JS-FILE-001":
            http = [a for a in http if a["endpoint"] == "/ftp"]
        cases.append({"id": record["id"], "expected": "vulnerable" if positive else "safe",
            "family": family, "independence_group": record["independence_group"],
            "sample_kind": kind, "split": record["split"], "service": record["service"],
            "cwe": record.get("cwe"), "source_anchors": reviewed_anchors(record, target),
            "http_anchors": http, "expected_severity": label, "expected_context_priority": None})
        basis = "source_review" if positive else record["validation_basis"]
        runtime = record["runtime_eligible"] if positive else basis == "runtime"
        scopes.append({"id": record["id"], "root_cause_key": record["root_cause_key"],
            "truth_basis": basis, "runtime_eligible": runtime, "agent_capability_support": "not_assessed",
            "assertion_scope": record["root_cause_summary"] if positive else record["security_property"],
            "limitations": record["eligibility_reason"] if positive else record.get("limitations", record.get("safe_expected_behaviour", "Scoped control only")),
            "source_origin": "target_git_tree" if kind != "synthetic" else "separate_synthetic_fixture",
            "patch_reference": record.get("patch_reference"),
            "client_route": record.get("client_route"),
            "related_positive_case_ids": record.get("related_positive_case_ids", []),
            "evidence_reference": record.get("evidence_reference"),
            "grouping_limit": "Root-cause split isolation is not statistical independence of shared endpoints or defense mechanisms."})
        reviews.append({"id": record["id"], "decision": "accepted_scoped_source_or_property_truth",
            "basis": basis, "runtime_rerun_in_a04": False,
            "source_references": [a["file"] for a in record["source_anchors"]],
            "no_agent_result_used_as_truth": True})
        labels.append({"id": record["id"], "severity": label, "severity_reason": reason,
            "context_priority": None, "context_priority_reason":
            "No independent deployment/asset/authentication/blast-radius context frozen for this case; local lab exposure is not production business priority."})
    by_scope = {s["id"]: s for s in scopes}
    by_scope["JS-FILE-001"].update(assertion_scope="Public /ftp directory index without authentication; one concrete mount only.",
        limitations="A04 narrows A02 aggregate to FTP only. Encryption keys and logs are outside this frozen case; retain them as future unreviewed discoveries, not duplicates or negatives.")
    by_scope["JS-CRYPTO-001"]["limitations"] += " Source MD5 construction only: neither hash disclosure nor successful cracking is established."
    by_scope["JS-DATA-001"]["limitations"] += " Login SELECT *, user.data cache at routes/login.ts:23-25 and utils.queryResultToJson support field availability; no runtime disclosure was replayed."
    by_scope["JS-DATA-001"]["additional_provenance"] = [grounded_anchor(target, "routes/login.ts", 23, 25),
                                                              grounded_anchor(target, "routes/login.ts", 34, 36)]
    by_scope["JS-BIZ-002"]["limitations"] += " Runtime must use the requester's own basket to isolate coupon integrity from object authorization."
    for candidate, id_ in [("redirect", "JS-SAFE-REDIRECT-101"), ("nosql", "JS-SAFE-NOSQL-101")]:
        patch = make_patch(target, candidate)
        by_scope[id_]["anchor_version"] = "patched_application_source"
        by_scope[id_]["source_sha256_before"] = patch["source_sha256"]
        by_scope[id_]["patch_sha256"] = patch["patch_sha256"]
        by_scope[id_]["limitations"] += " Source anchors address the post-patch application, not the untouched original."
    dataset = {"schema_version": "benchmark.dataset.v2", "id": protocol.dataset_id,
        "target_commit": protocol.target_commit, "status": "frozen_a04",
        "family_aliases": FAMILY_ALIASES, "cases": cases}
    scope = {"schema_version": "benchmark.scope.a04.v1", "exhaustive": False,
        "source_population": "27 source-reviewed root causes, not all 116 challenges",
        "report_slices": ["split", "sample_kind", "truth_basis", "runtime_eligible"],
        "pooling": "Never pool original/patched/synthetic or source-only/runtime proof in primary runtime metrics.",
        "default_original_detection_case_ids": [c["id"] for c in cases if c["sample_kind"] == "original"],
        "default_original_runtime_case_ids": [s["id"] for s in scopes if s["runtime_eligible"] and
                                               next(c for c in cases if c["id"] == s["id"])["sample_kind"] == "original"],
        "holdout_limit": "Public target and previously inspected v1/SQL cases; frozen project labels, not unseen/generalization evidence.",
        "technical_preflight": "A07 must still validate A05 evidence/matcher and A06 scanner/environment locks before any producer call.",
        "cases": scopes}
    review = {"schema_version": "benchmark.review.a04.v1", "review_date": "2026-10-12",
        "input_commit": "e3e9ec53c8bd03d53495f5b164e213560446e9d2",
        "review_type": "automated_source_and_persisted_evidence_review",
        "human_independent_review": "not_performed",
        "second_automated_review": "Separate Dalton agent read-only source pass on 2026-10-12; concerns resolved by FTP-only scope, narrow patched/function anchors, MD5 impact limitation and login cache provenance. No human approval implied.",
        "new_runtime_cycles": 0, "positive_checks": positive_checks, "control_checks": control_checks,
        "negative_size_limit": "14 controls below approximately 20 target; no fabricated or unreviewed additions.",
        "cases": reviews}
    rubric = {"schema_version": "benchmark.rubric.a04.v1",
        "severity_definition": "Narrow source-impact ordinal HIGH: direct database disclosure, authentication bypass, unauthorized persistent update or administrative role acquisition. Not numeric CVSS3.1 and not official Juice Shop severity.",
        "severity_labels": ["HIGH"], "cvss_numeric_scores": "N/A: explicit justified CVSS3.1 metrics/calculator absent",
        "context_priority_definition": "Requires independently reviewed deployment facts: exposure, asset criticality, database/critical paths, auth and blast radius; do not self-grade production scorer output.",
        "null_policy": "N/A not safe/LOW and never in accuracy denominator; report reviewed/all and assessed/reviewed coverage separately.",
        "cases": labels}
    objects = {"ground_truth.yaml": dataset, "scope.yaml": scope, "review.yaml": review, "rubric.yaml": rubric}
    rendered = {name: yaml.safe_dump(value, sort_keys=False, allow_unicode=True, width=100)
                for name, value in objects.items()}
    inputs = {relative: digest(safe_input(relative).read_bytes()) for relative in source_inputs()}
    inputs.update({(DIRECTORY / name).relative_to(ROOT).as_posix(): digest(raw.encode())
                   for name, raw in rendered.items()})
    lock = {"schema_version": "benchmark.dataset.lock.a04.v1", "dataset_id": protocol.dataset_id,
        "target_commit": protocol.target_commit, "protocol_sha256": digest((DIRECTORY / "protocol.yaml").read_bytes()),
        "input_sha256": dict(sorted(inputs.items()))}
    rendered["dataset.lock.json"] = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    validate_membership(dataset, scope, rubric, protocol)
    return rendered


def validate_membership(dataset, scope, rubric, protocol):
    cases = dataset["cases"]
    ids = [c["id"] for c in cases]
    if len(set(ids)) != len(ids) or not ids:
        raise ValueError("Duplicate/empty frozen case IDs")
    units = [(c["independence_group"], c["sample_kind"]) for c in cases]
    if len(set(units)) != len(units):
        raise ValueError("Duplicate independent cause in sample slice")
    for name, artifact in [("scope", scope), ("rubric", rubric)]:
        if {c["id"] for c in artifact["cases"]} != set(ids) or len(artifact["cases"]) != len(ids):
            raise ValueError("Missing/duplicate " + name + " membership")
    for case in cases:
        if case["split"] != split_group(case["independence_group"], protocol.split):
            raise ValueError("Split drift")
        label = next(c for c in rubric["cases"] if c["id"] == case["id"])
        if (case["expected_severity"], case["expected_context_priority"]) != (label["severity"], label["context_priority"]):
            raise ValueError("Rubric label drift")
        if not case["source_anchors"] and not case["http_anchors"]:
            raise ValueError("Unanchored frozen case")
    originals = {c["id"] for c in cases if c["sample_kind"] == "original"}
    runtime = {c["id"] for c in scope["cases"] if c["runtime_eligible"]} & originals
    if set(scope["default_original_detection_case_ids"]) != originals or set(scope["default_original_runtime_case_ids"]) != runtime:
        raise ValueError("Scope denominator drift")


def validate(directory: Path = DIRECTORY, *, target: Path | None = None) -> dict:
    protocol = load_protocol()
    lock = json.loads((directory / "dataset.lock.json").read_text(encoding="utf-8"))
    if (lock["schema_version"] != "benchmark.dataset.lock.a04.v1" or
        lock["dataset_id"] != protocol.dataset_id or lock["target_commit"] != protocol.target_commit or
        lock["protocol_sha256"] != digest((DIRECTORY / "protocol.yaml").read_bytes())):
        raise ValueError("Dataset/protocol lock mismatch")
    required = set(source_inputs()) | {(DIRECTORY / name).relative_to(ROOT).as_posix()
                                      for name in OUTPUTS - {"dataset.lock.json"}}
    if set(lock["input_sha256"]) != required:
        raise ValueError("Freeze input membership changed")
    for relative, expected in lock["input_sha256"].items():
        current = safe_input(relative).read_bytes()
        # A04 records historical generators, not a requirement to run their old
        # implementation forever. Dataset/catalog/output bytes stay strict/local.
        raw = (historical_input(ROOT, relative)
               if relative.endswith(".py") and not relative.startswith("benchmarks/") else current)
        raw = frozen_presentation_input(ROOT, relative, raw)
        if digest(raw) != expected:
            raise ValueError("Frozen input digest mismatch: " + relative)
    dataset = read_yaml(directory / "ground_truth.yaml")
    if dataset["schema_version"] != "benchmark.dataset.v2" or dataset["status"] != "frozen_a04" or dataset["target_commit"] != protocol.target_commit:
        raise ValueError("Invalid frozen dataset")
    validate_membership(dataset, read_yaml(directory / "scope.yaml"), read_yaml(directory / "rubric.yaml"), protocol)
    if target is not None:
        validate_catalog(target)
        validate_controls(target)
    return {"status": "valid_frozen_a04", "case_count": len(dataset["cases"]),
        "positive_count": sum(c["expected"] == "vulnerable" for c in dataset["cases"]),
        "negative_count": sum(c["expected"] == "safe" for c in dataset["cases"]),
        "split": dict(Counter(c["split"] for c in dataset["cases"])),
        "inputs_bound": len(required), "target_source_checked": target is not None,
        "new_runtime_cycles": 0, "implementation_scope": "historical_generators",
        "historical_implementation_revision": BASELINE_REVISION,
        "current_implementation_verified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["render", "validate"])
    parser.add_argument("--target", type=Path)
    args = parser.parse_args()
    if args.command == "render":
        if args.target is None:
            parser.error("render requires --target")
        print(json.dumps(render(args.target), ensure_ascii=False))
    else:
        print(json.dumps(validate(target=args.target), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
