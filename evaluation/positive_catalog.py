"""Read-only A02 extraction/validation against pinned Git bytes. Never scores runs."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path, PurePosixPath

import yaml

from discovery.express_routes import build_express_source_map
from evaluation.benchmark_protocol import ROOT, load_protocol, split_group
from schemas.benchmark_catalog import CatalogAnchor, ExcludedCatalog, PositiveCatalog
from schemas.discovery import ProjectDiscoveryResult
from schemas.source_map import ExpressSourceMap
from schemas.target import TargetProfile

CATALOG = ROOT / "benchmarks/juice-shop-v20.2.0-v2/catalog"
ANNOTATION = re.compile(r"(?:^|//|#|<!--)\s*vuln-code-snippet\s+(start|vuln-line|end)\s+(.*)")
METADATA = "data/static/challenges.yml"
TEXT_SUFFIXES = {".ts", ".js", ".html", ".yml", ".yaml", ".json", ".md", ".pug", ".tf", ".sol"}


def git(target: Path, *args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(target), *args], timeout=30)


def snapshot(target: Path, commit: str) -> dict[str, bytes]:
    """Reject dirty/foreign checkout or any byte mismatch to the immutable Git tree."""
    target = target.resolve(strict=True)
    if git(target, "rev-parse", "HEAD").decode().strip() != commit:
        raise ValueError("A02 requires the exact protocol target commit")
    if git(target, "status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("A02 requires a clean target checkout")
    files = {}
    for record in git(target, "ls-tree", "-rz", commit).split(b"\0"):
        if not record:
            continue
        metadata, name = record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split()
        relative = name.decode("utf-8")
        if mode not in {"100644", "100755"} or kind != "blob":
            raise ValueError("Linked/submodule target source is not supported")
        path = target / relative
        if not path.resolve(strict=True).is_relative_to(target):
            raise ValueError("Target source escapes checkout")
        current = path
        while current != target:
            if current.is_symlink():
                raise ValueError("Linked target source is not supported")
            current = current.parent
        raw = path.read_bytes()
        blob = b"blob " + str(len(raw)).encode() + b"\0" + raw
        if hashlib.sha1(blob).hexdigest() != oid:
            raise ValueError("Target source bytes differ from pinned Git blob: " + relative)
        if PurePosixPath(relative).suffix in TEXT_SUFFIXES or relative == "LICENSE":
            files[relative] = raw
    return files


def region(raw: bytes, start: int, end: int) -> str:
    lines = raw.decode("utf-8").splitlines()
    if not 1 <= start <= end <= len(lines):
        raise ValueError("Catalog anchor range exceeds source")
    return "\n".join(lines[start - 1:end]) + "\n"


def anchor(files, file, start, end, role, tokens) -> dict:
    raw = files[file]
    return CatalogAnchor(
        file=file, line_start=start, line_end=end, role=role,
        file_sha256=hashlib.sha256(raw).hexdigest(),
        region_sha256=hashlib.sha256(region(raw, start, end).encode()).hexdigest(),
        required_tokens=tokens,
    ).model_dump()


def challenge_metadata(files: dict[str, bytes]) -> dict:
    items = yaml.safe_load(files[METADATA])
    if not isinstance(items, list) or not items:
        raise ValueError("Challenge metadata must be a nonempty list")
    indexed = {}
    lines = files[METADATA].decode("utf-8").splitlines()
    separators = [i for i, line in enumerate(lines, 1) if line == "-"]
    for item in items:
        key = item["key"]
        if key in indexed:
            raise ValueError("Duplicate challenge key")
        key_line, = [i for i, line in enumerate(lines, 1)
                     if re.fullmatch(r"\s*key:\s*" + re.escape(key) + r"\s*", line)]
        start = max((i for i in separators if i <= key_line), default=1)
        end = min((i - 1 for i in separators if i > key_line), default=len(lines))
        indexed[key] = {
            "key": key, "name": item["name"], "category": item["category"],
            "description": item["description"], "tags": item.get("tags", []),
            "disabled_environments": item.get("disabledEnv", []),
            "metadata_anchor": anchor(files, METADATA, start, end, "provenance", ["key: " + key]),
        }
    return indexed


def extract_annotations(files: dict[str, bytes], keys: set[str]) -> dict:
    result = {key: {"spans": [], "vulnerable_lines": []} for key in sorted(keys)}
    for file, raw in sorted(files.items()):
        if not (file == "server.ts" or file.startswith(("routes/", "lib/", "models/", "frontend/src/", "infrastructure/"))):
            continue
        opened: dict[str, list[int]] = {}
        for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
            match = ANNOTATION.search(line)
            if not match:
                continue
            operation, names = match.groups()
            known = [key for key in names.split() if key in keys]
            for key in known:
                if operation == "start":
                    opened.setdefault(key, []).append(number)
                elif operation == "vuln-line":
                    result[key]["vulnerable_lines"].append(
                        anchor(files, file, number, number, "provenance", [key]))
                elif opened.get(key):
                    start = opened[key].pop()
                    result[key]["spans"].append(
                        anchor(files, file, start, number, "provenance", [key]))
        if any(opened.values()):
            raise ValueError("Unclosed challenge annotation: " + file)
    return result


def source_map(target: Path, files: dict[str, bytes]) -> ExpressSourceMap:
    # Reuse the production bounded registration parser. Raw evaluator reads above
    # deliberately retain truth annotations; they are never supplied to Scout.
    paths = sorted(f for f in files if f == "server.ts" or f.startswith(("routes/", "lib/")))
    return build_express_source_map(ProjectDiscoveryResult(repository_root=target, project_files=paths))


def extract_candidates(target: Path) -> dict:
    protocol = load_protocol()
    files = snapshot(target, protocol.target_commit)
    metadata = challenge_metadata(files)
    annotations = extract_annotations(files, set(metadata))
    mapping = source_map(target, files)
    references = {key: [] for key in metadata}
    pattern = re.compile(r"\b(?:" + "|".join(re.escape(k) for k in sorted(metadata)) + r")\b")
    for file, raw in sorted(files.items()):
        if not (file == "server.ts" or file.startswith((
            "routes/", "lib/", "models/", "frontend/src/", "data/", "test/", "infrastructure/",
        ))) or file == METADATA:
            continue
        if "codefixes" in PurePosixPath(file).parts:
            continue
        for number, line in enumerate(raw.decode("utf-8").splitlines(), 1):
            for key in sorted(set(pattern.findall(line))):
                references[key].append({"file": file, "line": number,
                                        "kind": "upstream_test" if file.startswith("test/") or ".spec." in file else "source_code"})
    candidates = []
    for key, item in sorted(metadata.items()):
        paths = {ref["file"] for ref in references[key]}
        paths.update(a["file"] for a in annotations[key]["spans"])
        routes = [route.id for route in mapping.routes
                  if set(route.handler_files).intersection(paths)
                  or any(a["file"] == route.file and route.line_start <= a["line_start"] <= route.line_end
                         for a in annotations[key]["vulnerable_lines"])]
        candidates.append({**item, "review_status": "generated_unreviewed_not_truth",
                           "annotations": annotations[key], "references": references[key],
                           "route_ids": sorted(routes)})
    return {
        "schema_version": "benchmark.candidates.a02.v1", "target_commit": protocol.target_commit,
        "source_manifest": {f: hashlib.sha256(raw).hexdigest() for f, raw in sorted(files.items())},
        "source_map": mapping.model_dump(mode="json"), "candidates": candidates,
        "limitations": ["One candidate per challenge, not one positive per challenge.",
                        "Express inventory is bounded and omits dynamic Finale/client routes.",
                        "No scanner/model judgment, runtime execution or reviewed labels in generation."],
    }


def validate_anchor(a: CatalogAnchor, files: dict[str, bytes]):
    if a.file not in files:
        raise ValueError("Missing pinned source anchor file: " + a.file)
    raw = files[a.file]
    text = region(raw, a.line_start, a.line_end)
    if hashlib.sha256(raw).hexdigest() != a.file_sha256 or hashlib.sha256(text.encode()).hexdigest() != a.region_sha256:
        raise ValueError("Catalog source digest mismatch: " + a.file)
    if not all(token and token in text for token in a.required_tokens):
        raise ValueError("Expected source region tokens absent: " + a.file)


def validate_http(a, mapping: ExpressSourceMap, files):
    validate_anchor(a.registration, files)
    if a.basis == "direct_express":
        valid = any(r.method.upper() in {a.method, "ALL"} and r.path == a.endpoint
                    and r.file == a.registration.file
                    and a.registration.line_start <= r.line_start <= a.registration.line_end
                    for r in mapping.routes)
    elif a.basis == "middleware_mount":
        valid = any(m.mount_path == a.endpoint and m.path_is_static
                    and m.file == a.registration.file
                    and a.registration.line_start <= m.line_start <= a.registration.line_end
                    for m in mapping.middleware_mounts)
    else:
        text = region(files[a.registration.file], a.registration.line_start, a.registration.line_end)
        name_match = re.fullmatch(r"/api/([A-Za-z]+)s(?:/:id)?", a.endpoint)
        # Validate the exact upstream Finale resource declaration, not a new route
        # matcher. The API generation anchor and model membership are required.
        valid = bool(name_match and f"name: '{name_match[1]}'" in text
                     and "finale.resource({" in text
                     and "endpoints: [`/api/${name}s`, `/api/${name}s/:id`]" in text)
    if not valid:
        raise ValueError("HTTP anchor has no supporting registration: " + a.endpoint)


def validate_catalog(target: Path, directory: Path = CATALOG) -> dict:
    if directory.resolve().is_relative_to(target.resolve()):
        raise ValueError("Evaluator catalog must stay outside target discovery")
    protocol = load_protocol()
    files = snapshot(target, protocol.target_commit)
    generated = extract_candidates(target)
    saved = yaml.safe_load((directory / "candidates.generated.yaml").read_text(encoding="utf-8"))
    if generated != saved:
        raise ValueError("Generated candidate catalog is not reproducible from pinned sources")
    positives = PositiveCatalog.model_validate(yaml.safe_load(
        (directory / "positives.reviewed.yaml").read_text(encoding="utf-8")))
    excluded = ExcludedCatalog.model_validate(yaml.safe_load(
        (directory / "excluded.yaml").read_text(encoding="utf-8")))
    if positives.target_commit != protocol.target_commit or excluded.target_commit != protocol.target_commit:
        raise ValueError("Catalog target commit mismatch")
    protocol_hash = hashlib.sha256((ROOT / "benchmarks/juice-shop-v20.2.0-v2/protocol.yaml").read_bytes()).hexdigest()
    if positives.protocol_sha256 != protocol_hash:
        raise ValueError("Catalog protocol digest mismatch")
    metadata = {item["key"]: item for item in generated["candidates"]}
    mapping = ExpressSourceMap.model_validate(generated["source_map"])
    profile = TargetProfile.from_yaml(ROOT / protocol.baseline.profile, repository_path_override=target)
    for case in positives.cases:
        if case.service not in profile.services:
            raise ValueError("Unknown catalog service")
        if not set(case.challenge_keys).issubset(metadata):
            raise ValueError("Unknown challenge reference")
        if case.split != split_group(case.independence_group, protocol.split):
            raise ValueError("Catalog split differs from the locked A01 helper")
        for a in case.source_anchors:
            validate_anchor(a, files)
            if profile.resolve_service(a.file) != case.service:
                raise ValueError("Catalog anchor belongs to another service")
        for provenance in case.provenance:
            validate_anchor(provenance.anchor, files)
            if provenance.kind == "source_annotation" and "vuln-code-snippet" not in region(
                files[provenance.anchor.file], provenance.anchor.line_start, provenance.anchor.line_end
            ):
                raise ValueError("Annotation provenance lacks an actual source annotation")
            if provenance.kind == "upstream_test" and not (
                provenance.anchor.file.startswith("test/") or ".spec." in provenance.anchor.file
            ):
                raise ValueError("Upstream-test provenance must reference a test source")
        if not any(p.kind == "source_code" for p in case.provenance):
            raise ValueError("Reviewed positive requires source-code provenance")
        primary_metadata = metadata[case.primary_candidate]["metadata_anchor"]
        if not any(p.kind == "challenge_metadata" and p.anchor.model_dump() == primary_metadata
                   for p in case.provenance):
            raise ValueError("Primary challenge metadata provenance is missing")
        for a in case.http_anchors:
            validate_http(a, mapping, files)
        if case.runtime_eligible and any("Docker" in metadata[key]["disabled_environments"]
                                         for key in case.challenge_keys):
            raise ValueError("Docker-disabled case cannot be runtime eligible in this catalog")
    primary = {c.primary_candidate for c in positives.cases}
    excluded_keys = [entry.candidate_key for entry in excluded.exclusions]
    if len(excluded_keys) != len(set(excluded_keys)) or set(excluded_keys) & primary:
        raise ValueError("Duplicate exclusion or selected primary also excluded")
    if primary | set(excluded_keys) != set(metadata):
        raise ValueError("Every generated candidate requires selected/excluded disposition")
    by_id = {c.id: c for c in positives.cases}
    for entry in excluded.exclusions:
        if not set(entry.represented_by).issubset(by_id):
            raise ValueError("Exclusion refers to an unknown selected case")
        if entry.reason in {"duplicate_root_cause", "same_independence_group_as_existing_case"} and (
            not entry.represented_by or not all(entry.candidate_key in by_id[cid].challenge_keys
                                               for cid in entry.represented_by)
        ):
            raise ValueError("Duplicate exclusion requires a reviewed cause relationship")
    return {"candidates": len(metadata), "selected_positives": len(positives.cases),
            "families": dict(sorted(Counter(c.category for c in positives.cases).items())),
            "split": dict(Counter(c.split for c in positives.cases)),
            "family_split": {family: dict(Counter(c.split for c in positives.cases if c.category == family))
                             for family in sorted({c.category for c in positives.cases})},
            "runtime_eligible": sum(c.runtime_eligible for c in positives.cases),
            "detection_only": sum(not c.runtime_eligible and c.detection_only_eligible for c in positives.cases),
            "excluded_reasons": dict(sorted(Counter(e.reason for e in excluded.exclusions).items())),
            "reviewer_status": positives.reviewer_status}


def write_yaml(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(yaml.safe_dump(value, sort_keys=False, allow_unicode=True, width=100).encode("utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["extract", "validate"])
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, default=CATALOG)
    args = parser.parse_args()
    if args.catalog.resolve().is_relative_to(args.target.resolve()):
        raise ValueError("Evaluator catalog must stay outside target discovery")
    if args.operation == "extract":
        generated = extract_candidates(args.target.resolve())
        write_yaml(args.catalog / "candidates.generated.yaml", generated)
        print(f"A02 generated unreviewed candidates: {len(generated['candidates'])}")
    else:
        print(json.dumps(validate_catalog(args.target.resolve(), args.catalog), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
