"""Нормализуем model scout до того, как кандидат увидит основной pipeline."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256
from pathlib import Path

from sast.identity import deduplicate_findings, normalize_finding, rule_family
from schemas.discovery import ProjectDiscoveryResult
from schemas.finding import Finding, FindingObservation
from schemas.scout import CandidateFinding
from security.source_paths import normalize_source_path


def validate_scout_candidates(
    candidates: Iterable[CandidateFinding],
    discovery: ProjectDiscoveryResult,
) -> list[CandidateFinding]:
    """Scout не может сослаться на файл вне trusted discovery inventory."""
    known_files = set(discovery.project_files)
    valid: list[CandidateFinding] = []
    for candidate in candidates:
        try:
            file = normalize_source_path(candidate.file, discovery.repository_root)
            paths = {normalize_source_path(path, discovery.repository_root)
                     for path in candidate.provenance_paths}
        except ValueError:
            continue
        if file not in known_files or not paths.issubset(known_files):
            continue
        valid.append(candidate)
    return valid


def merge_scout_candidates(
    findings: list[Finding], candidates: Iterable[CandidateFinding], *,
    service_resolver=None, repository_root: str | Path | None = None,
) -> tuple[list[Finding], int]:
    """Merge unambiguous exact anchors, preserving every scanner/model observation."""
    merged = [normalize_finding(item, repository_root=repository_root,
                                service_resolver=service_resolver) for item in findings]
    for candidate in candidates:
        family = rule_family(candidate.rule_id)
        start = candidate.line_start
        end = candidate.line_end or start
        file = normalize_source_path(candidate.file, repository_root)
        identity = f"{family}:{file}:{start}:{end}"
        finding = candidate.to_finding(
            finding_id="model-scout-" + sha256(identity.encode()).hexdigest()[:20],
        )
        finding.description += "\nScout rationale and verification strategy: " + candidate.rationale
        merged.append(normalize_finding(
            finding, repository_root=repository_root, service_resolver=service_resolver,
            observation=FindingObservation(
                source_id=finding.id, source=candidate.source, rule_id=candidate.rule_id,
                original_file=candidate.file, title=candidate.title, description=candidate.description,
                line_start=start, line_end=end, rationale=candidate.rationale,
                provenance_paths=[normalize_source_path(path, repository_root)
                                  for path in candidate.provenance_paths],
            ),
        ))
    return deduplicate_findings(merged)


def coalesce_bound_scout_findings(findings: list[Finding], profile) -> tuple[list[Finding], int]:
    """Join a scout observation only to one uniquely matching scanner sink.

    Different range ends are permitted only when the same start, file digest,
    family and operator-resolved route agree. Distinct scanner sinks and unbound
    observations stay separate. The primary anchor and every origin are retained.
    """
    from security.verification_binding import resolve_binding

    def key(finding):
        provenance = finding.provenance
        if (provenance is None or provenance.anchor_status != "source_bound"
                or not provenance.file_sha256 or finding.line_start is None):
            return None
        resolution = resolve_binding(profile, finding)
        binding = resolution.binding
        if resolution.status != "bound" or binding is None:
            return None
        return (finding.file, finding.line_start, provenance.file_sha256,
                provenance.family, finding.service, binding.route_id,
                binding.source_snapshot, binding.map_sha256)

    def columns(finding):
        return {(o.column_start, o.column_end) for o in finding.provenance.observations
                if o.column_start is not None}

    originals = {item.id: item for item in findings if item.source != "model_scout"}
    by_key = {}
    for item in originals.values():
        identity = key(item)
        if identity is not None:
            by_key.setdefault(identity, []).append(item.id)
    retained, merged = [], 0
    for item in findings:
        if item.source != "model_scout":
            continue
        candidates = by_key.get(key(item), [])
        if len(candidates) != 1:
            retained.append(item)
            continue
        primary = originals[candidates[0]]
        if columns(item) and columns(primary) and columns(item) != columns(primary):
            retained.append(item)
            continue
        origins = {o.model_dump_json(): o for f in [primary, item]
                   for o in f.provenance.observations}
        provenance = primary.provenance.model_copy(update={
            "aliases": sorted(set(primary.provenance.aliases + item.provenance.aliases)),
            "observations": [origins[k] for k in sorted(origins)],
        })
        originals[primary.id] = primary.model_copy(update={"provenance": provenance})
        merged += 1
    result = [*originals.values(), *retained]
    result.sort(key=lambda item: (item.file, item.line_start or 0, item.id))
    return result, merged
