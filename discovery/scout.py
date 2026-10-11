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
