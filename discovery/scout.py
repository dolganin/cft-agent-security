"""Нормализуем model scout до того, как кандидат увидит основной pipeline."""

from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256

from schemas.discovery import ProjectDiscoveryResult
from schemas.finding import Finding
from schemas.scout import CandidateFinding


def validate_scout_candidates(
    candidates: Iterable[CandidateFinding],
    discovery: ProjectDiscoveryResult,
) -> list[CandidateFinding]:
    """Scout не может сослаться на файл вне trusted discovery inventory."""
    known_files = set(discovery.project_files)
    valid: list[CandidateFinding] = []
    for candidate in candidates:
        paths = set(candidate.provenance_paths)
        if candidate.file not in known_files or not paths.issubset(known_files):
            continue
        valid.append(candidate)
    return valid


def rule_family(rule: str) -> str:
    value = rule.lower().replace("_", "-")
    if "redirect" in value:
        return "open-redirect"
    if any(marker in value for marker in ("path-traversal", "zip-slip")):
        return "path-traversal"
    if any(marker in value for marker in ("authn", "authentication", "credential")):
        return "authentication"
    for family, markers in (
        ("sql-injection", ("sql-injection", "sequelize-injection", "sqli")),
        ("xss", ("xss", "dangerous-html", "dangerouslysetinnerhtml")),
        ("access-control", ("access-control", "idor", "broken-authorization")),
        ("file-exposure", ("file-exposure", "directory-listing", "sensitive-directory")),
    ):
        if any(marker in value for marker in markers):
            return family
    return value


def merge_scout_candidates(
    findings: list[Finding], candidates: Iterable[CandidateFinding], *,
    service_resolver=None,
) -> tuple[list[Finding], int]:
    """Merge only matching family and overlapping source anchors, preserving SAST."""
    merged = list(findings)
    duplicates = 0
    for candidate in candidates:
        family = rule_family(candidate.rule_id)
        start = candidate.line_start
        end = candidate.line_end or start
        duplicate = any(
            item.file == candidate.file and rule_family(item.rule_id) == family
            and start is not None and item.line_start is not None
            and start <= (item.line_end or item.line_start)
            and item.line_start <= end
            for item in merged
        )
        if duplicate:
            duplicates += 1
            continue
        identity = f"{family}:{candidate.file}:{start}:{end}"
        finding = candidate.to_finding(
            finding_id="model-scout-" + sha256(identity.encode()).hexdigest()[:20],
        )
        finding.description += "\nScout rationale and verification strategy: " + candidate.rationale
        finding.service = service_resolver(candidate.file) if service_resolver else None
        merged.append(finding)
    return merged, duplicates
