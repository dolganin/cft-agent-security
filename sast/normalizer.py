from collections.abc import Callable
from pathlib import Path, PurePosixPath

from sast.identity import deduplicate_findings, normalize_finding
from schemas.finding import Finding, FindingObservation
from security.source_paths import normalize_source_path

ServiceResolver = Callable[[str], str | None]


def normalize_semgrep_result(
    raw: dict,
    *,
    service_resolver: ServiceResolver | None = None,
    repository_root: str | Path | None = None,
    scanner_root: str | None = None,
) -> Finding:
    extra = raw.get("extra", {})
    start = raw.get("start", {})
    end = raw.get("end", {})

    check_id = str(raw.get("check_id", "unknown"))
    original_path = str(raw.get("path", ""))
    path = original_path
    if scanner_root is not None and path.startswith("/"):
        # A Docker mount root is a POSIX namespace even when the host is Windows.
        # Never resolve it through the host filesystem or silently strip any root.
        mount = PurePosixPath(scanner_root)
        if not mount.is_absolute() or ".." in mount.parts:
            raise ValueError("Scanner root must be a trusted absolute POSIX path")
        try:
            path = PurePosixPath(path).relative_to(mount).as_posix()
        except ValueError as exc:
            raise ValueError("Source path is outside the trusted scanner root") from exc
    path = normalize_source_path(path, repository_root)
    line_start = start.get("line")
    stable_location = line_start if line_start is not None else 0
    message = str(extra.get("message", ""))

    # Semgrep не знает архитектуру проекта, service приходит из TargetProfile
    service = service_resolver(path) if service_resolver is not None else None

    finding = Finding(
        id=f"{check_id}:{path}:{stable_location}",
        source="semgrep",
        rule_id=check_id,
        title=message or check_id or "Semgrep finding",
        description=message,
        file=path,
        line_start=line_start,
        line_end=end.get("line"),
        severity=extra.get("severity"),
        service=service,
    )
    return normalize_finding(
        finding, repository_root=repository_root, service_resolver=service_resolver,
        observation=FindingObservation(
            source_id=f"{check_id}:{original_path}:{stable_location}", source="semgrep",
            rule_id=check_id, original_file=original_path, title=finding.title,
            description=message, line_start=line_start, line_end=end.get("line"),
            column_start=start.get("col"), column_end=end.get("col"), severity=finding.severity,
        ),
    )


def normalize_semgrep_payload(
    payload: dict,
    *,
    service_resolver: ServiceResolver | None = None,
    repository_root: str | Path | None = None,
    scanner_root: str | None = None,
) -> list[Finding]:
    results = payload.get("results", [])
    if not isinstance(results, list):
        raise TypeError("Semgrep JSON field 'results' must be a list")
    findings = [
        normalize_semgrep_result(item, service_resolver=service_resolver,
                                 repository_root=repository_root, scanner_root=scanner_root)
        for item in results
        if isinstance(item, dict)
    ]
    return deduplicate_findings(findings)[0]
