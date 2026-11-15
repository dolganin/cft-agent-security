"""Conservative source-anchored identity and lossless candidate deduplication."""
import json
import os
from collections import defaultdict
from collections.abc import Callable, Iterable
from hashlib import sha256
from pathlib import Path, PureWindowsPath

from schemas.finding import Finding, FindingObservation, FindingProvenance
from security.source_paths import normalize_source_path


def rule_family(rule: str) -> str:
    value = rule.lower().replace("_", "-")
    for family, markers in (
        ("anti-automation", ("juice.captcha.",)),
        ("authorization", ("juice.authorization.",)),
        ("open-redirect", ("redirect",)),
        ("path-traversal", ("path-traversal", "zip-slip", "archive-path")),
        # Check specific injection families before generic authentication rules:
        # e.g. ``demo-sql-injection.authentication`` is still SQL injection.
        ("nosql-injection", ("nosql-injection", "nosql-where")),
        ("sql-injection", ("sql-injection", "sequelize-injection", "sqli")),
        ("authentication", ("authn", "authentication", "credential")),
        ("code-evaluation", ("code-evaluation", "dynamic-code", "eval")),
        ("weak-cryptography", ("weak-cryptography", "weak-hash", "md5", "sha1")),
        ("ssrf", ("ssrf", "request-url")),
        ("xml-external-entities", ("xxe", "xml-external", "external-entities")),
        ("xss", ("xss", "dangerous-html", "dangerouslysetinnerhtml")),
        ("access-control", ("access-control", "idor", "broken-authorization")),
        ("business-logic", ("business-logic",)),
        ("file-validation", ("file-validation", "archive-path")),
        ("sensitive-data-exposure", ("sensitive-data",)),
        ("rate-limiting", ("rate-limiting",)),
        ("file-exposure", ("file-exposure", "directory-listing", "sensitive-directory")),
    ):
        if any(marker in value for marker in markers):
            return family
    return value


def _digest(value) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _source_key(item: Finding) -> str:
    provenance = item.provenance
    identity = {
        "version": 1, "service": item.service, "family": provenance.family,
        "file": item.file, "start": item.line_start, "end": item.line_end or item.line_start,
        "file_sha256": provenance.file_sha256, "anchor": provenance.anchor_sha256,
    }
    if provenance.anchor_status == "location_only":
        identity["unbound_observation"] = {
            "source": item.source, "rule": item.rule_id,
            "title": item.title, "description": item.description,
        }
    return _digest(identity)


def normalize_finding(
    finding: Finding, *, repository_root: str | Path | None = None,
    service_resolver: Callable[[str], str | None] | None = None,
    observation: FindingObservation | None = None,
) -> Finding:
    file = normalize_source_path(finding.file, repository_root)
    service = service_resolver(file) if service_resolver else finding.service
    family = rule_family(finding.rule_id)
    previous = finding.provenance
    origins = list(previous.observations) if previous else []
    if not origins:
        origins = [observation or FindingObservation(
            source_id=finding.id, source=finding.source, rule_id=finding.rule_id,
            original_file=finding.file, title=finding.title, description=finding.description,
            line_start=finding.line_start, line_end=finding.line_end, severity=finding.severity,
        )]
    start, end = finding.line_start, finding.line_end or finding.line_start
    if start is not None and (start < 1 or end < start):
        raise ValueError("Invalid finding source range")
    file_digest = anchor_digest = None
    if (repository_root is not None
            and (os.name == "nt" or not PureWindowsPath(str(repository_root)).drive)):
        path = Path(repository_root).resolve() / file
        try:
            if not path.is_file():
                raise FileNotFoundError
            with path.open("rb") as stream:
                raw = stream.read(1_048_577)
            if len(raw) <= 1_048_576 and b"\0" not in raw:
                file_digest = sha256(raw).hexdigest()
                lines = raw.splitlines()
                if start and end <= len(lines) and end - start < 160:
                    anchor_digest = sha256(b"\n".join(lines[start - 1:end])).hexdigest()
        except (FileNotFoundError, IsADirectoryError, PermissionError):
            pass
    # Do not silently rebind an archived/provenanced finding to changed source bytes.
    if (previous and repository_root is not None and previous.file_sha256 is not None
            and previous.file_sha256 != file_digest):
        raise ValueError("Finding source digest changed; scan again")
    if previous and repository_root is None:
        file_digest, anchor_digest = previous.file_sha256, previous.anchor_sha256
    identity = {
        "version": 1, "service": service, "family": family, "file": file,
        "start": start, "end": end, "file_sha256": file_digest, "anchor": anchor_digest,
    }
    if anchor_digest is None:
        identity["unbound_observation"] = {
            "source": finding.source, "rule": finding.rule_id,
            "title": finding.title, "description": finding.description,
        }
    spans = {(o.column_start, o.column_end) for o in origins if o.column_start is not None}
    columns = next(iter(spans)) if len(spans) == 1 else None
    provenance = FindingProvenance(
        family=family, fingerprint=_digest({"anchor": _digest(identity), "columns": columns}),
        normalized_file=file,
        file_sha256=file_digest, anchor_sha256=anchor_digest,
        anchor_status="source_bound" if anchor_digest else "location_only",
        aliases=list(dict.fromkeys([finding.id, *(previous.aliases if previous else []),
                                   *(item.source_id for item in origins)])),
        observations=origins,
    )
    return finding.model_copy(update={"file": file, "service": service, "provenance": provenance})


def deduplicate_findings(findings: Iterable[Finding]) -> tuple[list[Finding], int]:
    findings = list(findings)
    buckets = defaultdict(list)
    result: list[Finding] = []
    for item in findings:
        # No anchor means insufficient identity; even matching titles are not merged.
        if item.provenance is None or item.line_start is None:
            result.append(item)
        else:
            buckets[_source_key(item)].append(item)
    for bucket in buckets.values():
        # Preserve distinct sinks on the same line if scanner columns distinguish them.
        precise = {
            (o.column_start, o.column_end) for item in bucket
            for o in item.provenance.observations if o.column_start is not None
        }
        groups = defaultdict(list)
        for item in bucket:
            spans = {(o.column_start, o.column_end) for o in item.provenance.observations
                     if o.column_start is not None}
            key = next(iter(spans)) if len(spans) == 1 else None
            if key is None and len(precise) == 1:
                key = next(iter(precise))
            groups[key].append(item)
        for key, group in groups.items():
            # A columnless candidate cannot pick among multiple concrete sinks.
            if key is None and len(precise) > 1:
                result.extend(group)
                continue
            primary = min(group, key=lambda f: (f.source == "model_scout", f.id))
            observations = {}
            aliases = set()
            for item in group:
                aliases.update(item.provenance.aliases)
                for origin in item.provenance.observations:
                    observations[origin.model_dump_json()] = origin
            provenance = primary.provenance.model_copy(update={
                "aliases": sorted(aliases),
                "observations": [observations[k] for k in sorted(observations)],
                # Column identity participates in the final stable key, not the coarse bucket.
                "fingerprint": _digest({"anchor": _source_key(primary), "columns": key}),
            })
            result.append(primary.model_copy(update={"provenance": provenance}))
    id_counts = defaultdict(int)
    for item in result:
        id_counts[item.id] += 1
    unique = []
    used = set()
    for item in result:
        if id_counts[item.id] > 1 and item.provenance:
            base = item.id + "-" + item.provenance.fingerprint[:16]
            identifier, ordinal = base, 1
            while identifier in used:
                ordinal += 1
                identifier = f"{base}-{ordinal}"
            item = item.model_copy(update={"id": identifier})
        used.add(item.id)
        unique.append(item)
    result = unique
    # Stable sort for scanner/model order independence; IDs remain historical primary IDs.
    result.sort(key=lambda f: (f.file, f.line_start or 0, f.provenance.family if f.provenance else f.rule_id, f.id))
    return result, len(findings) - len(result)
