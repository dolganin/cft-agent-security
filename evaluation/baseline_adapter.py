"""Raw scanner to A05 BenchmarkObservationV2 JSON. No truth or verifier claims."""
from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from security.source_paths import normalize_source_path

# Explicit CWE families, independent of benchmark labels. Ambiguous/unknown CWEs
# retain their scanner identity instead of guessing from a finding's title.
CWE_FAMILIES = {
    22: "path-traversal", 23: "path-traversal", 36: "path-traversal",
    78: "code-injection", 94: "code-injection", 95: "code-injection",
    79: "xss", 80: "xss", 89: "sql-injection", 90: "nosql-injection",
    200: "sensitive-data-exposure", 209: "sensitive-data-exposure",
    215: "sensitive-data-exposure", 548: "file-exposure",
    285: "authorization", 639: "authorization", 862: "authorization",
    863: "authorization", 915: "authorization",
    287: "authentication", 306: "authentication", 307: "authentication",
    620: "authentication", 640: "authentication",
    601: "open-redirect", 611: "xxe", 918: "ssrf",
    327: "weak-cryptography", 328: "weak-cryptography", 330: "weak-cryptography",
    400: "denial-of-service", 502: "deserialization",
    798: "hardcoded-secret", 321: "hardcoded-secret",
}


def family(cwes, fallback):
    if not isinstance(cwes, list):
        cwes = [cwes]
    numbers = set()
    for value in cwes:
        match = re.match(r"^(?:CWE-)?(\d+)(?:\D|$)", str(value))
        if match:
            numbers.add(int(match[1]))
    families = {CWE_FAMILIES[n] for n in numbers if n in CWE_FAMILIES}
    return next(iter(families)) if len(families) == 1 else fallback


def identity(source, payload):
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:24]
    return f"{source}:{digest}"


def observations_semgrep(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("results"), list):
        raise TypeError("Missing Semgrep results")
    observations = {}
    for item in raw["results"]:
        path = item["path"].replace("\\", "/")
        path = path.removeprefix("/src/")
        path = normalize_source_path(path)
        start, end = item["start"]["line"], item["end"]["line"]
        if type(start) is not int or type(end) is not int or start < 1 or end < start:
            raise ValueError("Invalid Semgrep source range")
        rule = item["check_id"]
        observed = {
            "id": identity("sast", [rule, path, item["start"], item["end"]]),
            "source": "semgrep", "family": family(
                item.get("extra", {}).get("metadata", {}).get("cwe", []), rule
            ),
            "service": "juice", "sample_kind": "original", "source_file": path,
            "line_start": start, "line_end": end,
            "verification": "not_run", "evidence_backed": False,
            "evidence": ["sast/raw.json"],
        }
        observations[observed["id"]] = observed
    return sorted(observations.values(), key=lambda o: o["id"])


def observations_zap(raw):
    if not isinstance(raw, dict) or not isinstance(raw.get("alerts"), list):
        raise TypeError("Missing ZAP alerts")
    observations = {}
    rejected = []
    for item in raw["alerts"]:
        parsed = urlsplit(item.get("url", ""))
        if parsed.scheme != "http" or parsed.netloc != "juice:3000":
            rejected.append(item.get("id", "unknown"))
            continue
        plugin = str(item["pluginId"])
        method = item.get("method", "").upper()
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            method = None
        observed = {
            "id": identity("dast", [plugin, item.get("alertRef"), item.get("url"),
                                      method, item.get("param", ""), item.get("attack", "")]),
            "source": "zap", "family": family(item.get("cweid"), "zap-" + plugin),
            "service": "juice", "sample_kind": "original",
            "http_endpoint": parsed.path or "/", "http_method": method,
            "http_parameter": item.get("param") or None,
            "verification": "not_run", "evidence_backed": False,
            "evidence": ["dast/raw.json"],
        }
        observations[observed["id"]] = observed
    return sorted(observations.values(), key=lambda o: o["id"]), rejected


def combined(sast, dast):
    """Retain both anchors. A05 deduplicates at case-level, never by title."""
    items = {o["id"]: o for o in [*sast, *dast]}
    if len(items) != len(sast) + len(dast):
        raise ValueError("Observation IDs collide")
    return sorted(items.values(), key=lambda o: o["id"])
