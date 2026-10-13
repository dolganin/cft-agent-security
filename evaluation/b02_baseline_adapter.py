"""B02-only enrichment over the frozen v1/A06 Semgrep observation adapter."""
from __future__ import annotations

from evaluation.baseline_adapter import identity, observations_semgrep
from sast.identity import rule_family
from sast.profiles import classify_signal_type
from security.source_paths import normalize_source_path


def observations_semgrep_b02(raw: dict) -> list[dict]:
    """Preserve legacy adaptation, adding family/CWE/signal tags for B02 rules."""
    legacy = observations_semgrep(raw)
    by_id = {item["id"]: dict(item) for item in legacy}
    for finding in raw["results"]:
        if not isinstance(finding, dict):
            continue
        path = normalize_source_path(str(finding["path"]).replace("\\", "/").removeprefix("/src/"))
        rule = str(finding["check_id"])
        identifier = identity("sast", [rule, path, finding["start"], finding["end"]])
        observation = by_id.get(identifier)
        if observation is None:
            continue
        metadata = finding.get("extra", {}).get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}
        if rule.startswith("cft."):
            observation["family"] = rule_family(rule)
        observation["signal_type"] = classify_signal_type(rule, path, metadata)
        cwe = metadata.get("cwe", [])
        observation["cwe"] = [str(item) for item in cwe] if isinstance(cwe, list) else [str(cwe)]
    return sorted(by_id.values(), key=lambda item: item["id"])
