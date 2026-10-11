"""Application-owned verification candidates; never infer target URLs from the LLM."""
import json
from hashlib import sha256
from pathlib import Path

from discovery.scout import rule_family
from schemas.target import TargetArtifact
from security.source_paths import normalize_source_path


def register_source_artifacts(profile, findings, repository):
    root = Path(repository).resolve()
    artifacts = dict(profile.artifacts)
    for finding in findings:
        try:
            relative = normalize_source_path(finding.file, root)
        except ValueError:
            continue
        path = root / relative
        if path.suffix.lower() not in {".js", ".ts", ".jsx", ".tsx"}:
            continue
        try:
            relative = path.resolve(strict=True).relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
        if not path.is_file() or len(artifacts) >= 64:
            continue
        artifact_id = "source-" + sha256(relative.encode()).hexdigest()[:16]
        existing = artifacts.get(artifact_id)
        if existing is not None:
            if existing.kind != "javascript" or existing.relative_path != relative:
                continue
        else:
            artifacts[artifact_id] = TargetArtifact(id=artifact_id, kind="javascript", path=relative)
    return profile.model_copy(update={"artifacts": artifacts})


def verification_candidates(state):
    profile = state["target_profile"]
    finding = state["finding"]
    try:
        file = normalize_source_path(finding.file, profile.repository_path)
    except ValueError:
        return []
    artifact = next((a for a in profile.artifacts.values()
                     if a.kind == "javascript" and a.relative_path == file), None)
    if artifact is None:
        return []
    candidates = []
    family = rule_family(finding.rule_id)
    # These bindings belong to the operator's trusted profile, not model guesses.
    key = f"verification.{file}:{finding.line_start}"
    endpoint = profile.metadata.get(key + ".endpoint")
    runtime = state.get("runtime_services")
    service_id = profile.resolve_service(file)
    service = runtime.services.get(service_id) if runtime else None
    if service and service.ready and endpoint in service.allowed_endpoints:
        tool = None
        parameters = {}
        if family == "sql-injection":
            mode = profile.metadata.get(key + ".mode")
            if mode in {"search", "authentication"}:
                tool, parameters = "verify_sql_injection", {"mode": mode}
        elif family == "file-exposure":
            tool = "verify_sensitive_directory"
        if tool:
            parameters.update(artifact_id=artifact.id, line=finding.line_start,
                              check=profile.metadata.get(key + ".check", "source_metadata"))
            candidates.append({
                "candidate_id": "runtime-verification", "tool": tool,
                "parameters": parameters, "service": service_id, "endpoint": endpoint,
                "purpose": "Bounded controlled verification of this finding's trusted endpoint.",
            })
    check = profile.metadata.get(key + ".check", "source_metadata")
    candidates.append({
        "candidate_id": "javascript-source", "tool": "inspect_javascript_security",
        "parameters": {"artifact_id": artifact.id, "line": finding.line_start, "check": check},
        "service": None, "endpoint": None,
        "purpose": "Read bounded source metadata without executing JavaScript or disclosing secrets; this alone is not exploit proof.",
    })
    def signature(tool, parameters, service, endpoint):
        return (tool, json.dumps(parameters, sort_keys=True, separators=(",", ":")), service, endpoint)

    used = {
        signature(r.action.tool, r.action.parameters, r.action.service, r.action.endpoint)
        for r in state.get("action_history", [])
    }
    return [c for c in candidates
            if signature(c["tool"], c["parameters"], c["service"], c["endpoint"]) not in used]
