"""Application-owned verification candidates; never infer target URLs from the LLM."""
import json
from hashlib import sha256
from pathlib import Path

from discovery.scout import rule_family
from schemas.target import TargetArtifact
from security.source_paths import normalize_source_path
from security.verification_binding import resolve_binding


def register_source_artifacts(profile, findings, repository):
    root = Path(repository).resolve()
    artifacts = dict(profile.artifacts)
    # Keep files needed by existing operator verifiers ahead of unrelated scanner
    # observations. A broader Scout pass must not consume the finite registry
    # before a registered route's source is reached. Registration alone grants
    # no execution: the exact binding/Validator checks still run independently.
    bound_files = {normalize_source_path(source.file, root)
                   for route in profile.verification_routes
                   for source in [route.registration, *route.sources]}

    def operator_bound(finding):
        try:
            return normalize_source_path(finding.file, root) in bound_files
        except ValueError:
            return False

    for finding in sorted(findings, key=lambda item: not operator_bound(item)):
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
    family = rule_family(finding.rule_id)
    if profile.verification_routes:
        resolution = resolve_binding(profile, finding)
        if resolution.binding is None:
            return []
        binding = resolution.binding
        if binding.tool == "verify_access_control":
            from security.access_verification import ACCESS_CHECKS
            registrations = [check for check in ACCESS_CHECKS.values()
                             if check.route_id == binding.route_id]
            if len(registrations) != 1:
                return []
            registration = registrations[0]
            from security.access_verification import is_access_check_supported
            if not is_access_check_supported(registration.check_id):
                return []
            candidate = {
                "candidate_id": "access-check:" + registration.check_id,
                "tool": "verify_access_control", "parameters": {"check_id": registration.check_id},
                "service": binding.service, "endpoint": binding.endpoint,
                "verification_binding": binding,
                "purpose": "Run one operator-registered access-control check against its bound fixture.",
            }
            if any(r.action.verification_binding == binding for r in state.get("action_history", [])):
                return []
            return [candidate]
        artifacts = [a for a in profile.artifacts.values()
                     if a.kind == "javascript" and a.relative_path == file]
        if len(artifacts) != 1:
            return []
        artifact = artifacts[0]
        candidates = []
        runtime = state.get("runtime_services")
        service = runtime.services.get(binding.service) if runtime else None
        if not service or not service.ready or binding.endpoint not in service.allowed_endpoints:
            return []
        parameters = {"artifact_id": artifact.id, "line": binding.line_start, "check": binding.check}
        if binding.mode is not None:
            parameters["mode"] = binding.mode
        candidate = {
            "candidate_id": "runtime:" + binding.route_id, "tool": binding.tool,
            "parameters": parameters, "service": binding.service, "endpoint": binding.endpoint,
            "verification_binding": binding,
            "purpose": "Verify the unique operator-mapped handler/endpoint in its source snapshot.",
        }
        from schemas.b06_verification import B06_TOOLS
        if binding.tool in B06_TOOLS:
            fixture = runtime.verification_fixtures.get(binding.tool)
            if (fixture is None or fixture.source_snapshot != binding.source_snapshot
                    or fixture.target != profile.id or fixture.tool != binding.tool
                    or fixture.session_id != runtime.session_id):
                return []
            candidate["fixture_binding"] = fixture
        if any(r.action.verification_binding == binding for r in state.get("action_history", [])):
            return []
        return [candidate]
    artifacts = [a for a in profile.artifacts.values()
                 if a.kind == "javascript" and a.relative_path == file]
    if len(artifacts) != 1:
        return []
    artifact = artifacts[0]
    candidates = []
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
