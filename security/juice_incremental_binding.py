"""Trusted routing/binding for the fixed Juice Shop mini-proof capabilities."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from schemas.action import ActionProposal
from schemas.juice_incremental_proof import JuiceProofBinding, JuiceProofProfile, JuiceProofRoute

_TARGET_COMMIT = "5658473cf8814459bf89000ce373b20ed0b4eb37"


def _digest(value: object) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _protocol_files(check_id: str) -> tuple[str, ...]:
    if check_id == "role-registration":
        return ("server.ts", "routes/login.ts", "routes/currentUser.ts",
                "models/user.ts", "lib/insecurity.ts")
    if check_id == "anonymous-product-put":
        return ("server.ts", "models/product.ts", "models/user.ts", "lib/insecurity.ts")
    raise ValueError("Juice proof check is not registered")


def _source_snapshot(repository: Path, check_id: str) -> str:
    files: dict[str, str] = {}
    root = repository.resolve(strict=True)
    for relative in _protocol_files(check_id):
        source = root / relative
        resolved = source.resolve(strict=True)
        if (source.is_symlink() or not resolved.is_relative_to(root)
                or resolved.relative_to(root).as_posix() != relative
                or not resolved.is_file()):
            raise ValueError("Juice proof source is not canonical")
        raw = resolved.read_bytes()
        if len(raw) > 1_048_576:
            raise ValueError("Juice proof source exceeds the fixed size limit")
        files[relative] = hashlib.sha256(raw).hexdigest()
    return _digest(files)


def _route(profile: JuiceProofProfile, check_id: str) -> JuiceProofRoute:
    matches = [route for route in profile.routes if route.check_id == check_id]
    if len(matches) != 1:
        raise ValueError("Juice proof check is not uniquely registered")
    return matches[0]


def bind_finding(profile, finding) -> JuiceProofBinding | None:
    """Create application-owned binding only for the two reviewed detector routes."""
    config = profile.juice_incremental_proofs
    repository = profile.repository_path
    if config is None or repository is None:
        return None
    for route in config.routes:
        if finding.rule_id != route.rule_id or finding.file.replace("\\", "/") != route.source_file:
            continue
        return JuiceProofBinding(
            target=profile.id,
            finding_id=finding.id,
            rule_id=route.rule_id,
            source_file=route.source_file,
            check_id=route.check_id,
            route_sha256=_digest(route.model_dump(mode="json")),
            source_snapshot_sha256=_source_snapshot(repository, route.check_id),
        )
    return None


def validate_action_binding(profile, action: ActionProposal) -> JuiceProofBinding:
    """Recompute every trusted field at approval and execution boundaries."""
    config = profile.juice_incremental_proofs
    binding = action.juice_proof_binding
    if config is None or binding is None or profile.repository_path is None:
        raise ValueError("Juice proof requires a registered operator profile and binding")
    if (action.tool != "verify_juice_proof" or action.target != profile.id
            or binding.target != profile.id or binding.finding_id == ""
            or action.parameters != {"check_id": binding.check_id}):
        raise ValueError("Juice proof action does not match its approved binding")
    if (config.target_commit != _TARGET_COMMIT
            or config.target_image != "bkimminich/juice-shop@sha256:8739101ade29358abb5469ee66ae78e582c97ed0a5543a4ad102e5fa5193526b"
            or config.worker_image != "python@sha256:1b668429b3511ab407d8e00648891631b0b1a4d7e15e3ca70f38ab5b91ad4ab4"):
        raise ValueError("Juice proof target, worker or image differs from the fixed v20.2.0 pin")
    route = _route(config, binding.check_id)
    if (binding.rule_id != route.rule_id or binding.source_file != route.source_file
            or _digest(route.model_dump(mode="json")) != binding.route_sha256):
        raise ValueError("Juice proof route binding is stale or mismatched")
    if _source_snapshot(profile.repository_path, binding.check_id) != binding.source_snapshot_sha256:
        raise ValueError("Juice proof target source changed after candidate binding")
    return binding
