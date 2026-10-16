"""Fail-closed source scoping for blind RepositoryScout development runs."""

from __future__ import annotations

from pathlib import Path

import yaml

from schemas.discovery import ProjectDiscoveryResult
from schemas.scout import ScoutSurfaceProfile, ScoutSurfaceRegistry
from tools.repository_source import RepositorySource


def load_surface_profile(path: Path, surface_id: str) -> tuple[ScoutSurfaceProfile, bytes]:
    """Load one data-only, operator-owned profile from a versioned YAML registry."""
    raw = path.read_bytes()
    registry = ScoutSurfaceRegistry.model_validate(yaml.safe_load(raw))
    matches = [item for item in registry.surfaces if item.id == surface_id]
    if len(matches) != 1:
        raise ValueError(f"Scout surface {surface_id!r} is not registered exactly once")
    return matches[0], raw


def scope_discovery(
    inventory: ProjectDiscoveryResult,
    profile: ScoutSurfaceProfile,
) -> ProjectDiscoveryResult:
    """Project discovery down to exactly the operator-registered source allowlist."""
    selected = set(profile.source_paths)
    available = set(inventory.project_files)
    missing = sorted(selected - available)
    if missing:
        raise ValueError(
            "Scout surface contains paths absent from target inventory: "
            + ", ".join(missing)
        )

    scoped = inventory.model_copy(update={
        "project_files": sorted(selected),
        "signals": [signal for signal in inventory.signals if signal.path in selected],
        "components": _scoped_components(inventory, selected),
        "warnings": [],
        "interpretation": None,
    })
    indexed = set(RepositorySource(scoped).lines)
    if indexed != selected:
        skipped = sorted(selected - indexed)
        raise ValueError(
            "Scout surface is not fully readable by the source-only reader: "
            + ", ".join(skipped)
        )
    return scoped


def _scoped_components(
    inventory: ProjectDiscoveryResult,
    selected_paths: set[str],
) -> list:
    components = []
    for component in inventory.components:
        root = component.root
        in_scope = root == "." or any(
            path == root or path.startswith(f"{root}/") for path in selected_paths
        )
        if not in_scope:
            continue
        components.append(component.model_copy(update={
            # Keep only topology/technology context useful for source review.
            # Build commands, local addresses and unrelated files are not needed.
            "dependency_files": [],
            "dockerfiles": [],
            "compose_candidates": [],
            "build_candidates": [],
            "run_candidates": [],
            "healthcheck_candidates": [],
            "allowed_local_addresses": [],
            "source_paths": sorted(set(component.source_paths).intersection(selected_paths)),
        }))
    return components
