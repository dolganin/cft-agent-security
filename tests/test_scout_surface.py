from pathlib import Path

import pytest
from pydantic import ValidationError

from schemas.discovery import (
    DiscoveredComponent,
    DiscoverySignal,
    ProjectDiscoveryResult,
)
from schemas.scout import ScoutSurfaceProfile
from security.scout_surface import load_surface_profile, scope_discovery
from tools.repository_source import RepositorySource


def make_inventory(root: Path) -> ProjectDiscoveryResult:
    files = {
        "routes/account.ts": "export const account = true;\n",
        "models/user.ts": "export class User {}\n",
        "routes/other.ts": "export const unrelated = true;\n",
        "routes/vulnCodeSnippet.ts": "return benchmarkAnswer;\n",
        "benchmarks/oracle.ts": "export const expected = true;\n",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return ProjectDiscoveryResult(
        repository_root=root,
        project_files=list(files),
        signals=[
            DiscoverySignal(detector="test", kind="technology", path="routes/account.ts",
                            name="express", confidence=1.0),
            DiscoverySignal(detector="test", kind="technology", path="routes/other.ts",
                            name="unrelated", confidence=1.0),
        ],
        components=[DiscoveredComponent(
            id="app", root=".", technologies=["node"], frameworks=["express"],
            dependency_files=["package.json"], dockerfiles=["Dockerfile"],
            allowed_local_addresses=["http://127.0.0.1:8080"],
            source_paths=["routes/account.ts", "routes/other.ts"], confidence=1.0,
        )],
        warnings=["not sent into blind source exploration"],
    )


def test_surface_profile_rejects_paths_that_escape_target():
    with pytest.raises(ValidationError):
        ScoutSurfaceProfile(
            id="unsafe-surface", focus="Review application source safely",
            source_paths=["../outside.ts"],
        )
    with pytest.raises(ValidationError):
        ScoutSurfaceProfile(
            id="unsafe-surface", focus="Review application source safely",
            source_paths=["/outside.ts"],
        )


def test_scoped_discovery_contains_only_operator_allowlist_and_scrubs_runtime_details(tmp_path):
    inventory = make_inventory(tmp_path)
    profile = ScoutSurfaceProfile(
        id="account-lifecycle", focus="Review account handlers and related model source",
        source_paths=["routes/account.ts", "models/user.ts"],
    )

    scoped = scope_discovery(inventory, profile)

    assert scoped.project_files == ["models/user.ts", "routes/account.ts"]
    assert [signal.path for signal in scoped.signals] == ["routes/account.ts"]
    assert scoped.warnings == []
    assert scoped.interpretation is None
    component = scoped.components[0]
    assert component.source_paths == ["routes/account.ts"]
    assert component.dependency_files == []
    assert component.dockerfiles == []
    assert component.allowed_local_addresses == []
    assert RepositorySource(scoped).files == ["routes/account.ts", "models/user.ts"]
    assert "routes/other.ts" not in str(scoped.model_dump(mode="json"))


def test_surface_fails_closed_when_profile_has_absent_target_path(tmp_path):
    inventory = make_inventory(tmp_path)
    profile = ScoutSurfaceProfile(
        id="account-lifecycle", focus="Review account handlers and related model source",
        source_paths=["routes/missing.ts"],
    )
    with pytest.raises(ValueError, match="absent from target inventory"):
        scope_discovery(inventory, profile)


def test_surface_fails_closed_on_excluded_or_unreadable_source(tmp_path):
    inventory = make_inventory(tmp_path)
    profile = ScoutSurfaceProfile(
        id="unsafe-surface", focus="Review benchmark-associated source files safely",
        source_paths=["benchmarks/oracle.ts"],
    )
    with pytest.raises(ValueError, match="not fully readable"):
        scope_discovery(inventory, profile)


def test_profile_loader_requires_registered_surface(tmp_path):
    registry = tmp_path / "surfaces.yaml"
    registry.write_text(
        "schema_version: cft.scout_surfaces.v1\nsurfaces:\n"
        "  - id: catalog\n"
        "    focus: Review catalog application source safely\n"
        "    source_paths: [routes/catalog.ts]\n",
        encoding="utf-8",
    )
    profile, raw = load_surface_profile(registry, "catalog")
    assert profile.id == "catalog"
    assert raw == registry.read_bytes()
    with pytest.raises(ValueError, match="not registered"):
        load_surface_profile(registry, "unknown")

