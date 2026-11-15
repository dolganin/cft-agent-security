"""Local API composition: ordinary projects plus one isolated built-in example."""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from api.registry import ApiTargetRegistry
from api.service import RunOrchestrator
from api.store import ApiStore
from app.config import settings
from app.demo_preview import OrderStorePreview
from app.profile_pipeline import STORE_PROFILE, STORE_TEMPLATE
from pipeline.cancellation import CancellationToken, RunCancelled, cancellation_scope
from schemas.target import TargetProfile


class BuiltinStore:
    def __init__(self, port: int):
        self._temporary = tempfile.TemporaryDirectory(prefix="cft-builtin-store-")
        self.repository = Path(self._temporary.name) / "order-store"
        try:
            shutil.copytree(STORE_TEMPLATE, self.repository)
            self.profile = TargetProfile.from_yaml(STORE_PROFILE, repository_path_override=self.repository)
            self.preview = OrderStorePreview(self.repository, port=port)
        except Exception:
            self._temporary.cleanup()
            raise
        self.token = CancellationToken()

    def start(self):
        try:
            with cancellation_scope(self.token):
                self.preview.start()
        except RunCancelled:
            pass

    def status(self):
        return self.preview.public_status()

    def cancel(self):
        self.token.cancel()

    def close(self):
        self.preview.stop()
        self._temporary.cleanup()


def build_default_service():
    profiles = [p.strip() for p in settings.api_target_profiles.split(",") if p.strip()]
    registry = (ApiTargetRegistry.from_profile_paths(profiles, trusted_root=Path("targets"))
                if profiles else ApiTargetRegistry([]))
    example = BuiltinStore(settings.api_store_preview_port) if settings.api_builtin_store_enabled else None
    try:
        if example is not None:
            if any(target.profile.id == example.profile.id for target in registry.list()):
                raise ValueError("Built-in store id is reserved; remove its duplicate configured profile")
            registry.register_generated(profile_path=STORE_PROFILE, profile=example.profile)
        database = settings.api_database_path
        artifacts = settings.api_artifact_root
        projects = settings.api_project_root
        # Reuse the previous UI history only when no ordinary API database exists
        # and the operator has not explicitly selected another storage location.
        legacy = Path("api_data/presentation-2026-10-08.sqlite3")
        if ("api_database_path" not in settings.model_fields_set
                and database == Path("api_data/cft-security.sqlite3")
                and not database.exists() and legacy.is_file()):
            database = legacy
            if "api_artifact_root" not in settings.model_fields_set:
                artifacts = Path("artifacts/presentation-2026-10-08/runs")
            if "api_project_root" not in settings.model_fields_set:
                projects = Path("api_data/presentation-projects")
        service = RunOrchestrator(registry=registry, store=ApiStore(database),
                                  artifact_root=artifacts, project_root=projects)
        return service, example
    except Exception:
        if example is not None:
            example.close()
        raise
