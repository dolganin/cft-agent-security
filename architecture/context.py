from __future__ import annotations

from typing import Protocol

from schemas.architecture import (
    ArchitectureContext,
    ArchitectureOverrides,
    ProjectDescription,
)


class ArchitectureContextProvider(Protocol):
    def get_context(self, service: str) -> ArchitectureContext: ...


class ProjectDescriptionAdapter:
    """Собираем общие факты для scoring из описания проекта в памяти"""

    def __init__(
        self,
        description: ProjectDescription,
        overrides: ArchitectureOverrides | None = None,
    ) -> None:
        self.description = description
        self.overrides = overrides or ArchitectureOverrides()

    def get_context(self, service: str) -> ArchitectureContext:
        services = self.description.services
        node = services.get(service)

        if node is None:
            context = ArchitectureContext(service=service)
        else:
            connected = list(dict.fromkeys(node.connects_to))
            databases = [
                name
                for name in connected
                if services.get(name) is not None
                and services[name].type.strip().lower() == "database"
            ]
            critical_paths = [
                f"{service} -> {name}"
                for name in connected
                if services.get(name) is not None
                and services[name].criticality.strip().lower() in {"high", "critical"}
            ]
            context = ArchitectureContext(
                service=service,
                public_exposure=node.public,
                criticality=node.criticality,
                trust_zone=node.trust_zone,
                connected_services=connected,
                databases=databases,
                critical_paths=critical_paths,
                authentication=node.authentication,
                blast_radius=node.blast_radius,
            )
            # Missing description facts must not become explicit negative facts
            # merely because the adapter materialized Pydantic defaults.
            values = context.model_dump()
            values.pop("unknown_inputs")
            if "public" not in node.model_fields_set:
                values.pop("public_exposure")
            if "connects_to" not in node.model_fields_set:
                values.pop("connected_services")
                values.pop("databases")
                values.pop("critical_paths")
            context = ArchitectureContext.model_validate(values)

        override = self.overrides.services.get(service)
        if override is None:
            return context

        values = override.model_dump(exclude_unset=True, exclude_none=True)
        known = context.model_dump(exclude_unset=True)
        known.pop("unknown_inputs", None)
        known.update(values)
        return ArchitectureContext.model_validate(known)
