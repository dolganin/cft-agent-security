from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ExpressRouteRegistration(BaseModel):
    """Source anchor for a statically named Express route registration."""

    model_config = ConfigDict(extra="forbid")

    id: str
    file: str
    receiver: str
    method: Literal["get", "post", "put", "patch", "delete", "head", "options", "all"]
    path: str | None = None
    path_is_static: bool
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    registration_order: int = Field(ge=0)
    middleware: list[str] = Field(default_factory=list, max_length=8)
    handler_files: list[str] = Field(default_factory=list, max_length=16)
    middleware_before: list[str] = Field(default_factory=list, max_length=8)
    service_id: str | None = None

    @model_validator(mode="after")
    def validate_line_range(self) -> ExpressRouteRegistration:
        if self.line_end < self.line_start:
            raise ValueError("Route source range ends before it starts")
        if self.path_is_static != (self.path is not None):
            raise ValueError("Static route path must be present and dynamic path must be unknown")
        return self


class ExpressMiddlewareRegistration(BaseModel):
    """One ordered app.use/router.use registration; names are not proof of behavior."""

    model_config = ConfigDict(extra="forbid")

    id: str
    file: str
    receiver: str
    mount_path: str | None = None
    path_is_static: bool
    line_start: int = Field(ge=1)
    registration_order: int = Field(ge=0)
    middleware: list[str] = Field(default_factory=list, max_length=8)


class ExpressSourceMap(BaseModel):
    """Bounded registration inventory. It does not decide whether a route is safe."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["cft.express_source_map.v1"] = "cft.express_source_map.v1"
    analyzed_files: list[str] = Field(default_factory=list, max_length=256)
    routes: list[ExpressRouteRegistration] = Field(default_factory=list, max_length=1024)
    middleware_mounts: list[ExpressMiddlewareRegistration] = Field(
        default_factory=list, max_length=2048,
    )
    dynamic_routes: int = Field(default=0, ge=0)
    omitted_routes: int = Field(default=0, ge=0)
    omitted_middleware_mounts: int = Field(default=0, ge=0)
    unsupported_files: list[str] = Field(default_factory=list, max_length=256)

    def for_context(self, paths: set[str], *, limit: int = 16) -> dict:
        """Return only routes related to code in the current model turn."""
        selected = [
            route for route in self.routes
            if route.file in paths or set(route.handler_files).intersection(paths)
        ][:limit]
        route_files = {route.file for route in selected}
        middleware = [
            item for item in self.middleware_mounts
            if item.file in route_files
        ][-limit:]
        return {
            "schema_version": self.schema_version,
            "routes": [item.model_dump(mode="json") for item in selected],
            "middleware_mounts": [item.model_dump(mode="json") for item in middleware],
            "dynamic_routes": self.dynamic_routes,
            "omitted_routes": self.omitted_routes,
        }
