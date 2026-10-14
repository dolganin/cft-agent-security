"""Operator scope and typed research requests; no live handles or credentials."""
from __future__ import annotations

import json
import re
from hashlib import sha256
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_serializer,
    model_validator,
)

RESEARCH_TOOLS = frozenset({"list_source_files", "read_source", "search_source",
                           "write_workspace_file", "read_workspace_file", "target_http"})


def content_digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode()).hexdigest()


def relative_file(value: str) -> str:
    if (not value or len(value) > 240 or value.startswith("/") or "\\" in value
            or any(ord(c) < 32 for c in value)
            or any(p in {"", ".", ".."} or ":" in p for p in value.split("/"))):
        raise ValueError("A canonical relative file path is required")
    return value


def request_path(value: str) -> str:
    decoded = value
    for _ in range(4):
        decoded = unquote(decoded)
    parsed = urlsplit(decoded)
    if (not decoded.startswith("/") or decoded.startswith("//") or "\\" in decoded
            or parsed.scheme or parsed.netloc or parsed.fragment
            or any(ord(c) <= 32 or ord(c) == 127 for c in decoded)
            or any(part in {".", ".."} for part in parsed.path.split("/"))
            or re.search(r"%[0-9a-fA-F]{2}", decoded)):
        raise ValueError("A bounded local path without URL/traversal is required")
    return value


class StrictResearchModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class ResearchFile(StrictResearchModel):
    original_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    visible_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class HttpServiceScope(StrictResearchModel):
    container_id: str = Field(pattern=r"^[a-f0-9]{64}$")
    image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    address: str
    read_prefixes: list[str] = Field(default_factory=list, max_length=32)
    write_paths: dict[str, list[str]] = Field(default_factory=dict)
    role_handles: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("read_prefixes")
    @classmethod
    def prefixes(cls, values):
        for value in values:
            if request_path(value) != value or "?" in value:
                raise ValueError("Scope prefixes must be local paths")
        return values

    @field_validator("write_paths")
    @classmethod
    def writes(cls, value):
        for method, paths in value.items():
            if method not in {"POST", "PUT", "PATCH", "DELETE"}:
                raise ValueError("Unsupported operator write method")
            for path in paths:
                request_path(path)
                if "?" in path:
                    raise ValueError("Write grants cannot contain a query")
        return value


class ResearchScope(StrictResearchModel):
    target_id: str
    environment: Literal["sandbox"] = "sandbox"
    session_id: str = Field(pattern=r"^research-[a-f0-9]{32}$")
    worker_image: str = Field(pattern=r"^(?:sha256:[a-f0-9]{64}|[^\s]+@sha256:[a-f0-9]{64})$")
    worker_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_files: dict[str, ResearchFile]
    services: dict[str, HttpServiceScope] = Field(default_factory=dict)
    network_name: str | None = None
    runtime_services_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    target_runtime_session_id: str | None = None
    max_actions: int = Field(default=64, ge=1, le=256)
    max_http_requests: int = Field(default=32, ge=0, le=256)
    wall_seconds: int = Field(default=300, ge=1, le=3600)

    @field_validator("source_files")
    @classmethod
    def sources(cls, values):
        if not values or len(values) > 4096:
            raise ValueError("Research requires a finite nonempty source inventory")
        for value in values:
            relative_file(value)
        return values

    @model_validator(mode="after")
    def network(self):
        if self.services and (not self.network_name or self.network_name in {"host", "bridge", "none"}):
            raise ValueError("Research HTTP requires an operator-owned internal network")
        if (self.runtime_services_sha256 is None) != (self.target_runtime_session_id is None):
            raise ValueError("RuntimeServiceMap digest and parent session must be provided together")
        return self

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        payload = handler(self)
        for field in ("runtime_services_sha256", "target_runtime_session_id"):
            if payload.get(field) is None:
                payload.pop(field, None)
        return payload

    @property
    def digest(self):
        return content_digest(self.model_dump(mode="json"))

    @property
    def source_snapshot(self):
        return content_digest({p: f.original_sha256 for p, f in self.source_files.items()})


class ResearchBinding(StrictResearchModel):
    session_id: str
    scope_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    source_snapshot: str = Field(pattern=r"^[a-f0-9]{64}$")


class ListSourceRequest(StrictResearchModel):
    offset: int = Field(default=0, ge=0, le=4096)
    limit: int = Field(default=100, ge=1, le=100)


class ReadSourceRequest(StrictResearchModel):
    path: str
    line_start: int = Field(default=1, ge=1, le=100000)
    line_end: int = Field(default=160, ge=1, le=100000)
    _path = field_validator("path")(relative_file)

    @model_validator(mode="after")
    def window(self):
        if not 0 <= self.line_end - self.line_start < 400:
            raise ValueError("Source windows are limited to 400 lines")
        return self


class SearchSourceRequest(StrictResearchModel):
    literal: str = Field(min_length=1, max_length=200)
    paths: list[str] = Field(default_factory=list, max_length=64)
    max_matches: int = Field(default=50, ge=1, le=100)


class WriteWorkspaceRequest(StrictResearchModel):
    path: str
    content: str = Field(max_length=65536)
    _path = field_validator("path")(relative_file)

    @field_validator("content")
    @classmethod
    def byte_limit(cls, value):
        if len(value.encode()) > 65536:
            raise ValueError("Workspace content exceeds 65536 bytes")
        return value


class ReadWorkspaceRequest(StrictResearchModel):
    path: str
    _path = field_validator("path")(relative_file)


class ScriptRequest(StrictResearchModel):
    argv: list[str] = Field(min_length=2, max_length=32)
    cwd: Literal["/workspace"] = "/workspace"
    script_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def command(self):
        if self.argv[0] not in {"python3", "node"} or not self.argv[1].startswith("/workspace/"):
            raise ValueError("Execute a digest-bound workspace script with python3 or node")
        relative_file(self.argv[1][len("/workspace/"):])
        if any(not v or len(v) > 1024 or "\x00" in v for v in self.argv):
            raise ValueError("Invalid script argument")
        return self


class TargetHttpRequest(StrictResearchModel):
    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path: str = Field(max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str = Field(default="", max_length=16384)
    role_handle: str | None = None
    _path = field_validator("path")(request_path)

    @field_validator("headers")
    @classmethod
    def safe_headers(cls, values):
        if len(values) > 8 or any(k.lower() not in {"accept", "content-type"}
                                  or len(v) > 256 or any(ord(c) < 32 for c in v)
                                  for k, v in values.items()):
            raise ValueError("Only bounded Accept/Content-Type headers are model-owned")
        return values


RESEARCH_REQUESTS = {
    "list_source_files": ListSourceRequest, "read_source": ReadSourceRequest,
    "search_source": SearchSourceRequest, "write_workspace_file": WriteWorkspaceRequest,
    "read_workspace_file": ReadWorkspaceRequest, "sandbox_command": ScriptRequest,
    "target_http": TargetHttpRequest,
}
