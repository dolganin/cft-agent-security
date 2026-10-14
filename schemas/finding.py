from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.pr import PRFindingContext


class FindingObservation(BaseModel):
    """Scanner/model observation; never execution Evidence or a verdict."""

    model_config = ConfigDict(extra="forbid")
    source_id: str
    source: str
    rule_id: str
    original_file: str
    title: str
    description: str
    line_start: int | None = Field(default=None, ge=1)
    line_end: int | None = Field(default=None, ge=1)
    column_start: int | None = Field(default=None, ge=1)
    column_end: int | None = Field(default=None, ge=1)
    severity: str | None = None
    rationale: str | None = None
    provenance_paths: list[str] = Field(default_factory=list)
    signal_type: Literal["code", "configuration", "dependency"] | None = None
    cwe: list[str] = Field(default_factory=list)


class FindingProvenance(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: Literal["1.0"] = "1.0"
    family: str
    fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    normalized_file: str
    anchor_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    file_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    anchor_status: Literal["source_bound", "location_only"]
    aliases: list[str] = Field(default_factory=list)
    observations: list[FindingObservation] = Field(default_factory=list)

    def public_copy(self) -> "FindingProvenance":
        """Keep raw spelling locally, but do not expose host absolute paths in API."""
        from pathlib import PurePosixPath, PureWindowsPath

        replacements = {
            item.original_file: self.normalized_file for item in self.observations
            if PurePosixPath(item.original_file).is_absolute()
            or PureWindowsPath(item.original_file).drive
        }

        def public_id(value: str) -> str:
            for raw, normalized in replacements.items():
                value = value.replace(raw, normalized)
            return value

        return self.model_copy(update={
            "aliases": list(dict.fromkeys(public_id(alias) for alias in self.aliases)),
            "observations": [item.model_copy(update={
                "original_file": replacements.get(item.original_file, item.original_file),
                "source_id": public_id(item.source_id),
                "provenance_paths": [replacements.get(path, path) for path in item.provenance_paths],
            }) for item in self.observations],
        })


class Finding(BaseModel):
    id: str
    source: str
    rule_id: str
    title: str
    description: str
    file: str
    line_start: int | None = None
    line_end: int | None = None
    severity: str | None = None
    service: str | None = None
    pr_context: PRFindingContext | None = None
    provenance: FindingProvenance | None = None
