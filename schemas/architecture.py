from pydantic import BaseModel, Field, model_validator


class ProjectServiceDescription(BaseModel):
    type: str = "unknown"
    public: bool = False
    criticality: str = "unknown"
    trust_zone: str | None = None
    connects_to: list[str] = Field(default_factory=list)
    authentication: str = "unknown"
    blast_radius: str = "unknown"


class ProjectDescription(BaseModel):
    services: dict[str, ProjectServiceDescription] = Field(default_factory=dict)


class ArchitectureContext(BaseModel):
    service: str
    public_exposure: bool = False
    criticality: str = "unknown"
    trust_zone: str | None = None
    connected_services: list[str] = Field(default_factory=list)
    databases: list[str] = Field(default_factory=list)
    critical_paths: list[str] = Field(default_factory=list)
    authentication: str = "unknown"
    blast_radius: str = "unknown"
    unknown_inputs: list[str] | None = None

    @model_validator(mode="after")
    def retain_unknown_facts(self):
        if self.unknown_inputs is None:
            fields = ("public_exposure", "criticality", "databases", "critical_paths",
                      "authentication", "blast_radius")
            self.unknown_inputs = [
                name for name in fields if name not in self.model_fields_set
                or (isinstance(getattr(self, name), str)
                    and getattr(self, name).strip().lower() in {"", "unknown"})
            ]
        return self


class ArchitectureContextOverride(BaseModel):
    public_exposure: bool | None = None
    criticality: str | None = None
    trust_zone: str | None = None
    connected_services: list[str] | None = None
    databases: list[str] | None = None
    critical_paths: list[str] | None = None
    authentication: str | None = None
    blast_radius: str | None = None


class ArchitectureOverrides(BaseModel):
    services: dict[str, ArchitectureContextOverride] = Field(default_factory=dict)
