"""Operator-owned confidentiality contract; private marker never goes to the model."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from schemas.research import request_path


class HttpMarkerSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(min_length=1, max_length=128)
    service: str
    owner_path: str
    probe_path: str
    negative_path: str
    owner_role: str
    marker: SecretStr
    expected_denial_statuses: list[Literal[401, 403]] = Field(default_factory=lambda: [401, 403], min_length=1)
    _paths = field_validator("owner_path", "probe_path", "negative_path")(request_path)

    def public(self):
        return {"id": self.id, "protocol": "confidential_marker.v1", "service": self.service,
                "probe_path": self.probe_path, "property": "anonymous access must not disclose the owned confidential marker"}
