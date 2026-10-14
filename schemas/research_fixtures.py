"""Operator-only permission for a closed, private verification protocol."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ResearchFixtureGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    protocol: Literal["b05.own-read.v1", "b06.redirect.v1", "b06.password-reauth.v1"]
    wall_seconds: int = Field(default=300, ge=10, le=600)
    max_http_requests: int = Field(default=256, ge=1, le=256)
