"""Operator-only permission for a closed, private verification protocol."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ResearchFixtureGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    protocol: Literal[
        "b05.own-read.v1", "b05.basket-insert.v1",
        "b05.review-owner.v1",
        "b05.review-nosql.v1",
        "b05.user-fields.v1",
        "b05.feedback-owner.v1",
        "b06.redirect.v1", "b06.password-reauth.v1",
    ]
    wall_seconds: int = Field(default=300, ge=10, le=600)
    max_http_requests: int = Field(default=256, ge=1, le=256)


class ResearchVerificationGrant(BaseModel):
    """Exact operator grant for a fixed canonical verifier, never for model HTTP."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    protocol: Literal["b01.login-sql.v1"]
    route_id: Literal["juice-login"]
    max_http_requests: Literal[4] = 4
