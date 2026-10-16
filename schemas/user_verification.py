"""Secret-free contract for the fixed Juice Shop user-field probe."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

USER_FIELDS_ORDER = [
    "identity-a-before", "identity-b-before", "default-fields", "allowed-fields",
    "private-fields-first", "private-fields-second", "anonymous-private-fields",
    "unknown-field-control", "identity-a-after", "identity-b-after",
]

_HASH = r"^[a-f0-9]{64}$"


class UserPrivateProbe(BaseModel):
    """One redacted private-field response; the value itself is never serialized."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    status: int = Field(ge=100, le=599)
    identity_sha: str = Field(pattern=_HASH)
    private_present: bool
    private_value_sha: str | None = Field(default=None, pattern=_HASH)


class UserFieldsTrial(BaseModel):
    """Operator-owned whoami field-selection observation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["user.fields.trial.v1"]
    generation_sha256: str = Field(pattern=_HASH)
    source_snapshot_digest: str = Field(pattern=_HASH)
    fixture_snapshot_digest: str = Field(pattern=_HASH)
    binding_snapshot_digest: str = Field(pattern=_HASH)
    profile_sha256: str = Field(pattern=_HASH)
    identity_a_sha256: str = Field(pattern=_HASH)
    identity_b_sha256: str = Field(pattern=_HASH)
    session_a_sha256: str = Field(pattern=_HASH)
    session_b_sha256: str = Field(pattern=_HASH)
    expected_private_value_sha256: str = Field(pattern=_HASH)
    private_probes: list[UserPrivateProbe] = Field(min_length=3, max_length=3)
    default_private_absent: bool
    allowed_identity_verified: bool
    anonymous_private_absent: bool
    unknown_field_omitted: bool
    request_order: list[str] = Field(min_length=10, max_length=10)
    http_exchanges: Literal[10]

    @model_validator(mode="after")
    def fixed_protocol_order(self):
        if self.request_order != USER_FIELDS_ORDER:
            raise ValueError("User-field trial request order is fixed")
        return self
