"""Redacted result contract for the fixed B05 feedback-owner probe."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

FEEDBACK_ORDER = [
    "identity-a-before", "identity-b-before", "captcha-owner", "owner-feedback-create",
    "owner-feedback-readback", "captcha-probe", "foreign-feedback-create",
    "post-probe-readback", "identity-a-after", "identity-b-after",
]
_HASH = r"^[a-f0-9]{64}$"


class FeedbackOwnershipTrial(BaseModel):
    """One disposable generation; numeric IDs and response bodies never leave worker."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["b05.feedback.trial.v1"]
    generation_sha256: str = Field(pattern=_HASH)
    source_snapshot_digest: str = Field(pattern=_HASH)
    fixture_snapshot_digest: str = Field(pattern=_HASH)
    binding_snapshot_digest: str = Field(pattern=_HASH)
    profile_sha256: str = Field(pattern=_HASH)
    identity_a_sha256: str = Field(pattern=_HASH)
    identity_b_sha256: str = Field(pattern=_HASH)
    session_a_sha256: str = Field(pattern=_HASH)
    session_b_sha256: str = Field(pattern=_HASH)
    control_marker_sha256: str = Field(pattern=_HASH)
    probe_marker_sha256: str = Field(pattern=_HASH)
    captcha_control_passed: bool
    owner_create_status: int = Field(ge=100, le=599)
    owner_readback_status: int = Field(ge=100, le=599)
    owner_readback_matches: bool
    probe_status: int = Field(ge=100, le=599)
    probe_created: bool
    probe_readback_status: int = Field(ge=100, le=599)
    probe_owner_role: Literal["role-a", "role-b", "other", "absent"]
    probe_comment_matches: bool
    control_unchanged_after_denial: bool | None
    request_order: list[str] = Field(min_length=10, max_length=10)
    http_exchanges: Literal[10]

    @model_validator(mode="after")
    def fixed_order_and_status(self):
        if self.request_order != FEEDBACK_ORDER:
            raise ValueError("Feedback trial request order is fixed")
        if self.probe_created != (self.probe_status in {200, 201}):
            raise ValueError("Feedback creation status does not match probe state")
        if self.probe_created and self.control_unchanged_after_denial is not None:
            raise ValueError("Creation trial cannot carry a denial-only control")
        if not self.probe_created and self.control_unchanged_after_denial is None:
            raise ValueError("Denied trial requires a readback of the control record")
        return self
