"""Public B06 protocol facts. Credentials and arbitrary destinations are excluded."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.access_fixture import FixtureRole

B06_TOOLS = frozenset({"verify_redirect_destination", "verify_auth_reauthentication"})
Digest = str


class B06Profile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    protocol: Literal["juice_b06_v1"] = "juice_b06_v1"


class FixtureExecutionBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    fixture_id: str = Field(pattern=r"^b06-[a-f0-9]{20}$")
    session_id: str = Field(pattern=r"^b06-[a-f0-9]{20}$")
    target: str
    tool: Literal["verify_redirect_destination", "verify_auth_reauthentication"]
    generations: tuple[str, str]
    source_snapshot: str = Field(pattern=r"^[a-f0-9]{64}$")
    profile_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")

    @model_validator(mode="after")
    def independent_generations(self):
        import re
        if (self.fixture_id != self.session_id or len(set(self.generations)) != 2
                or any(not re.fullmatch(r"[a-f0-9]{16}", g) for g in self.generations)):
            raise ValueError("Two independent bound generations are required")
        return self


class VerificationExchange(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    sequence: int = Field(ge=1, le=17)
    operation: str = Field(pattern=r"^[a-z_]{1,40}$")
    status_code: int = Field(ge=100, le=599)
    response_bytes: int = Field(ge=0, le=65537)
    truncated: bool = False
    identity_id: int | None = Field(default=None, gt=0)
    expected_identity_id: int | None = Field(default=None, gt=0)
    identity_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_identity_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    owner_id: int | None = Field(default=None, gt=0)
    login_accepted: bool | None = None
    denial: Literal["auth_required", "wrong_current", "none"] = "none"
    location: Literal["approved", "probe", "none", "other", "ambiguous"] = "none"
    location_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    object_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    expected_object_sha256: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")


class B06PreparationProof(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    fixture_id: str
    generation: str
    source_snapshot: str = Field(pattern=r"^[a-f0-9]{64}$")
    context_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    roles: list[FixtureRole] = Field(min_length=2, max_length=2)
    controls: tuple[Literal["availability", "negative-control", "anonymous-identity"], ...]
    owner_id: int = Field(gt=0)
    object_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    http_exchanges: int = Field(ge=1, le=64)


class B06TrialResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    generation: str = Field(pattern=r"^[a-f0-9]{16}$")
    exchanges: list[VerificationExchange] = Field(default_factory=list, max_length=17)
    http_exchanges: int = Field(ge=0, le=17)
    setup_http_exchanges: int = Field(ge=0, le=64)
    sink_requests: int = Field(ge=0)
    redirect_followed: bool
    destination_dns: bool
    cleanup_complete: bool
    preparation: B06PreparationProof | None = None
    error: Literal["none", "budget_exhausted", "timeout", "control_failed",
                   "technical_failure", "response_truncated"] = "none"

    @model_validator(mode="after")
    def ledger(self):
        if self.http_exchanges != len(self.exchanges):
            raise ValueError("HTTP accounting must match the complete ledger")
        if [e.sequence for e in self.exchanges] != list(range(1, self.http_exchanges + 1)):
            raise ValueError("Exchange sequence must be complete and unique")
        return self


class B06VerificationResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["cft.b06.runtime.v1"] = "cft.b06.runtime.v1"
    binding: FixtureExecutionBinding
    action_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    trials: list[B06TrialResult] = Field(min_length=2, max_length=2)
    original_unchanged: bool
    verdict: Literal["confirmed", "rejected", "inconclusive"]
    explanation: str = Field(max_length=1000)
    scope: Literal["runtime_redirect_destination", "runtime_password_reauthentication"]


def profile_digest(profile) -> str:
    from security.verification_binding import digest
    return digest(profile.model_dump(mode="json", exclude={"repository_path", "artifacts"}))
