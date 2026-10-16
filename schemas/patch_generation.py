"""Bounded model response and proposal-only C02 provenance."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from schemas.fix import PatchReviewArtifact, ProposedPatch


class BoundedPatchResponse(ProposedPatch):
    model_config = ConfigDict(extra="forbid", strict=True)
    finding_id: str = Field(min_length=1, max_length=512)
    rationale: str = Field(min_length=1, max_length=2000)
    unified_diff: str = Field(min_length=1, max_length=16384)


class PatchGenerationArtifact(BaseModel):
    schema_version: Literal["cft.patch-generation.c02.v1"] = "cft.patch-generation.c02.v1"
    family_id: str
    status: Literal["ready_for_review", "rejected", "failed", "ineligible"]
    reason: str
    generation_method: Literal["llm"] = "llm"
    provider_route: str | None = None
    provider_attempts: list[dict] = Field(default_factory=list)
    model_response_received: bool = False
    source_commit: str = ""
    source_snapshot_sha256: str = ""
    source_file_sha256: str = ""
    baseline_archive_sha256: str = ""
    original_report_sha256: str = ""
    request_sha256: str = ""
    response_sha256: str | None = None
    response_patch_sha256: str | None = None
    c01_lock_sha256: str = ""
    original_unchanged: bool = False
    review: PatchReviewArtifact | None = None
    applied: Literal[False] = False
    security_verified: Literal[False] = False

    @model_validator(mode="after")
    def require_proposal_provenance(self):
        if self.status == "ready_for_review" and not (
            self.review is not None and self.review.status == "ready_for_review"
            and self.review.model == self.provider_route
            and self.original_unchanged and self.model_response_received
            and self.source_snapshot_sha256 and self.source_file_sha256
            and self.request_sha256 and self.response_sha256
            and any(a.get("ok") is True and a.get("route") == self.provider_route
                    for a in self.provider_attempts)
        ):
            raise ValueError("Ready proposal requires complete model/source provenance")
        if self.status != "ready_for_review" and self.review is not None:
            raise ValueError("Failed/rejected/ineligible generation cannot expose a reviewed patch")
        return self
