"""Versioned C03 envelope; the Stage 1 artifact/API remains unchanged."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.action import ActionProposal
from schemas.evidence import Evidence
from schemas.execution import ExecutionResult
from schemas.fix import FixVerificationArtifact
from schemas.validation import ValidationResult


class C03Receipt(BaseModel):
    model_config = ConfigDict(extra='forbid')
    action: ActionProposal
    validation: ValidationResult
    execution: ExecutionResult
    record: dict
    audit: dict
    evidence: Evidence


class C03Artifact(BaseModel):
    model_config = ConfigDict(extra='forbid')
    schema_version: Literal['cft.c03.v1'] = 'cft.c03.v1'
    family: Literal['sql-search', 'redirect-allowlist']
    inputs: dict
    result: FixVerificationArtifact
    receipts: list[C03Receipt] = Field(default_factory=list)
    lifecycle: list[dict] = Field(default_factory=list)
    reason_codes: list[str] = Field(default_factory=list)
