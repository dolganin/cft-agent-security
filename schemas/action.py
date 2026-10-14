from pydantic import BaseModel, Field, model_serializer

from schemas.b06_verification import FixtureExecutionBinding
from schemas.research import ResearchBinding
from schemas.verification_binding import VerificationBinding


class ActionProposal(BaseModel):
    # Это запрос на проверку; право на выполнение появляется только после валидатора
    id: str
    tool: str
    target: str
    environment: str = "local"
    iteration: int = Field(default=1, ge=1)
    parameters: dict = Field(default_factory=dict)
    purpose: str
    expected_evidence: str
    service: str | None = None
    endpoint: str | None = None
    verification_binding: VerificationBinding | None = None
    fixture_binding: FixtureExecutionBinding | None = None
    research_binding: ResearchBinding | None = None

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        payload = handler(self)
        # Preserve the exact historical ActionProposal wire shape/approval digest.
        if self.research_binding is None:
            payload.pop("research_binding", None)
        return payload
