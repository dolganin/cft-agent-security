"""Opt-in tool descriptions for a future research harness; proposals only."""
from schemas.action import ActionProposal
from schemas.research import RESEARCH_REQUESTS, ResearchScope
from security.research_scope import binding_for, validate_research_action


def research_tool_contracts():
    return [{"name": name, "input_schema": model.model_json_schema(),
             "validator_required": True, "output": "ExecutionResult/research_observation",
             "enabled_by": "operator research scope and policies/research.yaml"}
            for name, model in RESEARCH_REQUESTS.items()]


def research_proposal(*, scope: ResearchScope, action_id: str, tool: str, parameters: dict,
                      purpose: str, expected_evidence: str, service: str | None = None,
                      endpoint: str | None = None, iteration: int = 1) -> ActionProposal:
    action = ActionProposal(id=action_id, tool=tool, parameters=parameters,
                            target=scope.target_id, environment=scope.environment,
                            purpose=purpose, expected_evidence=expected_evidence,
                            service=service, endpoint=endpoint, iteration=iteration,
                            research_binding=binding_for(scope))
    validate_research_action(scope, action)
    return action
