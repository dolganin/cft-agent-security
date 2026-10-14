"""Deterministic checks shared by Validator and Executor."""
from urllib.parse import unquote, urlsplit

from schemas.action import ActionProposal
from schemas.research import RESEARCH_REQUESTS, ResearchBinding, ResearchScope


def binding_for(scope: ResearchScope) -> ResearchBinding:
    return ResearchBinding(session_id=scope.session_id, scope_sha256=scope.digest,
                           source_snapshot=scope.source_snapshot)


def validate_research_action(scope: ResearchScope | None, action: ActionProposal):
    if (scope is None or action.research_binding != binding_for(scope)
            or action.target != scope.target_id or action.environment != scope.environment
            or action.verification_binding is not None or action.fixture_binding is not None):
        raise ValueError("Research requires the current operator-owned scope and source binding")
    model = RESEARCH_REQUESTS.get(action.tool)
    if model is None:
        raise ValueError("Unsupported research capability")
    request = model.model_validate(action.parameters)
    if action.tool == "target_http":
        service = scope.services.get(action.service or "")
        if service is None or action.endpoint != request.path:
            raise ValueError("HTTP requires an operator service and matching local endpoint")
        path = urlsplit(unquote(request.path)).path
        if request.role_handle is not None and request.role_handle not in service.role_handles:
            raise ValueError("Unknown operator role handle")
        if request.method in {"GET", "HEAD"}:
            if request.body or not any(path == prefix.rstrip("/") or
                                      path.startswith(prefix.rstrip("/") + "/")
                                      for prefix in service.read_prefixes):
                raise ValueError("Read path is outside the operator HTTP scope")
        elif path not in service.write_paths.get(request.method, []):
            raise ValueError("Write path is outside the operator fixture grant")
    elif action.service is not None or action.endpoint is not None:
        raise ValueError("Source/workspace actions cannot request runtime network scope")
    if action.tool == "read_source" and request.path not in scope.source_files:
        raise ValueError("Source file is not in the trusted projected inventory")
    if action.tool == "search_source" and any(p not in scope.source_files for p in request.paths):
        raise ValueError("Search files are outside the trusted inventory")
    return request
