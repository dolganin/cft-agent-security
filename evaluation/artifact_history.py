"""Lossless evaluator audit traces with recursive secret redaction."""

from __future__ import annotations

import json
import re
from pathlib import Path

from pydantic import BaseModel

from security.error_redaction import redact_error_message

_SECRET_KEY = re.compile(
    r"(?:^|[_-])(?:secret|password|passwd|access_token|refresh_token|api_key|credential)s?$"
    r"|(?:^|[_-])token$",
    re.IGNORECASE,
)


def sanitize(value, *, key: str = ""):
    if _SECRET_KEY.search(key):
        return "[REDACTED]"
    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(name): sanitize(item, key=str(name)) for name, item in value.items()}
    if isinstance(value, list):
        return [sanitize(item, key=key) for item in value]
    if isinstance(value, tuple):
        return [sanitize(item, key=key) for item in value]
    if isinstance(value, str):
        return redact_error_message(value, max_length=8192)
    return value


def persist_agent_trace(root: Path, finding_id: str, state: dict) -> Path:
    """Persist proposals, Validator decisions, executions and Evidence after graph.invoke."""
    payload = sanitize({
        "schema_version": "benchmark.agent_trace.v2",
        "finding_id": finding_id,
        "plans": state.get("plan_history", []),
        "actions": state.get("action_history", []),
        "decisions": state.get("decision_history", []),
        "evidence": state.get("evidence", []),
        "status": state.get("status"),
        "stop_reason": state.get("stop_reason"),
        "iterations": state.get("iteration_count", 0),
        "workflow_errors": state.get("workflow_errors", []),
        "reasoning_events": state.get("reasoning_events", []),
    })
    destination = root / "traces" / (re.sub(r"[^A-Za-z0-9_.-]", "_", finding_id) + ".json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(".json.tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)
    return destination
