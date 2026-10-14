"""Runtime-only reasoning deadline shared by all provider attempts of a node."""

from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime
from math import isfinite
from time import monotonic

_DEADLINE: ContextVar[float | None] = ContextVar("agent_reasoning_deadline", default=None)


class ReasoningBudgetExpired(TimeoutError):
    pass


@contextmanager
def reasoning_budget(state):
    budget = float(state.get("wall_clock_budget_seconds", 120.0))
    if not isfinite(budget):
        raise ValueError("Agent wall-clock budget must be finite")
    started = state.get("started_at")
    elapsed = (datetime.now(UTC) - started).total_seconds() if started is not None else 0.0
    token = _DEADLINE.set(monotonic() + max(0.0, budget - elapsed))
    try:
        yield
    finally:
        _DEADLINE.reset(token)


def bounded_timeout(configured):
    deadline = _DEADLINE.get()
    if deadline is None:
        return configured
    remaining = deadline - monotonic()
    if remaining <= 0:
        raise ReasoningBudgetExpired("Agent reasoning deadline exhausted")
    return min(configured, remaining)
