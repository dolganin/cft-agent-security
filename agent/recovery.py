"""Finding-local failure boundaries; cancellation and permissions remain authoritative."""

from functools import wraps

from agent.budget import ReasoningBudgetExpired
from agent.loop import wall_clock_exhausted
from pipeline.cancellation import RunCancelled, check_cancelled
from pipeline.errors import error_from_exception
from schemas.agent_loop import AgentDecisionRecord

REASONING_NODES = {"analyse", "form_hypothesis", "propose_action", "reevaluate"}
PRE_ACTION_NODES = {"analyse", "form_hypothesis", "propose_action", "validate_action", "execute"}


def stop_update(state, reason, explanation):
    plan = state.get("dynamic_plan")
    return {
        "status": "inconclusive",
        "stop_reason": reason,
        "decision_history": [
            *state.get("decision_history", []),
            AgentDecisionRecord(
                step=int(state.get("iteration_count", 0)),
                outcome="stop",
                reason=explanation,
                stop_reason=reason,
                evidence_ids=[item.id for item in state.get("evidence", [])],
                plan_id=plan.id if plan is not None else None,
            ),
        ],
    }


def protected_node(name, function):
    """Return a serializable failure state instead of discarding previous observations.

    In-flight operations retain their existing provider/Executor timeouts. This
    cooperative deadline prevents starting the next operation after expiration;
    it does not interrupt a worker or skip mandatory cleanup/evidence collection.
    """

    @wraps(function)
    def run(state):
        check_cancelled()
        if name in PRE_ACTION_NODES and wall_clock_exhausted(state):
            return stop_update(
                state,
                "wall_clock_budget_exhausted",
                "Wall-clock budget exhausted before " + name + ".",
            )
        try:
            return function(state)
        except RunCancelled:
            raise
        except ReasoningBudgetExpired:
            return stop_update(
                state,
                "wall_clock_budget_exhausted",
                "Reasoning deadline exhausted before another provider request.",
            )
        except Exception as exc:  # noqa: BLE001 - finding boundary; cancellation propagates above
            layer = (
                "llm"
                if name in REASONING_NODES
                else "executor"
                if name == "execute"
                else "validator"
                if name == "validate_action"
                else "storage"
                if name == "collect_evidence"
                else "agent"
            )
            error = error_from_exception(
                exc, layer=layer, public_message="Finding workflow node failed: " + name
            )
            reason = (
                "model_failure"
                if name in REASONING_NODES
                else "execution_timeout"
                if name == "execute" and error.code == "TIMEOUT"
                else "execution_failed"
                if name == "execute"
                else "workflow_failure"
            )
            update = stop_update(state, reason, error.message)
            update["workflow_errors"] = [*state.get("workflow_errors", []), error]
            action = state.get("proposed_action")
            history = list(state.get("action_history", []))
            if action is not None and name in {"execute", "collect_evidence"}:
                history = [
                    item.model_copy(update={"error": error, "execution": state.get("execution")})
                    if item.action.id == action.id
                    else item
                    for item in history
                ]
                update["action_history"] = history
            if name == "report":
                # A failed optional scoring recheck must not discard the graph's
                # completed history. Clear that input for the failure report.
                from reporting.builder import build_final_report

                report = build_final_report({**state, **update, "scoring_review": None})
                update["final_report"] = report
                update["status"] = report.status
            return update

    return run
