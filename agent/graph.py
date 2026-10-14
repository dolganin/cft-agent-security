from langgraph.graph import END, START, StateGraph

from agent.nodes import (
    analyse,
    build_report,
    collect_evidence,
    execute_action,
    form_hypothesis,
    guard_agent_budget,
    load_context,
    propose_action,
    reevaluate,
    score_finding,
    validate_action,
)
from agent.recovery import protected_node
from schemas.state import AgentState

# За одну итерацию T15 проходит несколько super-step, поэтому лимит LangGraph держим выше max_steps
_AGENT_GRAPH_RECURSION_LIMIT = 128


def _after_validation(state: AgentState) -> str:
    if state.get("status") != "inconclusive" and state.get("validation") is not None and state["validation"].approved:
        return "execute"
    # Отказ валидатора завершает ветку: обход политики не предусмотрен
    return "report"


def _after_proposal(state: AgentState) -> str:
    return "report" if state.get("status") == "inconclusive" else "validate_action"


def _after_budget_guard(state: AgentState) -> str:
    return "analyse" if state.get("status") == "budget_ok" else "report"


def _after_reevaluation(state: AgentState) -> str:
    if state.get("status") == "continue":
        # Новая итерация заново анализирует накопленный Evidence и строит свежий план.
        return "guard_agent_budget"
    return "report"


def _next_or_report(next_node):
    return lambda state: "report" if state.get("status") == "inconclusive" else next_node


def build_graph():
    graph = StateGraph(AgentState)

    graph.add_node("load_context", protected_node("load_context", load_context))
    graph.add_node("score_finding", protected_node("score_finding", score_finding))
    graph.add_node("guard_agent_budget", guard_agent_budget)
    graph.add_node("analyse", protected_node("analyse", analyse))
    graph.add_node("form_hypothesis", protected_node("form_hypothesis", form_hypothesis))
    graph.add_node("propose_action", protected_node("propose_action", propose_action))
    graph.add_node("validate_action", protected_node("validate_action", validate_action))
    graph.add_node("execute", protected_node("execute", execute_action))
    graph.add_node("collect_evidence", protected_node("collect_evidence", collect_evidence))
    graph.add_node("reevaluate", protected_node("reevaluate", reevaluate))
    graph.add_node("report", protected_node("report", build_report))

    graph.add_edge(START, "load_context")
    graph.add_conditional_edges("load_context", _next_or_report("score_finding"),
                                {"score_finding": "score_finding", "report": "report"})
    graph.add_conditional_edges("score_finding", _next_or_report("guard_agent_budget"),
                                {"guard_agent_budget": "guard_agent_budget", "report": "report"})
    graph.add_conditional_edges(
        "guard_agent_budget",
        _after_budget_guard,
        {
            "analyse": "analyse",
            "report": "report",
        },
    )
    graph.add_conditional_edges("analyse", _next_or_report("form_hypothesis"),
                                {"form_hypothesis": "form_hypothesis", "report": "report"})
    graph.add_conditional_edges("form_hypothesis", _next_or_report("propose_action"),
                                {"propose_action": "propose_action", "report": "report"})
    graph.add_conditional_edges(
        "propose_action",
        _after_proposal,
        {"validate_action": "validate_action", "report": "report"},
    )

    graph.add_conditional_edges(
        "validate_action",
        _after_validation,
        {
            "execute": "execute",
            "report": "report",
        },
    )

    graph.add_conditional_edges("execute", _next_or_report("collect_evidence"),
                                {"collect_evidence": "collect_evidence", "report": "report"})
    graph.add_conditional_edges("collect_evidence", _next_or_report("reevaluate"),
                                {"reevaluate": "reevaluate", "report": "report"})

    graph.add_conditional_edges(
        "reevaluate",
        _after_reevaluation,
        {
            "guard_agent_budget": "guard_agent_budget",
            "report": "report",
        },
    )

    graph.add_edge("report", END)

    compiled = graph.compile()
    compiled.config = {"recursion_limit": _AGENT_GRAPH_RECURSION_LIMIT}
    return compiled
