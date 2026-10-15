"""LangGraph topology for the first AegisForge workflow."""

from __future__ import annotations

from typing import Any

from langgraph.graph import END, START, StateGraph
from langgraph.runtime import Runtime

from .agents import AuditAgent, BlueTeamAgent, PolicyEnforcerAgent, RedTeamAgent
from .context import RuntimeContext
from .state import RunState


def build_graph(*, agents: dict[str, Any] | None = None, checkpointer: Any = None) -> Any:
    """Build and compile the explicit red -> policy -> blue -> audit workflow."""

    selected = agents or {
        "red": RedTeamAgent(),
        "policy": PolicyEnforcerAgent(),
        "blue": BlueTeamAgent(),
        "audit": AuditAgent(),
    }
    builder = StateGraph(RunState, context_schema=RuntimeContext)

    def red_node(state: RunState, runtime: Runtime[RuntimeContext]) -> dict[str, object]:
        return selected["red"].run(state, runtime.context)

    def policy_node(state: RunState, runtime: Runtime[RuntimeContext]) -> dict[str, object]:
        return selected["policy"].run(state, runtime.context)

    def blue_node(state: RunState, runtime: Runtime[RuntimeContext]) -> dict[str, object]:
        return selected["blue"].run(state, runtime.context)

    def audit_node(state: RunState, runtime: Runtime[RuntimeContext]) -> dict[str, object]:
        return selected["audit"].run(state, runtime.context)

    builder.add_node("red", red_node)
    builder.add_node("policy", policy_node)
    builder.add_node("blue", blue_node)
    builder.add_node("audit", audit_node)
    builder.add_edge(START, "red")
    builder.add_edge("red", "policy")
    builder.add_conditional_edges(
        "policy",
        lambda state: "approved" if state["policy_decision"].allowed else "denied",
        {"approved": "blue", "denied": "audit"},
    )
    builder.add_edge("blue", "audit")
    builder.add_edge("audit", END)
    return builder.compile(checkpointer=checkpointer)
