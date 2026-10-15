"""Single construction boundary for the application and all four agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .agents import AuditAgent, BlueTeamAgent, PolicyEnforcerAgent, RedTeamAgent
from .context import RuntimeContext
from .graph import build_graph
from .sandbox.memory import MemorySandbox


@dataclass
class Application:
    graph: Any
    context: RuntimeContext
    agents: tuple[object, ...]


def initialize(*, seed: int = 0, checkpointer: Any = None) -> Application:
    """Initialize the sandbox, agents, runtime context, and compiled graph."""

    agents = (RedTeamAgent(), PolicyEnforcerAgent(), BlueTeamAgent(), AuditAgent())
    agent_map = {"red": agents[0], "policy": agents[1], "blue": agents[2], "audit": agents[3]}
    context = RuntimeContext(
        sandbox=MemorySandbox(files={"telemetry/seed.txt": str(seed)}),
    )
    return Application(
        graph=build_graph(agents=agent_map, checkpointer=checkpointer),
        context=context,
        agents=agents,
    )
