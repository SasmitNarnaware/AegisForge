from __future__ import annotations

import pytest

from aegisforge.agents import AuditAgent, BlueTeamAgent, PolicyEnforcerAgent
from aegisforge.context import RuntimeContext
from aegisforge.domain import Action, Scenario
from aegisforge.graph import build_graph
from aegisforge.initializer import initialize
from aegisforge.sandbox.memory import MemorySandbox, SandboxViolation


def run(description: str, *, seed: int = 7):
    app = initialize(seed=seed)
    result = app.graph.invoke(
        {"scenario": Scenario(scenario_id="test", description=description, seed=seed)},
        context=app.context,
    )
    return app, result


def test_approved_flow_visits_all_agents_and_changes_virtual_control() -> None:
    app, result = run("A prompt injection attempts a malicious tool call.")

    assert result["report"].decision == "approved"
    assert result["report"].applied_changes == 2
    assert result["events"][-1].event_type == "run_completed"
    assert dict(app.context.sandbox.snapshot().controls) == {
        "tool:external_exec": "disabled",
        "tool:prompt_interpreter": "disabled",
    }


def test_denied_policy_path_skips_blue_mutation() -> None:
    class InvalidRedAgent:
        def run(self, state, context):
            return {
                "findings": [],
                "proposed_actions": [Action("bad-1", "execute_shell", "host")],
                "events": context.audit.events,
            }

    context = RuntimeContext(sandbox=MemorySandbox())
    graph = build_graph(
        agents={
            "red": InvalidRedAgent(),
            "policy": PolicyEnforcerAgent(),
            "blue": BlueTeamAgent(),
            "audit": AuditAgent(),
        }
    )
    result = graph.invoke(
        {"scenario": Scenario(scenario_id="denied", description="tampered action")},
        context=context,
    )

    assert result["report"].decision == "denied"
    assert result["report"].applied_changes == 0
    assert context.sandbox.snapshot().controls == ()


def test_sandbox_rejects_unapproved_or_traversing_actions() -> None:
    sandbox = MemorySandbox()

    with pytest.raises(SandboxViolation, match="explicitly approved"):
        sandbox.apply_approved(
            [Action("a-1", "write_file", "notes/result.txt", "blocked")], []
        )
    with pytest.raises(SandboxViolation, match="traversing"):
        sandbox.apply_approved(
            [Action("a-1", "write_file", "../result.txt", "blocked")], ["a-1"]
        )


def test_same_seed_and_input_produce_same_report() -> None:
    _, first = run("A prompt injection attempts a malicious tool call.")
    _, second = run("A prompt injection attempts a malicious tool call.")

    assert first["report"] == second["report"]
    assert first["events"] == second["events"]
