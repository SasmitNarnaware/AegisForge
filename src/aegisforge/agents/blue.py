"""Blue Team Agent: apply only the policy-approved defensive actions."""

from __future__ import annotations

from ..context import RuntimeContext
from ..domain import Change
from ..state import RunState


class BlueTeamAgent:
    name = "blue_team"
    system_prompt = (
        "You contain simulated threats. Re-check policy approval immediately before every "
        "sandbox mutation, and report changes. Never execute a raw command or make a network call."
    )

    def run(self, state: RunState, context: RuntimeContext) -> dict[str, object]:
        decision = state["policy_decision"]
        actions = state.get("proposed_actions", [])
        if not decision.allowed:
            context.audit.record(self.name, "changes_skipped", "policy denied all actions")
            return {"changes": [], "events": context.audit.events}

        changes: list[Change] = context.sandbox.apply_approved(
            actions, decision.approved_action_ids
        )
        context.audit.record(self.name, "changes_applied", str(len(changes)))
        return {"changes": changes, "events": context.audit.events}
