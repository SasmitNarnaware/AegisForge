"""Audit Agent: produce a deterministic report for every graph path."""

from __future__ import annotations

from ..context import RuntimeContext
from ..domain import AuditReport
from ..state import RunState


class AuditAgent:
    name = "audit"
    system_prompt = (
        "You maintain an append-only record of agent actions and decisions. Summarize the "
        "run using stable identifiers and digests; never alter the scenario or sandbox."
    )

    def run(self, state: RunState, context: RuntimeContext) -> dict[str, object]:
        decision = state.get("policy_decision")
        decision_label = "approved" if decision and decision.allowed else "denied"
        context.audit.record(self.name, "run_completed", decision_label)
        events = context.audit.events
        report = AuditReport(
            scenario_id=state["scenario"].scenario_id,
            decision=decision_label,
            findings=len(state.get("findings", [])),
            proposed_actions=len(state.get("proposed_actions", [])),
            applied_changes=len(state.get("changes", [])),
            sandbox_digest=context.sandbox.snapshot().digest,
            event_count=len(events),
            event_digests=tuple(context.audit.digest(event) for event in events),
        )
        return {"report": report, "events": events}
