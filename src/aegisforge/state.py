"""LangGraph state shared by the four core agents."""

from __future__ import annotations

from typing import TypedDict

from .domain import (
    Action,
    AuditEvent,
    AuditReport,
    Change,
    Finding,
    PolicyDecision,
    Scenario,
    SecurityPolicy,
)


class RunState(TypedDict, total=False):
    scenario: Scenario
    findings: list[Finding]
    proposed_actions: list[Action]
    policies: list[SecurityPolicy]
    policy_decision: PolicyDecision
    changes: list[Change]
    events: list[AuditEvent]
    report: AuditReport
