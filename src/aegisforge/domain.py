"""Small, typed domain objects shared by agents and the graph.

The first stage intentionally uses dataclasses instead of provider-specific
message objects. This keeps the orchestration deterministic and makes it safe
to replace the rule-based agents with model-backed adapters later.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

Severity = Literal["low", "medium", "high", "critical"]
ActionKind = Literal["set_control", "write_file", "record_observation"]


@dataclass(frozen=True)
class Scenario:
    """Untrusted input describing a simulated security exercise."""

    scenario_id: str
    description: str
    seed: int = 0


@dataclass(frozen=True)
class Finding:
    finding_id: str
    severity: Severity
    title: str
    description: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class Action:
    """A typed defensive mutation; arbitrary shell/tool calls are not allowed."""

    action_id: str
    kind: ActionKind
    target: str
    value: str = ""


@dataclass(frozen=True)
class SecurityPolicy:
    policy_id: str
    statement: str
    allowed_action_kinds: tuple[ActionKind, ...]


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    approved_action_ids: tuple[str, ...] = ()
    policy_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class Change:
    action_id: str
    applied: bool
    result: str


@dataclass(frozen=True)
class AuditEvent:
    sequence: int
    agent: str
    event_type: str
    detail: str


@dataclass(frozen=True)
class AuditReport:
    scenario_id: str
    decision: str
    findings: int
    proposed_actions: int
    applied_changes: int
    sandbox_digest: str
    event_count: int
    event_digests: tuple[str, ...]


def as_public_dict(value: object) -> dict[str, object]:
    """Convert a dataclass to stable JSON-friendly data for CLI output/tests."""

    return asdict(value) if hasattr(value, "__dataclass_fields__") else {"value": value}
