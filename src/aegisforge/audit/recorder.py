"""Deterministic append-only audit recording."""

from __future__ import annotations

import hashlib
import json

from ..domain import AuditEvent


class AuditRecorder:
    """Record agent activity without timestamps, UUIDs, or host-side effects."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    @property
    def events(self) -> list[AuditEvent]:
        return list(self._events)

    def record(self, agent: str, event_type: str, detail: str) -> AuditEvent:
        event = AuditEvent(
            sequence=len(self._events) + 1,
            agent=agent,
            event_type=event_type,
            detail=detail,
        )
        self._events.append(event)
        return event

    @staticmethod
    def digest(event: AuditEvent) -> str:
        payload = json.dumps(
            {
                "sequence": event.sequence,
                "agent": event.agent,
                "event_type": event.event_type,
                "detail": event.detail,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
