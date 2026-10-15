"""Runtime-only dependencies supplied to graph nodes."""

from __future__ import annotations

from dataclasses import dataclass, field

from .audit.recorder import AuditRecorder
from .sandbox.protocol import Sandbox


@dataclass
class RuntimeContext:
    """Dependencies kept out of graph state so they cannot be user-controlled."""

    sandbox: Sandbox
    audit: AuditRecorder = field(default_factory=AuditRecorder)
