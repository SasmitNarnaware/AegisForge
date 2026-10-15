"""Shared agent protocol and result type."""

from __future__ import annotations

from typing import Protocol

from ..context import RuntimeContext
from ..state import RunState


class Agent(Protocol):
    name: str
    system_prompt: str

    def run(self, state: RunState, context: RuntimeContext) -> dict[str, object]: ...
