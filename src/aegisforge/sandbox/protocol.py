"""Narrow sandbox contract used by agents."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence

from ..domain import Action, Change


@dataclass(frozen=True)
class SandboxSnapshot:
    files: tuple[tuple[str, str], ...]
    controls: tuple[tuple[str, str], ...]
    digest: str


class Sandbox(Protocol):
    def snapshot(self) -> SandboxSnapshot: ...

    def apply_approved(
        self, actions: Sequence[Action], approved_action_ids: Sequence[str]
    ) -> list[Change]: ...
