"""An in-memory sandbox with no process, network, or host-file access."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Collection, Sequence

from ..domain import Action, Change
from .protocol import SandboxSnapshot


class SandboxViolation(ValueError):
    """Raised when a typed action crosses the sandbox boundary."""


class MemorySandbox:
    """Virtual files and controls used for deterministic security simulations."""

    ALLOWED_KINDS = frozenset({"set_control", "write_file", "record_observation"})

    def __init__(self, *, files: dict[str, str] | None = None) -> None:
        self._files = dict(files or {})
        self._controls: dict[str, str] = {}

    def snapshot(self) -> SandboxSnapshot:
        files = tuple(sorted(self._files.items()))
        controls = tuple(sorted(self._controls.items()))
        canonical = json.dumps(
            {"files": files, "controls": controls},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return SandboxSnapshot(
            files=files,
            controls=controls,
            digest=hashlib.sha256(canonical).hexdigest(),
        )

    def apply_approved(
        self, actions: Sequence[Action], approved_action_ids: Collection[str]
    ) -> list[Change]:
        """Apply only approved, typed actions and fail closed on any mismatch."""

        approved = set(approved_action_ids)
        if any(action.action_id not in approved for action in actions):
            raise SandboxViolation("every action must be explicitly approved")

        changes: list[Change] = []
        for action in actions:
            self._validate_action(action)
            if action.kind == "set_control":
                self._controls[action.target] = action.value or "enabled"
                result = f"control {action.target}={self._controls[action.target]}"
            elif action.kind == "write_file":
                path = self._normalize_path(action.target)
                self._files[path] = action.value
                result = f"wrote virtual file {path}"
            else:
                result = f"recorded observation for {action.target}"
            changes.append(Change(action_id=action.action_id, applied=True, result=result))
        return changes

    def _validate_action(self, action: Action) -> None:
        if action.kind not in self.ALLOWED_KINDS:
            raise SandboxViolation(f"unsupported action kind: {action.kind}")
        if not action.target or "\x00" in action.target:
            raise SandboxViolation("action target must be non-empty and NUL-free")
        if action.kind == "write_file":
            self._normalize_path(action.target)
            if len(action.value.encode("utf-8")) > 4096:
                raise SandboxViolation("virtual file exceeds 4096 bytes")

    @staticmethod
    def _normalize_path(path: str) -> str:
        if path.startswith("/") or "\\" in path:
            raise SandboxViolation("sandbox paths must be relative POSIX paths")
        parts = path.split("/")
        if not path or any(part in {"", ".", ".."} for part in parts):
            raise SandboxViolation("invalid or traversing sandbox path")
        return "/".join(parts)
