"""Device adapter abstraction (interface only).

No implementation here connects anywhere: concrete adapters live in
generated user-side scripts. The backend references this interface
solely to document the execution contract.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class DeviceAdapter(ABC):
    """Execution contract for one vendor family."""

    vendor: str = ""
    platform: str = ""

    @abstractmethod
    def connect(self, host: str, username: str, password: str,
                **kwargs: Any) -> None:
        """Open a management session (user-side only)."""

    @abstractmethod
    def disconnect(self) -> None:
        """Close the management session."""

    @abstractmethod
    def get_running_config(self) -> str:
        """Return the current running configuration text."""

    @abstractmethod
    def backup_config(self) -> dict[str, Any]:
        """Snapshot config + hash BEFORE any change."""

    @abstractmethod
    def check_preconditions(self, plan: dict[str, Any]) -> list[dict]:
        """Re-verify preconditions against live state."""

    @abstractmethod
    def apply_changes(self, changes: list[dict]) -> dict[str, Any]:
        """Apply structured {context, commands} changes."""

    @abstractmethod
    def verify_changes(self, verification: list[str]) -> dict[str, Any]:
        """Run post-checks; report pass/fail per command."""

    @abstractmethod
    def rollback(self, rollback: list[dict]) -> dict[str, Any]:
        """Apply the plan's rollback changes."""
