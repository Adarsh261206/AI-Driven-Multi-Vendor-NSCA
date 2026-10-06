"""Cisco adapter metadata (backend side: descriptive only).

Real IOS-XE session logic ships inside generated user-side scripts
(see script_generator.py), which may use the operator's own automation
library of choice. This module records the Cisco contract the scripts
implement: config-mode hierarchy, per-context application, and the
show-command verification family. It opens no connections.
"""

from __future__ import annotations

from app.engines.remediation.adapters.base import DeviceAdapter


class CiscoDeviceAdapter(DeviceAdapter):
    """Cisco IOS-XE contract marker (no live implementation backend-side)."""

    vendor = "cisco"
    platform = "ios_xe"

    def connect(self, host: str, username: str, password: str,
                **kwargs) -> None:  # pragma: no cover - user-side contract
        raise NotImplementedError("user-side script only")

    def disconnect(self) -> None:  # pragma: no cover - user-side contract
        raise NotImplementedError("user-side script only")

    def get_running_config(self):  # pragma: no cover - user-side contract
        raise NotImplementedError("user-side script only")

    def backup_config(self):  # pragma: no cover - user-side contract
        raise NotImplementedError("user-side script only")

    def check_preconditions(self, plan):  # pragma: no cover
        raise NotImplementedError("user-side script only")

    def apply_changes(self, changes):  # pragma: no cover
        raise NotImplementedError("user-side script only")

    def verify_changes(self, verification):  # pragma: no cover
        raise NotImplementedError("user-side script only")

    def rollback(self, rollback):  # pragma: no cover
        raise NotImplementedError("user-side script only")


#: Context prefixes the Cisco adapter applies hierarchically.
HIERARCHICAL_CONTEXTS = ("line ", "interface ", "router ", "vlan ",
                         "ip access-list ", "crypto ", "control-plane")
