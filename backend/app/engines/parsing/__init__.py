"""Vendor configuration parsing engines.

Central parser-selection contract (E04 F3/F9/F10): exactly one parser per
supported vendor family (Cisco IOS, Junos, FortiOS). Unsupported or unknown
vendors get an explicit no-parser outcome (None) so callers stop instead of
parsing with another vendor's parser.

The platform argument is part of the caller contract but does not change
the selection: a single parser covers every platform of its vendor family.
"""

from __future__ import annotations

from app.engines.parsing.cisco import CiscoIOSParser
from app.engines.parsing.fortinet import FortiOSParser
from app.engines.parsing.juniper import JunosParser

SUPPORTED_PARSING_VENDORS = frozenset({"cisco", "juniper", "fortinet"})

__all__ = [
    "CiscoIOSParser",
    "FortiOSParser",
    "JunosParser",
    "SUPPORTED_PARSING_VENDORS",
    "get_parser",
]


def get_parser(vendor: str, platform: str = ""):
    """Return the parser for a vendor, or None when unsupported.

    Args:
        vendor: Vendor label (e.g. "cisco", "juniper", "fortinet").
        platform: Platform label (accepted for the caller contract; one
            parser covers each vendor family, so it never changes the
            selection).

    Returns:
        A parser instance, or None for unsupported/unknown vendors.
    """
    vendor_lower = (vendor or "").strip().lower()
    if vendor_lower == "cisco":
        return CiscoIOSParser()
    if vendor_lower == "juniper":
        return JunosParser()
    if vendor_lower == "fortinet":
        return FortiOSParser()
    return None
