"""
Fortinet FortiOS Configuration Parser

Parses FortiOS configurations into a structured parse tree.

Supports FortiOS config styles:
  1. Hierarchical config blocks:
        config system interface
            edit "port1"
                set mode static
                set ip 192.168.1.1/24
            next
        end
  2. Set-style within blocks:
        set status enable
        set mode static
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Any


@dataclass
class ConfigNode:
    """A node in the configuration parse tree"""
    path: list[str]
    key: str
    value: Optional[str] = None
    children: list[ConfigNode] = field(default_factory=list)
    line_number: int = 0
    raw_text: str = ""

    def get_full_path(self) -> str:
        """Get full path as dot-separated string"""
        return ".".join(self.path + [self.key]) if self.key else ".".join(self.path)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary"""
        result: dict[str, Any] = {
            "key": self.key,
            "value": self.value,
            "path": self.path,
            "line_number": self.line_number,
            "raw_text": self.raw_text,
        }
        if self.children:
            result["children"] = [child.to_dict() for child in self.children]
        return result


@dataclass
class ParseError:
    """Parse error details"""
    line_number: int
    message: str
    raw_text: str


@dataclass
class ParseWarning:
    """Parse warning details"""
    line_number: int
    message: str
    raw_text: str


@dataclass
class UnknownSection:
    """Unknown configuration section"""
    path: list[str]
    raw_text: str
    line_numbers: list[int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "raw_text": self.raw_text,
            "line_numbers": self.line_numbers,
        }


@dataclass
class ParseResult:
    """Result of configuration parsing"""
    parse_tree: list[ConfigNode]
    parse_errors: list[ParseError]
    parse_warnings: list[ParseWarning]
    unknown_sections: list[UnknownSection]

    def to_dict(self) -> dict[str, Any]:
        return {
            "parse_tree": [node.to_dict() for node in self.parse_tree],
            "parse_errors": [
                {"line_number": e.line_number, "message": e.message, "raw_text": e.raw_text}
                for e in self.parse_errors
            ],
            "parse_warnings": [
                {"line_number": w.line_number, "message": w.message, "raw_text": w.raw_text}
                for w in self.parse_warnings
            ],
            "unknown_sections": [s.to_dict() for s in self.unknown_sections],
        }


class FortiOSParser:
    """
    Fortinet FortiOS Configuration Parser

    Parses FortiOS configurations into a structured parse tree.
    Handles:
    - Hierarchical config blocks (config ... end)
    - Edit blocks within config sections
    - Set commands within edit blocks
    - Nested config sections
    """

    # Known top-level config sections
    CONFIG_SECTIONS = {
        "system", "firewall", "router", "switch", "wireless", "vpn",
        "log", "ips", "application", "web-proxy", "dns", "ntp",
        "snmp", "certificate", "user", "ssh", "ftp", "icmp", "diagnostic",
    }

    def __init__(self):
        pass

    def parse(self, content: str) -> ParseResult:
        """
        Parse FortiOS configuration

        Args:
            content: Configuration content string

        Returns:
            ParseResult with parse tree, errors, and warnings
        """
        lines = content.splitlines()
        errors: list[ParseError] = []
        warnings: list[ParseWarning] = []
        unknown_sections: list[UnknownSection] = []

        root_nodes: list[ConfigNode] = []
        section_stack: list[ConfigNode] = []
        edit_stack: list[ConfigNode] = []

        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue

            # Handle 'config' block start
            if stripped.startswith("config "):
                section_parts = stripped.split(None, 1)
                section_name = section_parts[1].strip() if len(section_parts) > 1 else ""

                new_node = ConfigNode(
                    path=[n.key for n in section_stack],
                    key="config",
                    value=section_name,
                    line_number=line_num,
                    raw_text=stripped,
                )

                if section_stack:
                    section_stack[-1].children.append(new_node)
                else:
                    root_nodes.append(new_node)

                section_stack.append(new_node)
                continue

            # Handle 'end' - close current config section
            if stripped == "end":
                if section_stack:
                    section_stack.pop()
                else:
                    errors.append(ParseError(line_num, "Unexpected 'end' without matching 'config'", stripped))
                continue

            # Handle 'edit' block start
            if stripped.startswith("edit "):
                edit_parts = stripped.split(None, 1)
                edit_name = edit_parts[1].strip() if len(edit_parts) > 1 else ""

                new_node = ConfigNode(
                    path=[n.key for n in section_stack] + ["edit"],
                    key="edit",
                    value=edit_name,
                    line_number=line_num,
                    raw_text=stripped,
                )

                if section_stack:
                    section_stack[-1].children.append(new_node)
                elif edit_stack:
                    edit_stack[-1].children.append(new_node)
                else:
                    root_nodes.append(new_node)

                edit_stack.append(new_node)
                continue

            # Handle 'next' - close current edit block
            if stripped == "next":
                if edit_stack:
                    edit_stack.pop()
                else:
                    errors.append(ParseError(line_num, "Unexpected 'next' without matching 'edit'", stripped))
                continue

            # Handle 'set' command
            if stripped.startswith("set "):
                set_parts = stripped.split(None, 2)
                key = set_parts[1] if len(set_parts) > 1 else ""
                value = set_parts[2] if len(set_parts) > 2 else ""

                new_node = ConfigNode(
                    path=[n.key for n in section_stack] + [n.key for n in edit_stack],
                    key=key,
                    value=value,
                    line_number=line_num,
                    raw_text=stripped,
                )

                if edit_stack:
                    edit_stack[-1].children.append(new_node)
                elif section_stack:
                    section_stack[-1].children.append(new_node)
                else:
                    root_nodes.append(new_node)
                continue

            # Handle 'unset' command
            if stripped.startswith("unset "):
                unset_parts = stripped.split(None, 1)
                key = unset_parts[1].strip() if len(unset_parts) > 1 else ""

                new_node = ConfigNode(
                    path=[n.key for n in section_stack] + [n.key for n in edit_stack],
                    key=f"unset_{key}",
                    value=None,
                    line_number=line_num,
                    raw_text=stripped,
                )

                if edit_stack:
                    edit_stack[-1].children.append(new_node)
                elif section_stack:
                    section_stack[-1].children.append(new_node)
                else:
                    root_nodes.append(new_node)
                continue

            # Unknown line
            unknown_sections.append(UnknownSection(
                path=[n.key for n in section_stack] + [n.key for n in edit_stack],
                raw_text=stripped,
                line_numbers=[line_num],
            ))

        # Check for unclosed blocks
        if section_stack:
            warnings.append(ParseWarning(
                0,
                f"Unclosed config sections: {', '.join(n.value or n.key for n in section_stack)}",
                "",
            ))
        if edit_stack:
            warnings.append(ParseWarning(
                0,
                f"Unclosed edit blocks: {', '.join(n.value or n.key for n in edit_stack)}",
                "",
            ))

        return ParseResult(
            parse_tree=root_nodes,
            parse_errors=errors,
            parse_warnings=warnings,
            unknown_sections=unknown_sections,
        )

    def find_all(self, tree: list[ConfigNode], key: str) -> list[ConfigNode]:
        """Find all nodes with the given key anywhere in the tree."""
        results: list[ConfigNode] = []
        for node in tree:
            if node.key == key:
                results.append(node)
            results.extend(self.find_all(node.children, key))
        return results

    def get_section(self, tree: list[ConfigNode], path: list[str]) -> Optional[ConfigNode]:
        """Get a section node by path from the root of the tree."""
        current = tree
        node = None
        for part in path:
            found = None
            for child in current:
                if child.key == part or child.value == part:
                    found = child
                    break
            if found is None:
                return None
            node = found
            current = node.children
        return node
