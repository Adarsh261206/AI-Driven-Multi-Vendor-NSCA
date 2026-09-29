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

E04 contract implemented here:
- Deterministic diagnostics: stray ``end``/``next`` are parse errors,
  unclosed blocks are warnings, unrecognised lines are unknown sections;
  JSON envelopes and foreign-vendor content get an explicit error instead
  of a silent junk tree.
- Value-less ``set`` statements use ``None`` (spec ``string | null``),
  uniform with the other two parsers.
- ``unset`` keeps the negation visible (``unset_<key>``) and sets the
  first-class ``negated`` flag.
"""

from __future__ import annotations

import json
import re
import uuid
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
    # E04 F4: first-class negation flag ('unset' sets it; JUNOS-style
    # content has no negation). Uniform cross-parser ConfigNode shape.
    negated: bool = False

    def get_full_path(self) -> str:
        """Get full path as dot-separated string"""
        return ".".join(self.path + [self.key]) if self.key else ".".join(self.path)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (iterative: safe for deeply nested trees)."""
        return _node_to_dict(self)


def _node_to_dict(node: ConfigNode) -> dict[str, Any]:
    out: dict[str, Any] = {
        "key": node.key,
        "value": node.value,
        "path": list(node.path),
        "line_number": node.line_number,
        "raw_text": node.raw_text,
        "negated": node.negated,
    }
    if not node.children:
        return out
    kids = [
        {
            "key": c.key,
            "value": c.value,
            "path": list(c.path),
            "line_number": c.line_number,
            "raw_text": c.raw_text,
            "negated": c.negated,
        }
        for c in node.children
    ]
    out["children"] = kids
    stack = [(node.children[i], kids[i]) for i in range(len(node.children))]
    while stack:
        current, d = stack.pop()
        if current.children:
            sub = [
                {
                    "key": c.key,
                    "value": c.value,
                    "path": list(c.path),
                    "line_number": c.line_number,
                    "raw_text": c.raw_text,
                    "negated": c.negated,
                }
                for c in current.children
            ]
            d["children"] = sub
            stack.extend(
                (current.children[i], sub[i]) for i in range(len(current.children))
            )
    return out


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
    # E04 F12: result envelope required by the ParsedConfiguration contract
    # (docs/PROJECT_MASTER_SPEC.md:744-753).
    vendor: str = ""
    platform: str = ""
    id: str = ""
    ingested_config_id: Optional[str] = None

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
            "vendor": self.vendor,
            "platform": self.platform,
            "id": self.id,
            "ingested_config_id": self.ingested_config_id,
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

    # E04 F3 (dimension B): FortiOS structural markers. Content with none
    # of these is foreign to this parser and gets an explicit error.
    _CONFIG_RE = re.compile(r"^config\s+\S")
    _EDIT_RE = re.compile(r"^edit\s")
    _BARE_RE = re.compile(r"^(end|next)\s*$")

    def __init__(self):
        pass

    def parse(
        self,
        content: str,
        *,
        vendor: str = "",
        platform: str = "",
        ingested_config_id: Optional[str] = None,
    ) -> ParseResult:
        """
        Parse FortiOS configuration

        Args:
            content: Configuration content string
            vendor: Vendor label supplied by the caller (stored on the result)
            platform: Platform label supplied by the caller
            ingested_config_id: Ingestion id supplied by the caller

        Returns:
            ParseResult with parse tree, errors, and warnings
        """
        if not isinstance(content, str):
            raise TypeError("content must be str")
        result = ParseResult(
            parse_tree=[],
            parse_errors=[],
            parse_warnings=[],
            unknown_sections=[],
            vendor=vendor,
            platform=platform,
            id=uuid.uuid4().hex,
            ingested_config_id=ingested_config_id,
        )
        if not content.strip():
            return result
        if self._is_json(content):
            result.parse_errors.append(ParseError(
                0,
                "content is a JSON document, not FortiOS configuration",
                (content.splitlines() or [""])[0][:200],
            ))
            result.unknown_sections = self._meaningful_unknowns(content)
            return result

        lines = content.splitlines()
        if not self._has_markers(lines):
            meaningful = [
                (n, line.strip())
                for n, line in enumerate(lines, 1)
                if line.strip() and not line.strip().startswith(("#", "!"))
            ]
            if not meaningful:
                result.parse_warnings.append(ParseWarning(
                    0, "no configuration statements recognized in content", ""))
                return result
            result.parse_errors.append(ParseError(
                0,
                "content does not match FortiOS syntax "
                "(no 'config'/'edit'/'end'/'next' structure found)",
                "",
            ))
            result.unknown_sections = [
                UnknownSection(path=[], raw_text=s, line_numbers=[n])
                for n, s in meaningful
            ]
            return result

        errors: list[ParseError] = []
        warnings: list[ParseWarning] = []
        unknown_sections: list[UnknownSection] = []

        root_nodes: list[ConfigNode] = []
        section_stack: list[ConfigNode] = []
        edit_stack: list[ConfigNode] = []
        statements = 0

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
                statements += 1
                continue

            # Handle 'end' - close current config section
            if stripped == "end":
                if section_stack:
                    section_stack.pop()
                else:
                    errors.append(ParseError(line_num, "Unexpected 'end' without matching 'config'", stripped))
                statements += 1
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
                statements += 1
                continue

            # Handle 'next' - close current edit block
            if stripped == "next":
                if edit_stack:
                    edit_stack.pop()
                else:
                    errors.append(ParseError(line_num, "Unexpected 'next' without matching 'edit'", stripped))
                statements += 1
                continue

            # Handle 'set' command
            if stripped.startswith("set "):
                set_parts = stripped.split(None, 2)
                key = set_parts[1] if len(set_parts) > 1 else ""
                # E04 F13/V04-50: a value-less statement is None (spec
                # string|null), uniform with the other two parsers.
                value = set_parts[2] if len(set_parts) > 2 else None

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
                statements += 1
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
                    # E04 F4: the negation is also first-class.
                    negated=True,
                )

                if edit_stack:
                    edit_stack[-1].children.append(new_node)
                elif section_stack:
                    section_stack[-1].children.append(new_node)
                else:
                    root_nodes.append(new_node)
                statements += 1
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
        if statements == 0 and not unknown_sections:
            warnings.append(ParseWarning(
                0, "no configuration statements recognized in content", ""))

        result.parse_tree = root_nodes
        result.parse_errors = errors
        result.parse_warnings = warnings
        result.unknown_sections = unknown_sections
        return result

    # ------------------------------------------------------------------
    # Pre-scan helpers (deterministic, content-shape only)
    # ------------------------------------------------------------------

    @staticmethod
    def _is_json(text: str) -> bool:
        stripped = text.lstrip()
        if not stripped or stripped[0] not in "{[":
            return False
        try:
            json.loads(stripped)
        except Exception:
            return False
        return True

    @classmethod
    def _has_markers(cls, lines: list[str]) -> bool:
        for line in lines:
            s = line.strip()
            if not s or s.startswith(("#", "!")):
                continue
            if cls._CONFIG_RE.match(s) or cls._EDIT_RE.match(s) \
                    or cls._BARE_RE.match(s):
                return True
        return False

    @staticmethod
    def _meaningful_unknowns(content: str) -> list[UnknownSection]:
        out: list[UnknownSection] = []
        for n, line in enumerate(content.splitlines(), 1):
            s = line.strip()
            if s and not s.startswith(("#", "!")):
                out.append(UnknownSection(path=[], raw_text=s, line_numbers=[n]))
        return out

    @classmethod
    def find_all(cls, tree: list[ConfigNode], pattern: str) -> list[ConfigNode]:
        """Find all nodes matching a pattern (iterative: safe for deep trees).

        Uniform cross-parser semantics (F13): ``re.search(pattern,
        node.key)`` or ``re.search(pattern, node.value or "")``.
        """
        regex = re.compile(pattern, re.IGNORECASE)
        results: list[ConfigNode] = []
        stack = list(reversed(tree))
        while stack:
            node = stack.pop()
            if regex.search(node.key or "") \
                    or (node.value and regex.search(node.value)):
                results.append(node)
            stack.extend(reversed(node.children))
        return results

    @classmethod
    def get_section(
        cls, tree: list[ConfigNode], path: list[str]
    ) -> Optional[ConfigNode]:
        """Get a section node by path from the root of the tree.

        Uniform cross-parser semantics (F13): a segment first matches a
        child's key, then a child's value; the final segment may also match
        the current node's own value.
        """
        nodes = list(tree)
        current: Optional[ConfigNode] = None
        for seg in path:
            key_hit = next((c for c in nodes if c.key == seg), None)
            if key_hit is not None:
                current = key_hit
                nodes = key_hit.children
                continue
            val_hit = next((c for c in nodes if c.value == seg), None)
            if val_hit is not None:
                current = val_hit
                nodes = val_hit.children
                continue
            if current is not None and current.value == seg:
                return current
            return None
        return current
