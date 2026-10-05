"""
Juniper JUNOS Configuration Parser

Parses JUNOS configurations into a structured parse tree.

Supports three JUNOS config styles:
  1. Hierarchical brace style:
        system {
            host-name R1;
            services {
                ssh;
            }
        }
  2. Set style:
        set system host-name R1
        set system services ssh
  3. '##'-prefixed hierarchical output (show configuration format used by
     many automation scripts and the CIS benchmark audit excerpts).

The parser preserves hierarchy, context, repeated blocks, line numbers and
raw text so that evidence chains can reference the exact configuration lines
that drove a compliance decision.

E04 contract implemented here:
- Mixed brace/set content is parsed per statement (no whole-file style
  switch, no blind 4-char strip of non-set lines).
- Set-style leaf split: ``KNOWN_LEAF_KEYS`` plus a numeric/quoted value
  heuristic, so ``set ... peer-as 65001`` keeps 65001 as a value.
- Deterministic diagnostics: unmatched ``}`` is a parse error, unclosed
  ``{`` is a ``ParseWarning``, unclassifiable lines become unknown
  sections (never errors), foreign-vendor content gets an explicit error
  instead of a silent junk tree.
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
    # E04 F4: first-class negation flag (JUNOS has no 'no' prefix; kept for
    # a uniform cross-parser ConfigNode shape).
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


class JunosParser:
    """
    Juniper JUNOS Configuration Parser

    Parses hierarchical, set-style, and '##'-prefixed JUNOS configurations
    into a structured parse tree of ConfigNode objects.
    """

    # Top-level statements that are always leaf configs (set-able without braces)
    LEAF_TOP_LEVEL = {
        "version",
        "system",
    }

    # Known leaf keys used by set-style parsing heuristic.
    # When the second-to-last token of a 'set' command is one of these,
    # the leaf is 'key value' and everything before it is the path.
    KNOWN_LEAF_KEYS = {
        "protocol-version", "root-login", "host-name", "minimum-length",
        "format", "tries-before-disconnect", "backoff-threshold",
        "backoff-factor", "lockout-period", "version", "address",
        "server", "authorization", "client-list-name", "description",
        "source-address", "port", "connection-limit", "rate-limit",
        "time-zone", "authentication-key", "preferred", "access",
        "community", "idle-timeout", "class", "permissions",
    }

    # E04 F2: known JUNOS top-level containers. A root-level hierarchical
    # statement with any other head is flagged unknown (statements nested
    # inside braces are trusted: JUNOS keys cannot be enumerated there).
    JUNOS_TOP_LEVEL = frozenset({
        "version", "system", "chassis", "interfaces", "snmp",
        "routing-options", "protocols", "policy-options", "firewall",
        "forwarding-options", "security", "services", "nat",
        "class-of-service", "multicast-snooping-options", "event-options",
        "groups", "apply-groups", "routing-instances", "logical-systems",
        "vlans", "switch-options", "access", "dynamic-profiles",
        "virtual-chassis", "poe", "ethernet-switching-options",
        "system-scripts", "accounting-options", "dialog", "extensions",
        # root-level configuration verbs (not containers, but JUNOS syntax)
        "activate", "deactivate",
    })

    # E04: a last set-token that looks like a value (number, quoted string
    # or address/prefix) pairs with the previous token as key=value.
    _VALUE_LIKE_RE = re.compile(r'^(?:\d+|".*"|[\d.:a-fA-F]+(?:/\d+)?)$')
    _BRACE_OPEN_RE = re.compile(r"\{\s*$")
    _FORTI_CONFIG_RE = re.compile(r"^config\s+\S")
    _FORTI_EDIT_RE = re.compile(r"^edit\s+\S")
    _FORTI_BARE_RE = re.compile(r"^(end|next)\s*$")

    def parse(
        self,
        content: str,
        *,
        vendor: str = "",
        platform: str = "",
        ingested_config_id: Optional[str] = None,
    ) -> ParseResult:
        """
        Parse a JUNOS configuration string into a parse tree.

        Args:
            content: Raw JUNOS configuration text
            vendor: Vendor label supplied by the caller (stored on the result)
            platform: Platform label supplied by the caller
            ingested_config_id: Ingestion id supplied by the caller

        Returns:
            ParseResult with parse_tree, errors, warnings, unknown_sections
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
                "content is a JSON document, not JUNOS configuration",
                (content.splitlines() or [""])[0][:200],
            ))
            result.unknown_sections = self._meaningful_unknowns(content)
            return result

        lines = content.splitlines()
        errors: list[ParseError] = []
        warnings: list[ParseWarning] = []
        unknown_sections: list[UnknownSection] = []

        # Detect style: set-style vs hierarchical
        cleaned_lines: list[tuple[int, str, str]] = []
        has_set = False
        has_brace = False
        has_hash = False
        has_semi = False
        for i, line in enumerate(lines, start=1):
            raw = line
            # Strip '##' prefix (show configuration | display defaults style)
            if line.lstrip().startswith("##"):
                has_hash = True
                line = line.lstrip()[2:]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("set ") or stripped == "set":
                has_set = True
            if "{" in stripped or stripped.startswith("}"):
                has_brace = True
            if ";" in stripped:
                has_semi = True
            cleaned_lines.append((i, raw, stripped))

        if self._has_forti_markers(c[2] for c in cleaned_lines):
            result.parse_errors.append(ParseError(
                0,
                "content does not match JUNOS syntax "
                "(FortiOS-style 'config'/'edit'/'end'/'next' lines found)",
                "",
            ))
            result.unknown_sections = [
                UnknownSection(path=[], raw_text=s, line_numbers=[n])
                for n, _r, s in cleaned_lines
            ]
            return result
        if not (has_set or has_brace or has_semi or has_hash):
            if not cleaned_lines:
                warnings.append(ParseWarning(
                    0, "no configuration statements recognized in content", ""))
                result.parse_warnings = warnings
                return result
            result.parse_errors.append(ParseError(
                0,
                "content does not match JUNOS syntax (no brace, set-style, "
                "or statement-terminator structure found)",
                "",
            ))
            result.unknown_sections = [
                UnknownSection(path=[], raw_text=s, line_numbers=[n])
                for n, _r, s in cleaned_lines
            ]
            return result

        if has_set and not has_brace:
            parsed = self._parse_set_style(cleaned_lines, errors, warnings, unknown_sections)
        else:
            # E04 F15: hierarchical mode also routes per-statement 'set'
            # lines to the set-path builder, so mixed content keeps both
            # styles without mangling.
            parsed = self._parse_hierarchical(cleaned_lines, errors, warnings, unknown_sections)
        parsed.vendor = vendor
        parsed.platform = platform
        parsed.id = result.id
        parsed.ingested_config_id = ingested_config_id
        if not parsed.parse_tree and not parsed.unknown_sections \
                and not parsed.parse_errors:
            parsed.parse_warnings.append(ParseWarning(
                0, "no configuration statements recognized in content", ""))
        return parsed

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
    def _has_forti_markers(cls, stripped_lines) -> bool:
        for s in stripped_lines:
            if cls._FORTI_CONFIG_RE.match(s) or cls._FORTI_EDIT_RE.match(s) \
                    or cls._FORTI_BARE_RE.match(s):
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

    # ------------------------------------------------------------------
    # Hierarchical (brace) parsing
    # ------------------------------------------------------------------

    def _parse_hierarchical(
        self,
        cleaned_lines: list[tuple[int, str, str]],
        errors: list[ParseError],
        warnings: list[ParseWarning],
        unknown_sections: list[UnknownSection],
    ) -> ParseResult:
        # Stack of (node, dict-of-child-by-key-path)
        # We keep a shadow dict tree for dedup/find
        root_children: list[ConfigNode] = []
        node_stack: list[tuple[ConfigNode, dict[str, ConfigNode]]] = []
        nodes_by_path: dict[tuple[str, ...], ConfigNode] = {}
        depth = 0

        for line_number, raw_text, stripped in cleaned_lines:
            # E04 F15: a 'set' line inside mixed content is parsed with the
            # set-style builder instead of being brace-mangled.
            if stripped.startswith("set ") or stripped == "set":
                self._parse_set_line(
                    root_children, nodes_by_path, line_number, raw_text,
                    stripped, errors, unknown_sections,
                )
                continue

            # Section open: 'name {'
            open_match = re.match(r"^(\S.*?)\s*\{\s*$", stripped)
            if open_match:
                section_text = open_match.group(1).strip()
                # Could be 'name value {' or 'name {'
                parts = section_text.split()
                key = parts[0]
                value = " ".join(parts[1:]) if len(parts) > 1 else None
                if not node_stack and key not in self.JUNOS_TOP_LEVEL:
                    unknown_sections.append(UnknownSection(
                        path=[], raw_text=stripped, line_numbers=[line_number]))
                node = ConfigNode(
                    path=[p[0].key for p in self._stack_paths(node_stack)],
                    key=key,
                    value=value,
                    line_number=line_number,
                    raw_text=raw_text,
                )
                parent, parent_children = self._current_container(node_stack, root_children)
                parent.children.append(node)
                node_stack.append((node, {}))
                depth += 1
                continue

            # Section close: '}'
            if stripped == "}" or stripped.startswith("};"):
                if not node_stack:
                    errors.append(ParseError(line_number, "Unbalanced closing brace", raw_text))
                    continue
                node_stack.pop()
                depth -= 1
                continue

            # Leaf statement: 'key value;' possibly multiple ';' separated
            # Split on ';' but keep a single statement list
            statement = stripped.rstrip(";").strip()
            if not statement:
                continue
            # Handle multiple statements on one line: 'a; b;'
            statements = [s.strip() for s in re.split(r";\s*", statement) if s.strip()]
            for stmt in statements:
                parts = stmt.split()
                key = parts[0]
                value = " ".join(parts[1:]) if len(parts) > 1 else None
                if not node_stack and (
                    key not in self.JUNOS_TOP_LEVEL or not stripped.rstrip().endswith(";")
                ):
                    # E04 F2: root-level lines JUNOS cannot classify are
                    # flagged unknown instead of silently becoming nodes.
                    unknown_sections.append(UnknownSection(
                        path=[], raw_text=stripped, line_numbers=[line_number]))
                    continue
                node = ConfigNode(
                    path=[p[0].key for p in self._stack_paths(node_stack)],
                    key=key,
                    value=value,
                    line_number=line_number,
                    raw_text=raw_text,
                )
                parent, parent_children = self._current_container(node_stack, root_children)
                parent.children.append(node)

        if node_stack:
            remaining = [p[0] for p in node_stack]
            # E04 V04-19: unclosed blocks are warnings, typed ParseWarning.
            warnings.append(ParseWarning(
                0,
                f"Unclosed braces: {', '.join(n.key for n in remaining)}",
                "",
            ))

        return ParseResult(
            parse_tree=root_children,
            parse_errors=errors,
            parse_warnings=warnings,
            unknown_sections=unknown_sections,
        )

    # ------------------------------------------------------------------
    # Set-style parsing
    # ------------------------------------------------------------------

    def _parse_set_line(
        self,
        root_children: list[ConfigNode],
        nodes_by_path: dict[tuple[str, ...], ConfigNode],
        line_number: int,
        raw_text: str,
        stripped: str,
        errors: list[ParseError],
        unknown_sections: list[UnknownSection],
    ) -> None:
        """Parse one 'set <path> <leaf>' line into the tree."""
        rest = stripped[3:].strip() if stripped != "set" else ""
        if not rest:
            errors.append(ParseError(line_number, "empty 'set' statement", raw_text))
            return
        parts = rest.split()
        if len(parts) < 2:
            unknown_sections.append(UnknownSection(
                path=[], raw_text=stripped, line_numbers=[line_number]))
            return
        # E04 F49: the last token pairs with the previous one when it is a
        # known leaf key, or when it looks like a value (number, quoted
        # string, address/prefix). Otherwise the last token is the leaf
        # (bare statement).
        if parts[-2] in self.KNOWN_LEAF_KEYS:
            path_parts = tuple(parts[:-2])
            leaf = " ".join(parts[-2:])
        elif self._VALUE_LIKE_RE.match(parts[-1]):
            path_parts = tuple(parts[:-2])
            leaf = " ".join(parts[-2:])
        else:
            path_parts = tuple(parts[:-1])
            leaf = parts[-1]
        self._set_path(
            nodes_by_path, root_children, path_parts, leaf,
            line_number, raw_text,
        )

    def _parse_set_style(
        self,
        cleaned_lines: list[tuple[int, str, str]],
        errors: list[ParseError],
        warnings: list[ParseWarning],
        unknown_sections: list[UnknownSection],
    ) -> ParseResult:
        """Parse 'set <path> <leaf>' style configuration into a tree."""
        root_children: list[ConfigNode] = []
        nodes_by_path: dict[tuple[str, ...], ConfigNode] = {}

        for line_number, raw_text, stripped in cleaned_lines:
            if not (stripped.startswith("set ") or stripped == "set"):
                # E04 F2: non-set lines inside set-style content are flagged
                # instead of being blind-stripped into mangled keys.
                unknown_sections.append(UnknownSection(
                    path=[], raw_text=stripped, line_numbers=[line_number]))
                continue
            self._parse_set_line(
                root_children, nodes_by_path, line_number, raw_text,
                stripped, errors, unknown_sections,
            )

        return ParseResult(
            parse_tree=root_children,
            parse_errors=errors,
            parse_warnings=warnings,
            unknown_sections=unknown_sections,
        )

    def _set_path(
        self,
        nodes_by_path: dict[tuple[str, ...], ConfigNode],
        root_children: list[ConfigNode],
        path_parts: tuple[str, ...],
        leaf: str,
        line_number: int,
        raw_text: str,
    ) -> ConfigNode:
        """Create/find intermediate nodes for a set path, then attach leaf."""
        parent = None
        parent_children = root_children
        current_path: list[str] = []

        for part in path_parts:
            current_path.append(part)
            key = tuple(current_path)
            if key not in nodes_by_path:
                # E04 F15: reuse a same-key sibling built by the other
                # style (mixed content merges into one tree).
                existing = next(
                    (c for c in parent_children if c.key == part), None)
                if existing is not None:
                    nodes_by_path[key] = existing
                else:
                    node = ConfigNode(
                        path=list(current_path[:-1]),
                        key=part,
                        line_number=line_number,
                        raw_text=raw_text,
                    )
                    parent_children.append(node)
                    nodes_by_path[key] = node
            parent = nodes_by_path[key]
            parent_children = parent.children

        # Leaf: 'key value' split
        leaf_parts = leaf.split()
        leaf_key = leaf_parts[0]
        leaf_value = " ".join(leaf_parts[1:]) if len(leaf_parts) > 1 else None
        leaf_node = ConfigNode(
            path=list(current_path),
            key=leaf_key,
            value=leaf_value,
            line_number=line_number,
            raw_text=raw_text,
        )
        if parent is not None:
            parent.children.append(leaf_node)
        else:
            root_children.append(leaf_node)
        return leaf_node

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _stack_paths(node_stack: list[tuple[ConfigNode, dict]]) -> list[tuple[ConfigNode, dict]]:
        return node_stack

    @staticmethod
    def _current_container(
        node_stack: list[tuple[ConfigNode, dict]],
        root_children: list[ConfigNode],
    ) -> tuple[ConfigNode, dict[str, ConfigNode]]:
        if node_stack:
            return node_stack[-1]
        # Pseudo-parent for root
        return _RootContainer(root_children), {}

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


class _RootContainer:
    """Adapter so root children behave like a node container for _current_container."""

    def __init__(self, children: list[ConfigNode]) -> None:
        self.children = children
        self.key = ""
