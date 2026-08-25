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

    def parse(self, content: str) -> ParseResult:
        """
        Parse a JUNOS configuration string into a parse tree.

        Args:
            content: Raw JUNOS configuration text

        Returns:
            ParseResult with parse_tree, errors, warnings, unknown_sections
        """
        lines = content.splitlines()
        errors: list[ParseError] = []
        warnings: list[ParseWarning] = []
        unknown_sections: list[UnknownSection] = []

        # Detect style: set-style vs hierarchical
        cleaned_lines: list[tuple[int, str, str]] = []
        set_style = False
        for i, line in enumerate(lines, start=1):
            raw = line
            # Strip '##' prefix (show configuration | display defaults style)
            if line.lstrip().startswith("##"):
                line = line.lstrip()[2:]
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("set ") or stripped == "set":
                set_style = True
            cleaned_lines.append((i, raw, stripped))

        if set_style:
            return self._parse_set_style(cleaned_lines, errors, warnings, unknown_sections)
        return self._parse_hierarchical(cleaned_lines, errors, warnings, unknown_sections)

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
        depth = 0

        for line_number, raw_text, stripped in cleaned_lines:
            # Section open: 'name {'
            open_match = re.match(r"^(\S.*?)\s*\{\s*$", stripped)
            if open_match:
                section_text = open_match.group(1).strip()
                # Could be 'name value {' or 'name {'
                parts = section_text.split()
                key = parts[0]
                value = " ".join(parts[1:]) if len(parts) > 1 else None
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
            warnings.append(ParseError(
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
            # 'set system host-name R1'
            rest = stripped[4:].strip()  # after 'set'
            if not rest:
                continue
            parts = rest.split()
            if len(parts) < 2:
                continue
            # Heuristic: if the second-to-last token is a known leaf key,
            # the leaf is 'key value' and everything before is the path.
            # Otherwise the last token is the leaf (bare statement).
            if parts[-2] in self.KNOWN_LEAF_KEYS:
                path_parts = tuple(parts[:-2])
                leaf = " ".join(parts[-2:])
            else:
                path_parts = tuple(parts[:-1])
                leaf = parts[-1]
            self._set_path(
                nodes_by_path, root_children, path_parts, leaf,
                line_number, raw_text,
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

    @staticmethod
    def find_all(tree: list[ConfigNode], key: str) -> list[ConfigNode]:
        """Find all nodes with the given key anywhere in the tree."""
        results: list[ConfigNode] = []
        for node in tree:
            if node.key == key:
                results.append(node)
            results.extend(JunosParser.find_all(node.children, key))
        return results

    @staticmethod
    def get_section(tree: list[ConfigNode], path: list[str]) -> Optional[ConfigNode]:
        """Get a section node by path from the root of the tree."""
        current = tree
        node = None
        for part in path:
            found = None
            for child in current:
                if child.key == part:
                    found = child
                    break
            if found is None:
                return None
            node = found
            current = node.children
        return node


class _RootContainer:
    """Adapter so root children behave like a node container for _current_container."""

    def __init__(self, children: list[ConfigNode]) -> None:
        self.children = children
        self.key = ""
