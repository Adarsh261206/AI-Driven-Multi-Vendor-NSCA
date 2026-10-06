"""
Cisco IOS Configuration Parser

Parses Cisco IOS configurations into a structured parse tree.

E04 contract implemented here:
- Flat IOS section grammar: every section start (interface/line/router/
  switch/vlan/acl/crypto/key_chain/nested) terminates the previously open
  sections, so consecutive top-level sections are siblings at the root.
- Banner blocks (``banner <type> <delim> ... <delim>``) are consumed as one
  opaque node; the body is never parsed as configuration commands.
- Deterministic diagnostics: parse errors (binary/control content, JSON
  envelope, foreign-vendor syntax, unterminated banner), parse warnings
  (section left open at EOF, non-empty content with no statements,
  prefix-notation addresses), unknown sections (root-level lines outside
  the recognised IOS/ASA/NX-OS command vocabulary).
- Negation is a first-class field: ``no <cmd>`` sets ``negated=True`` on
  the node instead of folding into the key.
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
    # E04 F4: first-class negation flag. ``no ip http server`` yields
    # key="ip" value="http server" negated=True, distinguishable from the
    # affirmative form without re-deriving anything from raw_text.
    negated: bool = False

    def get_full_path(self) -> str:
        """Get full path as dot-separated string"""
        return ".".join(self.path + [self.key]) if self.key else ".".join(self.path)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary (iterative: safe for deeply nested trees)."""
        out: dict[str, Any] = {
            "key": self.key,
            "value": self.value,
            "path": list(self.path),
            "line_number": self.line_number,
            "raw_text": self.raw_text,
            "negated": self.negated,
        }
        if not self.children:
            return out
        kids = [self._node_dict(c) for c in self.children]
        out["children"] = kids
        stack = [(self.children[i], kids[i]) for i in range(len(self.children))]
        while stack:
            node, d = stack.pop()
            if node.children:
                sub = [self._node_dict(c) for c in node.children]
                d["children"] = sub
                stack.extend(
                    (node.children[i], sub[i]) for i in range(len(node.children))
                )
        return out

    @staticmethod
    def _node_dict(node: "ConfigNode") -> dict[str, Any]:
        return {
            "key": node.key,
            "value": node.value,
            "path": list(node.path),
            "line_number": node.line_number,
            "raw_text": node.raw_text,
            "negated": node.negated,
        }


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
    # (docs/PROJECT_MASTER_SPEC.md:744-753). Filled by the executor; direct
    # parse() calls accept them as keyword arguments (defaults: empty).
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


class CiscoIOSParser:
    """
    Cisco IOS Configuration Parser

    Parses IOS configurations into a structured parse tree.
    Handles:
    - Hierarchical configuration sections with proper section-end detection
    - Interface configurations
    - Line configurations
    - Router/switch configurations
    - Access lists
    - SNMP configurations
    - NTP configurations
    - Logging configurations
    """

    # Patterns for section starts (order matters for matching)
    SECTION_PATTERNS = [
        # Interface sections
        (r"^interface\s+(\S+(?:\s+\S+)?)", "interface"),
        # Line sections (`con` is the standard running-config spelling of
        # the console line — without it, `line con 0` children never nest
        # and the E04 path diverges from raw evidence, V4-10)
        (r"^line\s+(vty|con(?:sole)?|aux)\s+(\S+(?:\s+\S+)?)", "line"),
        # Router sections
        (r"^router\s+(\S+)\s*(.*)", "router"),
        # Switch sections
        (r"^switch\s+(\S+)\s*(.*)", "switch"),
        # VLAN sections
        (r"^vlan\s+(\d+)", "vlan"),
        # Access list sections
        (r"^(access-list|ip\s+access-list)\s+(.+)", "acl"),
        # Crypto sections
        (r"^crypto\s+(.+)", "crypto"),
        # Key chain sections
        (r"^key\s+chain\s+(\S+)", "key_chain"),
        # Nested sections (using regex for complex patterns)
        (r"^(?:ip\s+)?(?:prefix-list|route-map|community-list)\s+(\S+)", "nested"),
        # Control-plane policing block (bare section keyword, no identifier)
        (r"^control-plane\s*$", "control-plane"),
    ]

    # Commands that are always top-level (not inside sections)
    TOP_LEVEL_COMMANDS = {
        "hostname", "enable", "no", "ip", "interface", "line", "router",
        "switch", "vlan", "access-list", "crypto", "key", "logging",
        "ntp", "snmp-server", "banner", "boot", "service", "version",
        "username", "aaa", "tacacs", "radius", "radius-server",
    }

    # E04 F2: recognised root-level command families (IOS + ASA + NX-OS).
    # A root-level line whose head word is not in this vocabulary is routed
    # to unknown_sections instead of silently becoming a tree node. This is
    # intentionally generous: it identifies obvious garbage, not a full
    # command grammar (lines inside a section are contextually trusted).
    RECOGNIZED_ROOT_WORDS = frozenset({
        # generic IOS globals
        "hostname", "enable", "no", "ip", "ipv6", "interface", "line",
        "router", "switch", "vlan", "access-list", "crypto", "key",
        "logging", "ntp", "sntp", "snmp-server", "banner", "boot",
        "service", "version", "username", "aaa", "tacacs", "tacacs-server",
        "radius", "radius-server", "end", "clock", "calendar", "scheduler",
        "kron", "archive", "event", "track", "errdisable", "spanning-tree",
        "port-channel", "lacp", "udld", "vtp",         "redundancy", "stackwise",
        "stack", "domain", "vrf", "alias", "privilege", "prompt", "parser",
        "file", "more", "default", "maximum-paths", "multicast-routing",
        "mpls", "route-map", "prefix-list", "community-list", "as-path",
        "table-map", "class-map", "policy-map", "parameter-map",
        "monitor", "netflow", "flow", "sampler", "rmon", "sflow",
        "cdp", "lldp", "callhome", "license", "feature", "install",
        "fabric", "fex", "dot1x", "mab", "eap", "ldap", "kerberos",
        "isakmp", "pki", "trustpoint", "certificate", "ssl", "ssh",
        "security",        "telnet", "console", "dialer", "isdn", "controller", "voice",
        "telephony-service", "call-manager", "mgcp", "sip-ua", "gatekeeper",
        "h323", "pots", "voice-card", "voice-port", "dial-peer",
        "translation-rule", "translation-profile", "stcapp", "sccp",
        "num-exp", "fallback", "modem", "chat-script", "x25", "x29",
        "bridge", "bridge-group", "mac", "arp", "atm", "frame-relay",
        "ppp", "multilink", "tunnel", "loopback", "null", "bvi", "sonet",
        # common in-section subcommands also accepted at root scope so a
        # legitimately placed line is never dropped from the tree
        "shutdown", "description", "duplex", "speed", "negotiation", "mtu",
        "encapsulation", "standby", "vrrp", "glbp", "hsrp", "switchport",
        "channel-group", "channel-protocol", "storm-control", "power",
        "load-interval", "carrier-delay", "dampening", "keepalive",
        "bandwidth", "delay", "media-type", "flowcontrol", "stopbits",
        "databits", "parity", "network", "passive-interface", "neighbor",
        "redistribute", "distance", "variance", "default-metric",
        "auto-summary", "synchronization", "timers", "maximum-path",
        "login", "transport", "exec-timeout", "session-timeout",
        "access-class", "accounting", "authorization", "authentication",
        "session-limit", "absolute-timeout", "location", "rotary",
        "autocommand", "autohangup", "escape-character", "history",
        "terminal", "width", "length", "monitor", "notify",
        "permit", "deny", "remark", "evaluate", "dynamic", "reflect",
        "established", "log", "address", "server", "peer", "broadcast",
        "master", "authenticate", "authentication-key", "trusted-key",
        "access-group", "update-calendar", "console", "buffered", "trap",
        "facility", "source-interface", "host", "contact", "community",
        "chassis-id", "engineid", "password", "secret", "view",
        "community", "contact",
        # ASA / NX-OS families
        "object", "object-group", "access-group", "nat", "name", "names",
        "pager", "icmp", "asdm", "threat-detection", "group-policy",
        "tunnel-group", "webvpn", "same-security-traffic", "dhcpd",
        "dhcprelay", "failover", "monitor-interface", "aaa-server",
        "dynamic-access-policy", "cifs", "http", "route",
        # IOS file structure markers and running-config preamble
        "boot-start-marker", "boot-end-marker", "building", "current",
        "mls", "memory-size", "mmi", "platform",
    })

    # E04 F14: named-ACL entry lines: "<seq> <action> <match...>"
    _ACL_ENTRY_RE = re.compile(
        r"^(\d+)\s+(permit|deny|remark|evaluate|dynamic|reflect)\b\s*(.*)$"
    )
    # E04: IPv4 prefix notation (NX-OS / EOS style, never classic IOS
    # ``ip address``) is an explicit recoverable anomaly, not an error.
    _CIDR_V4_RE = re.compile(r"^ip\s+address\s+\d{1,3}(?:\.\d{1,3}){3}/\d+\b")
    # E04 F2: binary / C0 control content (NUL etc.); lone surrogates and
    # non-ASCII are valid str content and are NOT flagged.
    _CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
    _BANNER_RE = re.compile(r"^banner\s+(\S+)(?:\s+(\S)(.*))?$", re.IGNORECASE)
    # E04 F3 (dimension B): structural markers of other vendors' syntax.
    _BRACE_OPEN_RE = re.compile(r"\{\s*$")
    _BRACE_CLOSE_RE = re.compile(r"^\}\s*(;.*)?$")
    _FORTI_CONFIG_RE = re.compile(r"^config\s+\S")
    _FORTI_EDIT_RE = re.compile(r"^edit\s+\S")

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
        Parse Cisco IOS configuration

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
                "content is a JSON document, not Cisco IOS configuration",
                (content.splitlines() or [""])[0][:200],
            ))
            result.unknown_sections = self._meaningful_unknowns(content)
            return result

        lines = content.splitlines()
        banner_starts, banner_body, unterminated = self._extract_banners(lines)
        for start_no, delim, start_raw in unterminated:
            result.parse_errors.append(ParseError(
                start_no,
                "unterminated banner block: closing delimiter %r not found" % delim,
                start_raw,
            ))
        foreign = self._detect_foreign(lines, banner_body)
        if foreign is not None:
            result.parse_errors.append(ParseError(0, foreign, ""))
            result.unknown_sections = self._meaningful_unknowns(
                content, skip=banner_body)
            return result
        self._detect_control_content(lines, result.parse_errors)

        # Track section stack for proper nesting
        section_stack: list[ConfigNode] = []
        section_path_stack: list[str] = []
        root_nodes: list[ConfigNode] = []
        statements = 0

        for line_num, line in enumerate(lines, 1):
            idx = line_num - 1
            stripped = line.strip()

            # Skip empty lines and comments
            if not stripped or stripped.startswith("!"):
                continue
            # Banner body lines are opaque payload, never configuration
            if idx in banner_body:
                continue
            # Banner start: one opaque node holding the whole body
            if idx in banner_starts:
                end_idx, _delim, body = banner_starts[idx]
                root_nodes.append(ConfigNode(
                    path=[],
                    key="banner",
                    value=body,
                    line_number=line_num,
                    raw_text=stripped,
                ))
                statements += 1
                continue

            # Check for section start
            section_match = self._check_section_start(stripped)

            if section_match:
                section_type, section_path = section_match

                # E04 F1: IOS sections are flat. A new section start closes
                # every open section; sections are always root siblings.
                section_stack.clear()
                section_path_stack.clear()

                # Create new section node
                new_node = ConfigNode(
                    path=[],
                    key=section_type,
                    value=section_path,
                    line_number=line_num,
                    raw_text=stripped,
                )
                root_nodes.append(new_node)
                section_stack.append(new_node)
                section_path_stack.append(section_type)
                statements += 1
                continue

            # E04 F14: numbered entries inside a named ACL use the action
            # keyword as the key; the sequence number stays in raw_text.
            if section_stack and section_stack[-1].key == "acl":
                acl_entry = self._ACL_ENTRY_RE.match(stripped)
                if acl_entry:
                    _seq, action, rest = acl_entry.groups()
                    node = ConfigNode(
                        path=section_path_stack.copy(),
                        key=action,
                        value=rest.strip() or None,
                        line_number=line_num,
                        raw_text=stripped,
                    )
                    section_stack[-1].children.append(node)
                    statements += 1
                    continue

            # E04: bare 'end' exits configuration mode in IOS, so it closes
            # every open section (many running-config dumps end with it).
            if stripped == "end":
                section_stack.clear()
                section_path_stack.clear()

            # Check for key-value pair
            kv_match = self._parse_key_value(stripped)

            if kv_match:
                key, value, kv_type = kv_match

                # E04 F14: a digit-headed line is never an IOS command (F14
                # class); it is flagged unknown in any scope. (Numbered ACL
                # entries were already consumed by the action-keyword rule.)
                if re.match(r"^\d", key):
                    result.unknown_sections.append(UnknownSection(
                        path=section_path_stack.copy(),
                        raw_text=stripped,
                        line_numbers=[line_num],
                    ))
                    continue

                # E04: prefix-notation IPv4 address (NX-OS/EOS style, never
                # classic IOS dotted-mask form) is an explicit recoverable
                # anomaly wherever it appears, never an error.
                if key == "ip" and value and self._CIDR_V4_RE.match(stripped):
                    result.parse_warnings.append(ParseWarning(
                        line_num,
                        "prefix-notation address (not classic IOS dotted-mask form)",
                        stripped,
                    ))

                # Check if this is a top-level command that should close sections
                if key in self.TOP_LEVEL_COMMANDS and section_stack:
                    # Pop sections until we find a valid parent or reach root
                    while section_stack:
                        top = section_stack[-1]
                        # Keep section if it's a different type and the command could be inside it
                        if top.key == "interface" and key == "ip":
                            break
                        if top.key == "line" and key in ("exec-timeout", "logging", "login", "transport"):
                            break
                        if top.key == "router" and key in ("network", "default-information"):
                            break
                        if top.key == "acl" and key in ("permit", "deny"):
                            break
                        section_stack.pop()
                        section_path_stack.pop()

                new_node = ConfigNode(
                    path=section_path_stack.copy(),
                    key=key,
                    value=value,
                    line_number=line_num,
                    raw_text=stripped,
                    negated=(kv_type == "negated"),
                )

                if section_stack:
                    section_stack[-1].children.append(new_node)
                    statements += 1
                elif key.lower() in self.RECOGNIZED_ROOT_WORDS:
                    root_nodes.append(new_node)
                    statements += 1
                else:
                    # E04 F2: recognised families only; the rest is flagged,
                    # never silently accepted as configuration.
                    result.unknown_sections.append(UnknownSection(
                        path=[],
                        raw_text=stripped,
                        line_numbers=[line_num],
                    ))
            else:
                # Unknown line - track as unknown section
                result.unknown_sections.append(UnknownSection(
                    path=section_path_stack.copy(),
                    raw_text=stripped,
                    line_numbers=[line_num],
                ))

        if section_stack:
            open_names = [f"{n.key} {n.value or ''}".strip() for n in section_stack]
            result.parse_warnings.append(ParseWarning(
                0,
                "section left open at end of file: %s" % ", ".join(open_names),
                "",
            ))
        if statements == 0 and not result.unknown_sections:
            result.parse_warnings.append(ParseWarning(
                0,
                "no configuration statements recognized in content",
                "",
            ))

        result.parse_tree = root_nodes
        return result

    # ------------------------------------------------------------------
    # Pre-scan helpers (deterministic, content-shape only)
    # ------------------------------------------------------------------

    @staticmethod
    def _meaningful_unknowns(
        content: str, skip: Optional[set[int]] = None
    ) -> list[UnknownSection]:
        """Every meaningful line as an unknown section (foreign/JSON content).

        ``skip`` holds 0-based banner-body lines, which are opaque payload.
        """
        skip = skip or set()
        out: list[UnknownSection] = []
        for n, line in enumerate(content.splitlines()):
            if n in skip:
                continue
            s = line.strip()
            if s and not s.startswith("!"):
                out.append(UnknownSection(path=[], raw_text=s, line_numbers=[n + 1]))
        return out

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
    def _extract_banners(
        cls, lines: list[str]
    ) -> tuple[dict[int, tuple[int, str, str]], set[int], list[tuple[int, str, str]]]:
        """Locate banner blocks.

        Returns (starts, body_lines, unterminated) where starts maps the
        0-based start line to (0-based end line, delimiter, body text),
        body_lines holds 0-based lines that are banner payload, and
        unterminated holds (1-based start line, delimiter, start raw text).
        """
        starts: dict[int, tuple[int, str, str]] = {}
        body: set[int] = set()
        unterminated: list[tuple[int, str, str]] = []
        i, n = 0, len(lines)
        while i < n:
            stripped = lines[i].strip()
            m = cls._BANNER_RE.match(stripped)
            if not m:
                i += 1
                continue
            delim, rest = m.group(2), m.group(3) or ""
            if not delim:
                # 'banner <type>' with no delimiter: an ordinary line.
                i += 1
                continue
            pos = rest.find(delim)
            if pos != -1:
                starts[i] = (i, delim, rest[:pos])
                i += 1
                continue
            chunks = [rest] if rest else []
            j = i + 1
            closed = False
            while j < n:
                text = lines[j]
                k = text.find(delim)
                if k != -1:
                    chunks.append(text[:k])
                    closed = True
                    break
                chunks.append(text)
                j += 1
            if closed:
                body.update(range(i + 1, j + 1))
                starts[i] = (j, delim, "\n".join(chunks))
                i = j + 1
            else:
                unterminated.append((i + 1, delim, stripped))
                body.update(range(i + 1, n))
                i = n
        return starts, body, unterminated

    @classmethod
    def _detect_foreign(cls, lines: list[str], banner_body: set[int]) -> Optional[str]:
        """Detect structural markers of non-IOS syntax (banner-aware)."""
        for idx, line in enumerate(lines):
            if idx in banner_body:
                continue
            stripped = line.strip()
            if not stripped or stripped.startswith("!"):
                continue
            if cls._BRACE_OPEN_RE.search(stripped) or cls._BRACE_CLOSE_RE.match(stripped):
                return ("content does not match Cisco IOS syntax "
                        "(brace-hierarchy structure found)")
            if cls._FORTI_CONFIG_RE.match(stripped):
                return ("content does not match Cisco IOS syntax "
                        "(FortiOS-style 'config' block found)")
            if cls._FORTI_EDIT_RE.match(stripped):
                return ("content does not match Cisco IOS syntax "
                        "(FortiOS-style 'edit' block found)")
        return None

    @classmethod
    def _detect_control_content(cls, lines: list[str], errors: list[ParseError]) -> None:
        for line_num, line in enumerate(lines, 1):
            if cls._CONTROL_RE.search(line):
                errors.append(ParseError(
                    line_num,
                    "binary/control characters in content",
                    line.strip()[:200],
                ))
                return

    def _check_section_start(self, line: str) -> Optional[tuple[str, Optional[str]]]:
        """Check if line starts a new configuration section"""
        for pattern, section_type in self.SECTION_PATTERNS:
            match = re.match(pattern, line)
            if match:
                # Extract the section identifier
                if match.lastindex:
                    section_path = match.group(1)
                    if match.lastindex > 1 and match.group(2):
                        section_path += " " + match.group(2)
                    section_path = section_path.strip()
                else:
                    # Bare section keyword (e.g. 'control-plane'): no value.
                    section_path = None

                return (section_type, section_path)
        return None

    def _parse_key_value(self, line: str) -> Optional[tuple[str, Optional[str], str]]:
        """Parse a key-value pair from line"""
        # Try simple key-value
        match = re.match(r"^(\S+)\s+(.+)$", line)
        if match:
            key = match.group(1)
            value = match.group(2).strip()

            # Check if it's a negated value
            if key.lower() == "no":
                return (value.split()[0] if value.split() else value,
                       value.split(None, 1)[1] if len(value.split()) > 1 else None,
                       "negated")

            return (key, value, "simple")

        # Try boolean (single keyword)
        match = re.match(r"^(\S+)\s*$", line)
        if match:
            return (match.group(1), None, "boolean")

        return None

    def get_section_value(self, tree: list[ConfigNode], section_path: str) -> Optional[str]:
        """
        Get value from a specific section path

        Args:
            tree: Parse tree
            section_path: Dot-separated path to section

        Returns:
            Value if found, None otherwise
        """
        node = self.get_section(tree, section_path.split("."))
        return node.value if node is not None else None

    @classmethod
    def get_section(
        cls, tree: list[ConfigNode], path: list[str]
    ) -> Optional[ConfigNode]:
        """Get a section node by path from the root of the tree.

        Uniform cross-parser semantics (F13): a segment first matches a
        child's key, then a child's value; the final segment may also match
        the current node's own value (e.g. FortiOS ``['config',
        'system interface']`` resolves the ``config`` node itself).
        """
        nodes = list(tree)
        current: Optional[ConfigNode] = None
        for pos, seg in enumerate(path):
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

    @classmethod
    def find_all(cls, tree: list[ConfigNode], pattern: str) -> list[ConfigNode]:
        """
        Find all nodes matching a pattern (iterative: safe for deep trees).

        Uniform cross-parser semantics (F13): ``re.search(pattern,
        node.key)`` or ``re.search(pattern, node.value or "")``.
        """
        regex = re.compile(pattern, re.IGNORECASE)
        matches: list[ConfigNode] = []
        stack = list(reversed(tree))
        while stack:
            node = stack.pop()
            if regex.search(node.key or "") \
                    or (node.value and regex.search(node.value)):
                matches.append(node)
            stack.extend(reversed(node.children))
        return matches
