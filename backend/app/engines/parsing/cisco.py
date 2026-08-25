"""
Cisco IOS Configuration Parser

Parses Cisco IOS configurations into a structured parse tree.
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
        # Line sections
        (r"^line\s+(vty|console|aux)\s+(\S+(?:\s+\S+)?)", "line"),
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
    ]
    
    # Commands that are always top-level (not inside sections)
    TOP_LEVEL_COMMANDS = {
        "hostname", "enable", "no", "ip", "interface", "line", "router",
        "switch", "vlan", "access-list", "crypto", "key", "logging",
        "ntp", "snmp-server", "banner", "boot", "service", "version",
        "username", "aaa", "tacacs", "radius", "radius-server",
    }
    
    def __init__(self):
        pass
    
    def parse(self, content: str) -> ParseResult:
        """
        Parse Cisco IOS configuration
        
        Args:
            content: Configuration content string
            
        Returns:
            ParseResult with parse tree, errors, and warnings
        """
        lines = content.splitlines()
        parse_errors: list[ParseError] = []
        parse_warnings: list[ParseWarning] = []
        unknown_sections: list[UnknownSection] = []
        
        # Track section stack for proper nesting
        section_stack: list[ConfigNode] = []
        section_path_stack: list[str] = []
        root_nodes: list[ConfigNode] = []
        
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            
            # Skip empty lines and comments
            if not stripped or stripped.startswith("!"):
                continue
            
            # Check for section start
            section_match = self._check_section_start(stripped)
            
            if section_match:
                section_type, section_path = section_match
                
                # Pop sections from stack until we find a valid parent
                # A new section of the same type or a top-level command closes previous sections
                while section_stack:
                    top = section_stack[-1]
                    top_type = top.key
                    
                    # Same type: pop (e.g., new interface after previous interface)
                    if top_type == section_type:
                        section_stack.pop()
                        section_path_stack.pop()
                        break
                    # Different section type that's also a section: keep as parent
                    elif self._check_section_start(top.raw_text):
                        break
                    # Otherwise pop
                    else:
                        section_stack.pop()
                        section_path_stack.pop()
                
                # Create new section node
                new_node = ConfigNode(
                    path=section_path_stack.copy(),
                    key=section_type,
                    value=section_path,
                    line_number=line_num,
                    raw_text=stripped,
                )
                
                # Add to appropriate parent
                if section_stack:
                    section_stack[-1].children.append(new_node)
                else:
                    root_nodes.append(new_node)
                
                section_stack.append(new_node)
                section_path_stack.append(f"{section_type}:{section_path}")
                continue
            
            # Check for key-value pair
            kv_match = self._parse_key_value(stripped)
            
            if kv_match:
                key, value, kv_type = kv_match
                
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
                )
                
                # Add to current section or root
                if section_stack:
                    section_stack[-1].children.append(new_node)
                else:
                    root_nodes.append(new_node)
            else:
                # Unknown line - track as unknown section
                unknown_sections.append(UnknownSection(
                    path=section_path_stack.copy(),
                    raw_text=stripped,
                    line_numbers=[line_num],
                ))
        
        return ParseResult(
            parse_tree=root_nodes,
            parse_errors=parse_errors,
            parse_warnings=parse_warnings,
            unknown_sections=unknown_sections,
        )
    
    def _check_section_start(self, line: str) -> Optional[tuple[str, str]]:
        """Check if line starts a new configuration section"""
        for pattern, section_type in self.SECTION_PATTERNS:
            match = re.match(pattern, line)
            if match:
                # Extract the section identifier
                if match.lastindex:
                    section_path = match.group(1)
                    if match.lastindex > 1 and match.group(2):
                        section_path += " " + match.group(2)
                else:
                    section_path = line.split()[0] if line.split() else ""
                
                return (section_type, section_path.strip())
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
        parts = section_path.split(".")
        current_nodes = tree
        
        for i, part in enumerate(parts):
            found = False
            for node in current_nodes:
                if node.key == part or f"{node.key}:{node.value}" == part:
                    if i == len(parts) - 1:
                        return node.value
                    current_nodes = node.children
                    found = True
                    break
            if not found:
                return None
        return None
    
    def find_all(self, tree: list[ConfigNode], pattern: str) -> list[ConfigNode]:
        """
        Find all nodes matching a pattern
        
        Args:
            tree: Parse tree
            pattern: Regex pattern to match
            
        Returns:
            List of matching nodes
        """
        matches = []
        regex = re.compile(pattern, re.IGNORECASE)
        
        def search_nodes(nodes: list[ConfigNode]):
            for node in nodes:
                if regex.search(node.raw_text):
                    matches.append(node)
                if node.children:
                    search_nodes(node.children)
        
        search_nodes(tree)
        return matches
