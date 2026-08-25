"""
Configuration Normalization Engine

Maps vendor-specific parsed configurations to the Universal Security Model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class NormalizationResultType(str, Enum):
    """Result of normalization"""
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class NormalizationMapping:
    """A single normalization mapping"""
    source_path: str
    universal_path: str
    raw_value: Any
    normalized_value: Any
    confidence: float


@dataclass
class NormalizationResult:
    """Result of configuration normalization"""
    vendor: str
    platform: str
    universal_config: dict[str, Any]
    mappings: list[NormalizationMapping]
    unmapped_paths: list[str]
    result_type: NormalizationResultType
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "vendor": self.vendor,
            "platform": self.platform,
            "universal_config": self.universal_config,
            "mappings": [
                {
                    "source_path": m.source_path,
                    "universal_path": m.universal_path,
                    "raw_value": m.raw_value,
                    "normalized_value": m.normalized_value,
                    "confidence": m.confidence,
                }
                for m in self.mappings
            ],
            "unmapped_paths": self.unmapped_paths,
            "result_type": self.result_type.value,
        }


class NormalizationEngine:
    """
    Configuration Normalization Engine
    
    Maps vendor-specific parsed configurations to the Universal Security Model.
    """
    
    def __init__(self):
        self.vendor_mappers: dict[str, dict[str, Any]] = {}
        self._initialize_mappers()
    
    def _initialize_mappers(self) -> None:
        """Initialize vendor-specific mappers"""
        
        # ============ CISCO IOS MAPPER ============
        cisco_ios_mapper = {
                "hostname": lambda config: self._extract_hostname(config),
                "management.http.enabled": lambda config: not self._is_negated(config, "ip http server"),
                "management.https.enabled": lambda config: self._is_enabled(config, "ip http secure-server"),
                "management.ssh.enabled": lambda config: self._has_section(config, "line vty"),
                "management.ssh.version": lambda config: self._extract_ssh_version(config),
                "management.ssh.port": lambda config: 22,  # Default
                "management.ssh.timeout": lambda config: self._extract_exec_timeout(config),
                "management.ssh.auth_retries": lambda config: self._extract_ssh_auth_retries(config),
                "management.ssh.source_interface": lambda config: self._extract_value(config, "ip ssh source-interface"),
                "management.ssh.strict_host_key_check": lambda config: self._is_enabled(config, "ip ssh stricthostkeycheck"),
                "management.ssh.session_timeout": lambda config: self._extract_ssh_timeout(config),
                "management.telnet.enabled": lambda config: self._has_line_transport(config, "vty", "telnet"),
                "management.telnet.port": lambda config: 23,  # Default
                "management.vty.transport": lambda config: self._extract_vty_transport(config),
                
                "management.vty.all_blocks": lambda config: self._extract_all_line_blocks(config),
                "management.vty.exec_timeouts": lambda config: self._extract_exec_timeout_per_block(config),
                "management.vty.transports": lambda config: self._extract_vty_blocks_transport(config),
                "management.vty.conflicts": lambda config: self._detect_conflicts(config),
                "config.conflicts": lambda config: self._detect_conflicts(config),
                "management.vty.console_timeout": lambda config: next(
                    (b["timeout_seconds"] for b in self._extract_exec_timeout_per_block(config) if b["type"] == "con"), None
                ),
                "management.vty.aux_timeout": lambda config: next(
                    (b["timeout_seconds"] for b in self._extract_exec_timeout_per_block(config) if b["type"] == "aux"), None
                ),
                "management.vty.vty_timeout": lambda config: next(
                    (b["timeout_seconds"] for b in self._extract_exec_timeout_per_block(config) if b["type"] == "vty"), None
                ),
                "management.vty.all_vty_transport": lambda config: [
                    b["transport"] for b in self._extract_vty_blocks_transport(config)
                ],
                "management.vty.conflicts": lambda config: self._detect_conflicts(config),
                
                "authentication.password_policy.min_length": lambda config: self._extract_value(config, "security passwords min-length"),
                "authentication.password_policy.complexity": lambda config: self._is_enabled(config, "password complexity"),
                "authentication.password_policy.expiration": lambda config: self._extract_days(config, "password aging"),
                "authentication.password_policy.history": lambda config: self._extract_value(config, "password history"),
                
                "aaa.authentication_enabled": lambda config: self._is_enabled(config, "aaa authentication"),
                "aaa.authorization_enabled": lambda config: self._is_enabled(config, "aaa authorization"),
                "aaa.accounting_enabled": lambda config: self._is_enabled(config, "aaa accounting"),
                "aaa.radius_configured": lambda config: self._is_enabled(config, "radius-server"),
                "aaa.tacacs_configured": lambda config: self._is_enabled(config, "tacacs-server"),
                
                "logging.enabled": lambda config: self._is_enabled(config, "logging"),
                "logging.level": lambda config: self._extract_logging_level(config),
                "logging.remote_enabled": lambda config: self._is_enabled(config, "logging host"),
                "logging.remote_server": lambda config: self._extract_first_value(config, "logging host"),
                "logging.source_interface": lambda config: self._extract_value(config, "logging source-interface"),
                
                "ntp.configured": lambda config: self._is_enabled(config, "ntp server"),
                "ntp.authenticated": lambda config: self._is_enabled(config, "ntp authentication"),
                "ntp.servers": lambda config: self._extract_list(config, "ntp server"),
                
                "access_control.acl_applied": lambda config: self._has_section(config, "access-list") or self._has_section(config, "ip access-list"),
                "access_control.rules_count": lambda config: self._count_acls(config),
                
                "crypto.ssh_key_size": lambda config: self._extract_value(config, "crypto key generate rsa modulus"),
                "crypto.snmp_v3_auth": lambda config: self._is_snmpv3(config),
                
                "services.snmp.enabled": lambda config: self._is_enabled(config, "snmp-server community"),
                "services.snmp.version": lambda config: self._extract_snmp_version(config),
                "services.snmp.community_string_type": lambda config: self._extract_community_type(config),
                
                "monitoring.syslog.enabled": lambda config: self._is_enabled(config, "logging host"),
                "monitoring.syslog.severity_level": lambda config: self._extract_syslog_severity(config),
                "monitoring.syslog.source_interface": lambda config: self._extract_value(config, "logging source-interface"),
                "monitoring.audit_trail.enabled": lambda config: self._is_enabled(config, "logging buffered") or self._is_enabled(config, "logging host"),
                
                "networking.access_control.enabled": lambda config: self._is_enabled(config, "no ip redirects") or self._is_enabled(config, "no ip unreachables") or self._is_enabled(config, "no ip proxy-arp") or self._is_enabled(config, "no ip source-route"),
                
                "interfaces.unused_interfaces_shutdown": lambda config: self._check_unused_interfaces_shutdown(config),
                "interfaces.management_interface_identified": lambda config: True,  # Assume identified if configured
            }
        
        self.vendor_mappers["cisco"] = {
            "ios": cisco_ios_mapper,
            "ios_xe": cisco_ios_mapper,
        }
        
        # ============ FORTINET MAPPER ============
        self.vendor_mappers["fortinet"] = {
            "fortios": {
                "hostname": lambda config: self._extract_fortinet_hostname(config),
                "management.http.enabled": lambda config: self._is_fortinet_enabled(config, "set status enable", "config system interface", "http"),
                "management.https.enabled": lambda config: self._is_fortinet_enabled(config, "set status enable", "config system interface", "https"),
                "management.ssh.enabled": lambda config: self._is_fortinet_enabled(config, "set status enable", "config system interface", "ssh"),
                "management.ssh.port": lambda config: 22,
                "management.telnet.enabled": lambda config: self._is_fortinet_enabled(config, "set status enable", "config system interface", "telnet"),
                
                "authentication.password_policy.min_length": lambda config: self._extract_fortinet_value(config, "set min-length"),
                "authentication.password_policy.complexity": lambda config: self._is_fortinet_enabled(config, "set complexity enable", "config system password-policy"),
                "authentication.password_policy.expiration": lambda config: self._extract_fortinet_value(config, "set expire-days"),
                "authentication.password_policy.history": lambda config: self._extract_fortinet_value(config, "set history"),
                
                "aaa.authentication_enabled": lambda config: self._is_fortinet_enabled(config, "config user local"),
                "aaa.authorization_enabled": lambda config: self._is_fortinet_enabled(config, "config user group"),
                
                "logging.enabled": lambda config: self._is_fortinet_enabled(config, "config log setting"),
                "logging.remote_enabled": lambda config: self._is_fortinet_enabled(config, "set status enable", "config log syslogd setting"),
                "logging.remote_server": lambda config: self._extract_fortinet_first_value(config, "set server"),
                
                "ntp.configured": lambda config: self._is_fortinet_enabled(config, "config system ntp"),
                "ntp.servers": lambda config: self._extract_fortinet_list(config, "set ntpserver"),
                
                "access_control.acl_applied": lambda config: self._is_fortinet_enabled(config, "config firewall policy"),
                "access_control.rules_count": lambda config: self._count_fortinet_policies(config),
                
                "services.snmp.enabled": lambda config: self._is_fortinet_enabled(config, "config system snmp-community"),
            },
        }
        
        # ============ JUNIPER MAPPER ============
        self.vendor_mappers["juniper"] = {
            "junos": {
                "hostname": lambda config: self._extract_juniper_hostname(config),
                "device.time_zone": lambda config: self._extract_juniper_time_zone(config),
                "management.ssh.enabled": lambda config: self._is_juniper_enabled(config, "system", "services", "ssh"),
                "management.ssh.port": lambda config: 22,
                "management.ssh.version": lambda config: self._extract_juniper_ssh_version(config),
                "management.ssh.root_login": lambda config: self._extract_juniper_root_login(config),
                "management.telnet.enabled": lambda config: self._is_juniper_enabled(config, "system", "services", "telnet"),
                "management.http.enabled": lambda config: self._is_juniper_enabled(config, "web-management", "http"),
                "management.https.enabled": lambda config: self._is_juniper_enabled(config, "web-management", "https"),

                "authentication.password_policy.min_length": lambda config: self._extract_juniper_min_length(config),
                "authentication.password_policy.hash_algorithm": lambda config: self._extract_juniper_password_format(config),
                "authentication.lockout_policy.max_attempts": lambda config: self._extract_juniper_tries_before_disconnect(config),
                "authentication.lockout_policy.lockout_duration": lambda config: self._extract_juniper_lockout_period(config),

                "aaa.authentication_enabled": lambda config: self._is_juniper_enabled(config, "authentication-order"),
                "aaa.authorization_enabled": lambda config: self._is_juniper_enabled(config, "authorization-order"),
                "aaa.accounting_enabled": lambda config: self._extract_juniper_accounting_events(config),

                "logging.enabled": lambda config: self._is_juniper_enabled(config, "system", "syslog"),
                "logging.remote_enabled": lambda config: self._is_juniper_enabled(config, "system", "syslog", "host"),
                "logging.remote_server": lambda config: self._extract_juniper_first_value(config, "host", "system syslog"),

                "ntp.configured": lambda config: self._is_juniper_section_present(config, "ntp"),
                "ntp.servers": lambda config: self._extract_juniper_ntp_servers(config),
                "ntp.authenticated": lambda config: self._is_juniper_enabled(config, "ntp", "authentication-key"),
                "ntp.version": lambda config: self._extract_juniper_ntp_version(config),

                "access_control.acl_applied": lambda config: self._is_juniper_enabled(config, "firewall", "filter"),

                "services.snmp.enabled": lambda config: self._is_juniper_enabled(config, "snmp"),
                "services.snmp.version": lambda config: self._extract_juniper_snmp_version(config),

                "interfaces.loopback_configured": lambda config: self._extract_juniper_loopback_configured(config),

                "config.conflicts": lambda config: self._extract_juniper_conflicts(config),
            },
        }
    
    def normalize(
        self,
        config: dict[str, Any],
        vendor: str,
        platform: str,
    ) -> NormalizationResult:
        """
        Normalize vendor-specific config to universal model
        
        Args:
            config: Vendor-specific parsed configuration
            vendor: Vendor name
            platform: Platform name
            
        Returns:
            NormalizationResult with universal config and mappings
        """
        # Get mapper for this vendor/platform
        vendor_platforms = self.vendor_mappers.get(vendor, {})
        mapper = vendor_platforms.get(platform, {})
        
        if not mapper:
            return NormalizationResult(
                vendor=vendor,
                platform=platform,
                universal_config={},
                mappings=[],
                unmapped_paths=[],
                result_type=NormalizationResultType.FAILED,
            )
        
        universal_config: dict[str, Any] = {}
        mappings: list[NormalizationMapping] = []
        unmapped_paths: list[str] = []
        
        # Apply mappings
        for universal_path, mapper_func in mapper.items():
            try:
                raw_value = mapper_func(config)
                if raw_value is not None:
                    # Store in universal config
                    self._set_nested_value(universal_config, universal_path, raw_value)
                    
                    # Track mapping
                    mappings.append(NormalizationMapping(
                        source_path=f"{vendor}.{platform}.{universal_path}",
                        universal_path=universal_path,
                        raw_value=raw_value,
                        normalized_value=raw_value,
                        confidence=0.9,
                    ))
            except Exception as e:
                unmapped_paths.append(universal_path)
        
        # Determine result type
        if len(mappings) > 0 and len(unmapped_paths) == 0:
            result_type = NormalizationResultType.SUCCESS
        elif len(mappings) > 0:
            result_type = NormalizationResultType.PARTIAL
        else:
            result_type = NormalizationResultType.FAILED
        
        return NormalizationResult(
            vendor=vendor,
            platform=platform,
            universal_config=universal_config,
            mappings=mappings,
            unmapped_paths=unmapped_paths,
            result_type=result_type,
        )
    
    def _set_nested_value(self, d: dict, path: str, value: Any) -> None:
        """Set a nested dictionary value using dot-separated path"""
        parts = path.split(".")
        current = d
        for part in parts[:-1]:
            if part not in current:
                current[part] = {}
            current = current[part]
        current[parts[-1]] = value
    
    # ============ HELPER METHODS ============
    
    def _extract_hostname(self, config: dict) -> Optional[str]:
        """Extract hostname from configuration"""
        for line in config.get("raw_lines", []):
            stripped = line.strip()
            if stripped.startswith("hostname "):
                return stripped.split("hostname ", 1)[1].strip()
        return None
    
    def _is_negated(self, config: dict, key: str) -> bool:
        """Check if a configuration key is negated (no prefix)"""
        raw_lines = config.get("raw_lines", [])
        negated_key = f"no {key}"
        return any(negated_key in line for line in raw_lines)
    
    def _is_enabled(self, config: dict, key: str) -> bool:
        """Check if a configuration key is enabled"""
        raw_lines = config.get("raw_lines", [])
        return any(key in line for line in raw_lines)
    
    def _has_section(self, config: dict, section: str) -> bool:
        """Check if a configuration section exists"""
        return any(section in line for line in config.get("raw_lines", []))
    
    def _has_line_transport(self, config: dict, line_type: str, transport: str) -> bool:
        """Check if a line has specific transport"""
        raw_lines = config.get("raw_lines", [])
        in_line_section = False
        for line in raw_lines:
            if f"line {line_type}" in line:
                in_line_section = True
                continue
            if in_line_section:
                if f"transport input {transport}" in line:
                    return True
                # If we hit another section or command, stop looking
                if line.strip() and not line.strip().startswith(" ") and not line.strip().startswith("transport"):
                    in_line_section = False
        return False
    
    def _extract_value(self, config: dict, key: str) -> Optional[str]:
        """Extract a value for a configuration key"""
        for line in config.get("raw_lines", []):
            if key in line:
                parts = line.split(key)
                if len(parts) > 1:
                    return parts[1].strip()
        return None
    
    def _extract_first_value(self, config: dict, key: str) -> Optional[str]:
        """Extract the first value after a key"""
        for line in config.get("raw_lines", []):
            if key in line:
                parts = line.split()
                key_idx = next((i for i, p in enumerate(parts) if key in p), None)
                if key_idx is not None and key_idx + 1 < len(parts):
                    return parts[key_idx + 1]
        return None
    
    def _extract_list(self, config: dict, key: str) -> list[str]:
        """Extract all values for a key"""
        values = []
        for line in config.get("raw_lines", []):
            if key in line:
                parts = line.split()
                key_idx = next((i for i, p in enumerate(parts) if key in p), None)
                if key_idx is not None:
                    values.extend(parts[key_idx + 1:])
        return values
    
    def _extract_days(self, config: dict, key: str) -> Optional[int]:
        """Extract days value from config"""
        value = self._extract_value(config, key)
        if value:
            try:
                return int(value)
            except ValueError:
                pass
        return None
    
    def _extract_ssh_version(self, config: dict) -> Optional[int]:
        """Extract SSH version from config"""
        for line in config.get("raw_lines", []):
            if "ip ssh version" in line:
                parts = line.split()
                try:
                    return int(parts[-1])
                except (ValueError, IndexError):
                    pass
        return None  # not explicitly configured
    
    def _extract_logging_level(self, config: dict) -> str:
        """Extract logging level from config"""
        level_map = {
            "emergencies": 0,
            "alerts": 1,
            "critical": 2,
            "errors": 3,
            "warnings": 4,
            "notifications": 5,
            "informational": 6,
            "debugging": 7,
        }
        for line in config.get("raw_lines", []):
            if "logging trap" in line or "logging level" in line:
                for level_name, level_num in level_map.items():
                    if level_name in line:
                        return level_name
        return "informational"
    
    def _count_acls(self, config: dict) -> int:
        """Count access list rules"""
        count = 0
        for line in config.get("raw_lines", []):
            if line.startswith("access-list") or "permit " in line or "deny " in line:
                count += 1
        return count
    
    def _extract_snmp_version(self, config: dict) -> int:
        """Extract SNMP version"""
        for line in config.get("raw_lines", []):
            if "snmp-server group" in line and "v3" in line:
                return 3
            elif "snmp-server community" in line:
                return 2
        return 2
    
    def _is_snmpv3(self, config: dict) -> bool:
        """Check if SNMPv3 is configured"""
        return any("v3" in line for line in config.get("raw_lines", []) if "snmp" in line)
    
    def _extract_community_type(self, config: dict) -> str:
        """Extract SNMP community string type"""
        for line in config.get("raw_lines", []):
            if "snmp-server community" in line:
                if "public" in line:
                    return "public"
                elif "private" in line:
                    return "private"
                else:
                    return "custom"
        return "none"
    
    def _check_unused_interfaces_shutdown(self, config: dict) -> bool:
        """Check if unused interfaces are shutdown"""
        shutdown_count = sum(1 for line in config.get("raw_lines", []) if "shutdown" in line)
        return shutdown_count > 0
    
    def _extract_ssh_auth_retries(self, config: dict) -> Optional[int]:
        """Extract SSH authentication retries from config"""
        for line in config.get("raw_lines", []):
            if "ip ssh authentication-retries" in line:
                parts = line.split()
                try:
                    return int(parts[-1])
                except (ValueError, IndexError):
                    pass
        return None
    
    def _extract_ssh_timeout(self, config: dict) -> Optional[int]:
        """Extract SSH timeout (ip ssh timeout) in seconds.
        
        This is the SSH session negotiation timeout, distinct from exec-timeout.
        Commands: ip ssh timeout <seconds> OR ip ssh time-out <seconds>
        Returns None if not configured.
        """
        import re
        for line in config.get("raw_lines", []):
            m = re.match(r"^\s*ip\s+ssh\s+time-?out\s+(\d+)", line, re.IGNORECASE)
            if m:
                try:
                    return int(m.group(1))
                except ValueError:
                    pass
        return None
    
    def _extract_exec_timeout(self, config: dict) -> Optional[int]:
        """Extract exec-timeout value as total seconds.
        
        Cisco format: exec-timeout <minutes> <seconds>
        Example: 'exec-timeout 5 0' → 300 seconds
                 'exec-timeout 10 30' → 630 seconds
        Returns None if not found or malformed.
        """
        for line in config.get("raw_lines", []):
            if "exec-timeout" in line:
                parts = line.split()
                key_idx = next((i for i, p in enumerate(parts) if "exec-timeout" in p), None)
                if key_idx is None:
                    continue
                # Expect: exec-timeout <minutes> [seconds]
                remaining = parts[key_idx + 1:]
                if not remaining:
                    return None
                try:
                    minutes = int(remaining[0])
                    seconds = int(remaining[1]) if len(remaining) > 1 else 0
                    return minutes * 60 + seconds
                except (ValueError, IndexError):
                    return None
        return None
    
    def _extract_vty_transport(self, config: dict) -> str:
        """Extract transport input from line vty sections.
        
        Returns one of: 'ssh', 'telnet', 'ssh telnet', 'telnet ssh', 'none', 'unknown'
        """
        raw_lines = config.get("raw_lines", [])
        in_vty = False
        transports: list[str] = []
        
        for line in raw_lines:
            stripped = line.strip()
            if stripped.startswith("line vty") and not line.startswith(" ") and not line.startswith("\t"):
                in_vty = True
                transports = []
                continue
            if in_vty:
                if stripped.startswith("transport input"):
                    parts = stripped.split()
                    if len(parts) >= 3:
                        transports = parts[2:]  # everything after "transport input"
                # End of VTY section: non-indented, non-comment line
                if stripped and not line.startswith(" ") and not line.startswith("\t") and not stripped.startswith("!"):
                    in_vty = False
        
        if not transports:
            return "unknown"
        
        # Normalize transport list
        transport_set = set(t.lower() for t in transports)
        if "ssh" in transport_set and "telnet" in transport_set:
            return "ssh telnet"
        elif "ssh" in transport_set:
            return "ssh"
        elif "telnet" in transport_set:
            return "telnet"
        else:
            return "none"
    
    def _extract_syslog_severity(self, config: dict) -> Optional[int]:
        """Extract syslog severity level from logging trap"""
        level_map = {
            "emergencies": 0, "alerts": 1, "critical": 2, "errors": 3,
            "warnings": 4, "notifications": 5, "informational": 6, "debugging": 7,
        }
        for line in config.get("raw_lines", []):
            if "logging trap" in line:
                for level_name, level_num in level_map.items():
                    if level_name in line:
                        return level_num
        return None  # not configured
    
    def _extract_all_line_blocks(self, config: dict) -> list[dict]:
        """Extract all line blocks (vty, console, aux) with their settings.
        
        Returns list of dicts:
            [{"type": "vty", "range": "0 4", "settings": {"exec-timeout": "5 0", "transport input": "ssh"}}, ...]
        """
        raw_lines = config.get("raw_lines", [])
        blocks: list[dict] = []
        current_block: dict | None = None
        
        for line in raw_lines:
            stripped = line.strip()
            # Detect line block start (must NOT be indented)
            if stripped.startswith("line ") and not line.startswith(" ") and not line.startswith("\t"):
                parts = stripped.split()
                if len(parts) >= 3:
                    line_type = parts[1]  # vty, con, aux
                    line_range = " ".join(parts[2:])
                    current_block = {"type": line_type, "range": line_range, "settings": {}}
                    blocks.append(current_block)
                continue
            # Parse settings within block (indented lines)
            if current_block is not None:
                if stripped and not line.startswith(" ") and not line.startswith("\t") and not stripped.startswith("!"):
                    # Non-indented, non-comment line → end of block
                    current_block = None
                    continue
                if stripped.startswith("exec-timeout"):
                    current_block["settings"]["exec-timeout"] = stripped
                elif stripped.startswith("transport input"):
                    current_block["settings"]["transport input"] = stripped
                elif stripped.startswith("transport output"):
                    current_block["settings"]["transport output"] = stripped
        return blocks
    
    def _extract_exec_timeout_per_block(self, config: dict) -> list[dict]:
        """Extract exec-timeout for each line block.
        
        Returns list of dicts:
            [{"block": "line vty 0 4", "timeout_seconds": 300, "raw": "exec-timeout 5 0"}, ...]
        
        Blocks without exec-timeout have timeout_seconds=None.
        """
        blocks = self._extract_all_line_blocks(config)
        results: list[dict] = []
        
        for block in blocks:
            block_label = f"line {block['type']} {block['range']}"
            raw_timeout = block["settings"].get("exec-timeout")
            timeout_seconds = None
            
            if raw_timeout:
                parts = raw_timeout.split()
                key_idx = next((i for i, p in enumerate(parts) if "exec-timeout" in p), None)
                if key_idx is not None:
                    remaining = parts[key_idx + 1:]
                    try:
                        minutes = int(remaining[0])
                        seconds = int(remaining[1]) if len(remaining) > 1 else 0
                        timeout_seconds = minutes * 60 + seconds
                    except (ValueError, IndexError):
                        timeout_seconds = None  # malformed
            
            results.append({
                "block": block_label,
                "type": block["type"],
                "range": block["range"],
                "timeout_seconds": timeout_seconds,
                "raw": raw_timeout,
            })
        
        return results
    
    def _extract_vty_blocks_transport(self, config: dict) -> list[dict]:
        """Extract transport input for each VTY block.
        
        Returns list of dicts:
            [{"block": "line vty 0 4", "transport": "ssh", "raw": "transport input ssh"}, ...]
        
        Blocks without transport input have transport="unknown".
        """
        blocks = self._extract_all_line_blocks(config)
        results: list[dict] = []
        
        for block in blocks:
            if block["type"] != "vty":
                continue
            block_label = f"line vty {block['range']}"
            raw_transport = block["settings"].get("transport input")
            transport = "unknown"
            
            if raw_transport:
                parts = raw_transport.split()
                if len(parts) >= 3:
                    transport_values = [p.lower() for p in parts[2:]]
                    transport_set = set(transport_values)
                    if "ssh" in transport_set and "telnet" in transport_set:
                        transport = "ssh telnet"
                    elif "ssh" in transport_set:
                        transport = "ssh"
                    elif "telnet" in transport_set:
                        transport = "telnet"
                    elif "none" in transport_set:
                        transport = "none"
                    else:
                        transport = " ".join(sorted(transport_set))
            
            results.append({
                "block": block_label,
                "range": block["range"],
                "transport": transport,
                "raw": raw_transport,
            })
        
        return results
    
    def _detect_conflicts(self, config: dict) -> list[dict]:
        """Detect conflicting duplicate configuration settings.
        
        Returns list of conflicts:
            [{"setting": "exec-timeout", "blocks": ["line vty 0 4", "line vty 5 15"],
              "values": ["exec-timeout 5 0", "exec-timeout 10 0"], "conflict": True}, ...]
        
        Non-conflicting duplicates (same value) return conflict=False.
        Settings appearing only once are not included.
        """
        blocks = self._extract_all_line_blocks(config)
        
        # Group values by setting type across blocks
        setting_groups: dict[str, list[dict]] = {}
        for block in blocks:
            block_label = f"line {block['type']} {block['range']}"
            for setting_key, setting_raw in block["settings"].items():
                if setting_key not in setting_groups:
                    setting_groups[setting_key] = []
                setting_groups[setting_key].append({
                    "block": block_label,
                    "raw": setting_raw,
                })
        
        conflicts: list[dict] = []
        for setting_key, entries in setting_groups.items():
            if len(entries) < 2:
                continue  # no duplicate
            unique_values = set(e["raw"] for e in entries)
            conflicts.append({
                "setting": setting_key,
                "blocks": [e["block"] for e in entries],
                "values": [e["raw"] for e in entries],
                "conflict": len(unique_values) > 1,
                "path_prefix": "management.vty",
            })
        
        return conflicts
    
    def _extract_aaa_accounting_exec(self, config: dict) -> Optional[bool]:
        """Check if AAA accounting exec is configured"""
        for line in config.get("raw_lines", []):
            if "aaa accounting exec" in line:
                return True
        return None  # not configured
    
    # ============ FORTINET HELPERS ============
    
    def _extract_fortinet_hostname(self, config: dict) -> Optional[str]:
        """Extract hostname from Fortinet config"""
        for line in config.get("raw_lines", []):
            if "set hostname" in line:
                parts = line.split('"')
                if len(parts) > 1:
                    return parts[1]
        return None
    
    def _is_fortinet_enabled(self, config: dict, *keywords: str) -> bool:
        """Check if a Fortinet setting is enabled
        
        Args:
            config: Configuration dictionary with raw_lines
            *keywords: First N-1 keywords are section markers, last keyword is the target
            
        Returns:
            True if the target keyword is found within the section context
        """
        raw_lines = config.get("raw_lines", [])
        in_section = False
        section_depth = 0
        
        for line in raw_lines:
            # Track section boundaries using config/end markers
            if line.strip().startswith("config "):
                section_depth += 1
                in_section = False
            elif line.strip() == "end":
                section_depth -= 1
                in_section = False
                continue
            
            # Check for section markers (all keywords except the last)
            for keyword in keywords[:-1]:
                if keyword in line:
                    in_section = True
                    break
            
            # Check for target keyword within section
            if in_section and keywords[-1] in line:
                return True
        
        return False
    
    def _extract_fortinet_value(self, config: dict, key: str) -> Optional[str]:
        """Extract value from Fortinet config"""
        for line in config.get("raw_lines", []):
            if key in line:
                parts = line.split()
                key_idx = next((i for i, p in enumerate(parts) if key in p), None)
                if key_idx is not None and key_idx + 1 < len(parts):
                    return parts[key_idx + 1].strip('"')
        return None
    
    def _extract_fortinet_first_value(self, config: dict, key: str) -> Optional[str]:
        """Extract first value from Fortinet config"""
        return self._extract_fortinet_value(config, key)
    
    def _extract_fortinet_list(self, config: dict, key: str) -> list[str]:
        """Extract list from Fortinet config"""
        values = []
        for line in config.get("raw_lines", []):
            if key in line:
                parts = line.split('"')
                if len(parts) > 1:
                    values.append(parts[1])
        return values
    
    def _count_fortinet_policies(self, config: dict) -> int:
        """Count Fortinet firewall policies
        
        In FortiOS, policies are numbered with 'edit <number>' inside 'config firewall policy' blocks.
        Handles both plain and #-prefixed config formats.
        """
        count = 0
        in_policy_section = False
        
        for line in config.get("raw_lines", []):
            stripped = line.strip().lstrip('#').strip()
            
            # Track firewall policy section
            if "config firewall policy" in stripped:
                in_policy_section = True
                continue
            elif stripped == "end" and in_policy_section:
                in_policy_section = False
                continue
            
            # Count edit statements within policy section
            if in_policy_section and re.match(r'^edit\s+\d+', stripped):
                count += 1
        
        return count
    
    # ============ JUNIPER HELPERS ============
    
    def _extract_juniper_hostname(self, config: dict) -> Optional[str]:
        """Extract hostname from Juniper config
        
        Handles both flat (set system host-name X) and 
        hierarchical (host-name X;) formats.
        Also handles ## prefixed configurations.
        """
        for line in config.get("raw_lines", []):
            # Strip ## prefix and whitespace
            cleaned = line.replace('##', '').strip().rstrip(';')
            
            # Flat format: set system host-name hostname
            if "set system host-name" in cleaned:
                parts = cleaned.split()
                if len(parts) > 3:
                    return parts[3]
            
            # Hierarchical format: host-name hostname
            if cleaned.startswith("host-name "):
                return cleaned.split("host-name ", 1)[1].strip()
        return None
    
    def _is_juniper_section_present(self, config: dict, section_name: str) -> bool:
        """Check if a Juniper configuration section exists
        
        Handles hierarchical configs like: protocols { ntp { ... } }
        Also handles ## prefixed configurations.
        """
        raw_lines = config.get("raw_lines", [])
        
        for line in raw_lines:
            # Strip ## prefix and check for section
            cleaned = line.replace('##', '').strip()
            if cleaned.startswith(section_name + ' {') or cleaned == section_name + ' {':
                return True
        
        return False
    
    def _is_juniper_enabled(self, config: dict, *keywords: str) -> bool:
        """Check if a Juniper setting is enabled
        
        Handles both hierarchical (system { services { ssh; } }) and 
        flat (set system services ssh) configuration styles.
        Also handles ## prefixed configurations.
        
        Convention: First keyword(s) are section context, last keyword is the target.
        """
        raw_lines = config.get("raw_lines", [])
        
        if not keywords:
            return False
        
        target = keywords[-1]
        context_keywords = keywords[:-1]
        
        # Clean lines: strip ## prefix, strip whitespace, strip semicolons
        cleaned_lines = [line.replace('##', '').strip().rstrip(';') for line in raw_lines]
        
        # Check for single-line 'set' style configurations
        for line in cleaned_lines:
            all_found = all(keyword in line for keyword in keywords)
            if all_found:
                return True
        
        # Check for hierarchical configuration blocks
        section_stack = []
        
        for line in cleaned_lines:
            # Track section opens
            if '{' in line:
                section_name = line.replace('{', '').strip()
                section_stack.append(section_name)
                # A section opener itself can be the target (e.g., 'snmp {')
                if target == section_name or (len(section_name.split()) > 0 and target == section_name.split()[0]):
                    if not context_keywords:
                        return True
                    if any(
                        ctx_keyword in section_name or any(ctx_keyword in s for s in section_stack[:-1])
                        for ctx_keyword in context_keywords
                    ):
                        return True
                continue
            
            # Track section closes
            if '}' in line:
                if section_stack:
                    section_stack.pop()
                continue
            
            # Check if target is found in this line
            if target in line and len(section_stack) > 0:
                if not context_keywords:
                    return True
                for ctx_keyword in context_keywords:
                    if any(ctx_keyword in s for s in section_stack):
                        return True
        
        return False
    
    def _extract_juniper_value(self, config: dict, key: str) -> Optional[str]:
        """Extract value from Juniper config"""
        for line in config.get("raw_lines", []):
            if key in line:
                parts = line.split()
                key_idx = next((i for i, p in enumerate(parts) if key in p), None)
                if key_idx is not None and key_idx + 1 < len(parts):
                    return parts[key_idx + 1]
        return None
    
    def _extract_juniper_accounting_events(self, config: dict) -> Optional[bool]:
        """Check if accounting events are configured (e.g., events login).
        
        Audit: [edit] show system accounting → accounting { events login; }
        Handles: set system accounting events login
                 accounting { events login; }
        Returns True if accounting events are configured, None if no accounting section.
        """
        cleaned_lines = self._juniper_clean_lines(config)
        
        # Flat set style: 'set system accounting events login'
        for line in cleaned_lines:
            if "accounting" in line and "events" in line:
                return True
        
        # Hierarchical: accounting { events login; }
        section_stack: list[str] = []
        for line in cleaned_lines:
            if '{' in line:
                section_stack.append(line.replace('{', '').strip())
                continue
            if '}' in line:
                if section_stack:
                    section_stack.pop()
                continue
            if "events" in line and any("accounting" in s for s in section_stack):
                return True
        
        # No accounting section found at all → None (not configured)
        for line in cleaned_lines:
            if "accounting" in line:
                return False
        return None
    
    def _extract_juniper_ntp_servers(self, config: dict) -> Optional[list[str]]:
        """Extract NTP server addresses (excluding boot-server).
        
        Audit: [edit] show system ntp | match server | except boot-server | count
        Handles: set system ntp server 10.0.0.1
                 ntp { server 10.0.0.1; server 10.0.0.2; }
        Returns list of server addresses, or None if no NTP servers configured.
        """
        cleaned_lines = self._juniper_clean_lines(config)
        servers: list[str] = []
        
        for line in cleaned_lines:
            if "boot-server" in line:
                continue
            if "ntp server" in line:
                # set system ntp server 1.2.3.4 [key N]
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if p == "server" and "ntp" in line), None)
                if idx is None:
                    continue
                # Walk tokens after 'server', collect address-like tokens (IPv4/IPv6)
                for token in parts[idx + 1:]:
                    if token in ("key", "version", "prefer"):
                        break
                    servers.append(token.strip())
        
        # Hierarchical: server <addr>; lines inside ntp { }
        section_stack: list[str] = []
        for line in cleaned_lines:
            if '{' in line:
                section_stack.append(line.replace('{', '').strip())
                continue
            if '}' in line:
                if section_stack:
                    section_stack.pop()
                continue
            if line.startswith("server") and any("ntp" in s for s in section_stack):
                parts = line.split()
                if len(parts) >= 2:
                    servers.append(parts[1].strip())
        
        if not servers:
            return None
        # Deduplicate preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for s in servers:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique
    
    # Settings where duplicate conflicting values are genuine conflicts.
    # Settings that legitimately repeat (e.g., multiple NTP servers, syslog
    # hosts) are deliberately excluded because benchmark semantics define
    # them as normal.
    JUNIPER_CONFLICT_PATH_MAP: dict[str, str] = {
        "protocol-version": "management.ssh.version",
        "root-login": "management.ssh.root_login",
        "tries-before-disconnect": "authentication.lockout_policy.max_attempts",
        "lockout-period": "authentication.lockout_policy.lockout_duration",
        "minimum-length": "authentication.password_policy.min_length",
        "format": "authentication.password_policy.hash_algorithm",
        "version": "ntp.version",
        "time-zone": "device.time_zone",
        "telnet": "management.telnet.enabled",
        "events": "aaa.accounting_enabled",
        "password": "authentication.password_policy.min_length",
    }

    def _extract_juniper_conflicts(self, config: dict) -> list[dict]:
        """Detect conflicting duplicate settings in JUNOS configs.
        
        Groups leaf statements by (hierarchical context, setting key).
        Duplicate keys with different values in the SAME context are conflicts.
        Identical duplicates are not conflicts.
        
        Settings that legitimately repeat (NTP servers, syslog hosts) are
        excluded per benchmark semantics.
        """
        import re as _re
        cleaned_lines = self._juniper_clean_lines(config)
        statements: list[tuple[str, str, str]] = []  # (context, key, value)
        
        # Hierarchical brace style
        stack: list[str] = []
        for line in cleaned_lines:
            if '{' in line:
                stack.append(line.replace('{', '').strip())
                continue
            if '}' in line:
                if stack:
                    stack.pop()
                continue
            for stmt in _re.split(r";\s*", line.rstrip(';')):
                stmt = stmt.strip()
                if not stmt:
                    continue
                parts = stmt.split()
                if parts:
                    val = " ".join(parts[1:]) if len(parts) > 1 else ""
                    statements.append((">".join(stack), parts[0], val))
        
        # Set style
        for line in cleaned_lines:
            if line.startswith("set "):
                parts = line[4:].split()
                if len(parts) < 2:
                    continue
                if parts[-2] in self.KNOWN_JUNOS_LEAF_KEYS:
                    ctx_parts = parts[:-2]
                    key = parts[-2]
                    val = parts[-1]
                else:
                    ctx_parts = parts[:-1]
                    key = parts[-1]
                    val = ""
                statements.append((">".join(ctx_parts), key, val))
        
        # Group by (context, key)
        groups: dict[tuple[str, str], list[str]] = {}
        for ctx, key, val in statements:
            groups.setdefault((ctx, key), []).append(val)
        
        conflicts: list[dict] = []
        for (ctx, key), vals in groups.items():
            if len(vals) < 2:
                continue
            unique = set(vals)
            path_prefix = self.JUNIPER_CONFLICT_PATH_MAP.get(key)
            conflicts.append({
                "setting": key,
                "context": ctx,
                "values": vals,
                "conflict": len(unique) > 1,
                "path_prefix": path_prefix,
            })
        
        return conflicts
    
    KNOWN_JUNOS_LEAF_KEYS = {
        "protocol-version", "root-login", "host-name", "minimum-length",
        "format", "tries-before-disconnect", "backoff-threshold",
        "backoff-factor", "lockout-period", "version", "address",
        "server", "authorization", "client-list-name", "time-zone",
        "idle-timeout", "connection-limit", "rate-limit", "source-address",
    }
    
    def _extract_juniper_first_value(self, config: dict, *keywords: str) -> Optional[str]:
        """Extract first value from Juniper config"""
        raw_lines = config.get("raw_lines", [])
        
        for line in raw_lines:
            all_found = all(keyword in line for keyword in keywords[:-1])
            if all_found:
                parts = line.split()
                for i, part in enumerate(parts):
                    if keywords[-1] in part and i + 1 < len(parts):
                        return parts[i + 1]
        
        return None
    
    def _extract_juniper_list(self, config: dict, key: str) -> list[str]:
        """Extract list from Juniper config"""
        values = []
        for line in config.get("raw_lines", []):
            if key in line:
                parts = line.split()
                key_idx = next((i for i, p in enumerate(parts) if key in p), None)
                if key_idx is not None:
                    values.extend(parts[key_idx + 1:])
        return values
    
    def _extract_juniper_snmp_version(self, config: dict) -> int:
        """Extract SNMP version from Juniper config"""
        for line in config.get("raw_lines", []):
            if "v3" in line and "snmp" in line:
                return 3
            elif "v2c" in line and "snmp" in line:
                return 2
        return 2
    
    def _juniper_clean_lines(self, config: dict) -> list[str]:
        """Return config lines with ## prefix stripped, whitespace stripped, semicolons removed."""
        return [line.replace('##', '').strip().rstrip(';') for line in config.get("raw_lines", [])]
    
    def _extract_juniper_ssh_version(self, config: dict) -> Optional[int]:
        """Extract SSH protocol-version from Juniper config.
        
        Audit: [edit system services ssh] show protocol-version → 'protocol-version v2;'
        Handles both set style (set system services ssh protocol-version v2) and
        hierarchical (protocol-version v2;) configs.
        """
        for line in self._juniper_clean_lines(config):
            if "protocol-version" in line:
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if "protocol-version" in p), None)
                if idx is not None and idx + 1 < len(parts):
                    val = parts[idx + 1].strip()
                    if val.lower() == "v2":
                        return 2
                    if val.lower() == "v1":
                        return 1
        return None
    
    def _extract_juniper_root_login(self, config: dict) -> Optional[str]:
        """Extract SSH root-login setting.
        
        Audit: [edit system services ssh] show | match root-login → 'root-login deny;'
        Returns 'deny' or 'allow' (or None if not configured).
        """
        for line in self._juniper_clean_lines(config):
            if "root-login" in line:
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if "root-login" in p), None)
                if idx is not None and idx + 1 < len(parts):
                    val = parts[idx + 1].strip()
                    if val in ("deny", "allow", "allow-and-password"):
                        return "deny" if val == "deny" else "allow"
        return None
    
    def _extract_juniper_min_length(self, config: dict) -> Optional[int]:
        """Extract local password minimum-length.
        
        Audit: [edit] show system login password minimum-length → 'minimum-length <n>;'
        Handles set system login password minimum-length N and hierarchical forms.
        """
        for line in self._juniper_clean_lines(config):
            if "minimum-length" in line:
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if "minimum-length" in p), None)
                if idx is not None and idx + 1 < len(parts):
                    try:
                        return int(parts[idx + 1])
                    except ValueError:
                        pass
        return None
    
    def _extract_juniper_password_format(self, config: dict) -> Optional[str]:
        """Extract local password hashing format.
        
        Audit: [edit] show system login password format → 'login password format sha512;'
        Handles: set system login password format sha512
                 password { format sha512; }
        Returns 'md5', 'sha1', 'sha256', 'sha512' or None if not configured.
        """
        cleaned_lines = self._juniper_clean_lines(config)
        
        # Flat set style
        for line in cleaned_lines:
            if "password format" in line:
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if p == "format"), None)
                if idx is not None and idx + 1 < len(parts):
                    val = parts[idx + 1].strip().lower()
                    if val in ("md5", "sha1", "sha256", "sha512"):
                        return val
        
        # Hierarchical: password { format sha512; }
        section_stack: list[str] = []
        for line in cleaned_lines:
            if '{' in line:
                section_stack.append(line.replace('{', '').strip())
                continue
            if '}' in line:
                if section_stack:
                    section_stack.pop()
                continue
            if line.startswith("format") and any("password" in s for s in section_stack):
                parts = line.split()
                if len(parts) >= 2:
                    val = parts[1].strip().lower()
                    if val in ("md5", "sha1", "sha256", "sha512"):
                        return val
        return None
    
    def _extract_juniper_tries_before_disconnect(self, config: dict) -> Optional[int]:
        """Extract login retry tries-before-disconnect.
        
        Audit: [edit] show system login retry-options tries-before-disconnect
        Handles: set system login retry-options tries-before-disconnect N
                 retry-options { tries-before-disconnect N; }
        """
        for line in self._juniper_clean_lines(config):
            if "tries-before-disconnect" in line:
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if "tries-before-disconnect" in p), None)
                if idx is not None and idx + 1 < len(parts):
                    try:
                        return int(parts[idx + 1])
                    except ValueError:
                        pass
        return None
    
    def _extract_juniper_lockout_period(self, config: dict) -> Optional[int]:
        """Extract login retry lockout-period in seconds.
        
        Audit: [edit] show system login retry-options lockout-period
        Junos lockout-period is in minutes; canonical representation = seconds.
        Handles: set system login retry-options lockout-period N (minutes)
                 lockout-period N;
        """
        for line in self._juniper_clean_lines(config):
            if "lockout-period" in line:
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if "lockout-period" in p), None)
                if idx is not None and idx + 1 < len(parts):
                    try:
                        minutes = int(parts[idx + 1])
                        return minutes * 60
                    except ValueError:
                        pass
        return None
    
    def _extract_juniper_ntp_version(self, config: dict) -> Optional[int]:
        """Extract NTP version.
        
        Audit: [edit] show system ntp → 'version 4;'
        Handles: set system ntp version 4 / ntp { version 4; }
        """
        for line in self._juniper_clean_lines(config):
            if "version" in line and ("ntp" in line or line.strip().startswith("version")):
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if p == "version"), None)
                if idx is not None and idx + 1 < len(parts):
                    try:
                        val = int(parts[idx + 1])
                        if val in (3, 4):
                            return val
                    except ValueError:
                        pass
        return None
    
    def _extract_juniper_time_zone(self, config: dict) -> Optional[str]:
        """Extract system time-zone.
        
        Audit: [edit] show time-zone → 'time-zone UTC;' or 'time-zone GMT;'
        Handles: set system time-zone UTC / time-zone UTC;
        """
        for line in self._juniper_clean_lines(config):
            if "time-zone" in line:
                parts = line.split()
                idx = next((i for i, p in enumerate(parts) if "time-zone" in p), None)
                if idx is not None and idx + 1 < len(parts):
                    return parts[idx + 1].strip()
        return None
    
    def _extract_juniper_loopback_configured(self, config: dict) -> Optional[bool]:
        """Check whether a loopback interface with an inet address is configured.
        
        Audit: show interfaces lo0 → unit 0 { family inet { address <ip>/<mask>; } }
        Handles: interfaces { lo0 { unit 0 { family inet { address 10.0.0.1/32; } } } }
                 set interfaces lo0 unit 0 family inet address 10.0.0.1/32
        """
        cleaned_lines = self._juniper_clean_lines(config)
        
        for line in cleaned_lines:
            if "lo0" in line and "address" in line:
                return True
        
        # Check hierarchical: lo0 block with unit 0 and family inet address
        section_stack: list[str] = []
        for line in cleaned_lines:
            if '{' in line:
                section_stack.append(line.replace('{', '').strip())
                continue
            if '}' in line:
                if section_stack:
                    section_stack.pop()
                continue
            if "address" in line and any("lo0" in s for s in section_stack):
                return True
        return None
