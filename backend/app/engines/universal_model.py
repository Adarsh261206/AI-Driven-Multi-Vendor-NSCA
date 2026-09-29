"""
Universal Security Model

Defines the normalized security representation that all vendor configurations
are mapped to. This is the backbone of the vendor-agnostic compliance engine.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class SecurityRelevance(str, Enum):
    """Security relevance of a configuration concept"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class SecurityConcept:
    """A concept in the universal security model"""
    path: str
    name: str
    description: str
    relevance: SecurityRelevance
    data_type: str  # "boolean", "string", "integer", "enum", "list"
    default_value: Optional[Any] = None
    allowed_values: Optional[list[Any]] = None
    parent_path: Optional[str] = None
    children: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "name": self.name,
            "description": self.description,
            "relevance": self.relevance.value,
            "data_type": self.data_type,
            "default_value": self.default_value,
            "allowed_values": self.allowed_values,
            "parent_path": self.parent_path,
            "children": self.children,
        }


class UniversalSecurityModel:
    """
    Universal Security Model

    A hierarchical model of security concepts that vendor configurations
    are normalized into. This enables cross-vendor compliance evaluation.

    Structure:
    - device: Device-level information
    - management: Management access configuration
    - authentication: Authentication settings
    - authorization: Authorization settings
    - audit: Audit and logging settings
    - network: Network security settings
    - crypto: Cryptographic settings

    The model is versioned (spec §11.3). The authoritative version is
    UniversalSecurityModel.VERSION; every NormalizedConfiguration produced
    against this schema carries it as universal_model_version.
    """

    # Spec §11.3 model version (major.minor.patch). Bump on schema change:
    # MAJOR for removed/renamed paths, MINOR for added paths, PATCH for
    # description/default clarifications.
    VERSION = "1.0.0"

    def __init__(self):
        self.concepts: dict[str, SecurityConcept] = {}
        # Instance-level alias so hasattr(model, "version") holds.
        self.version: str = type(self).VERSION
        self._initialize_model()
    
    def _initialize_model(self) -> None:
        """Initialize the universal security model"""
        
        # ============ DEVICE ============
        self._add_concept(SecurityConcept(
            path="device",
            name="Device",
            description="Device-level information",
            relevance=SecurityRelevance.NONE,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="device.hostname",
            name="Hostname",
            description="Device hostname",
            relevance=SecurityRelevance.LOW,
            data_type="string",
            parent_path="device",
        ))
        
        self._add_concept(SecurityConcept(
            path="device.vendor",
            name="Vendor",
            description="Device vendor",
            relevance=SecurityRelevance.NONE,
            data_type="string",
            parent_path="device",
        ))
        
        self._add_concept(SecurityConcept(
            path="device.platform",
            name="Platform",
            description="Device platform/OS",
            relevance=SecurityRelevance.NONE,
            data_type="string",
            parent_path="device",
        ))
        
        self._add_concept(SecurityConcept(
            path="device.firmware_version",
            name="Firmware Version",
            description="Device firmware/OS version",
            relevance=SecurityRelevance.LOW,
            data_type="string",
            parent_path="device",
        ))
        
        self._add_concept(SecurityConcept(
            path="device.time_zone",
            name="Time Zone",
            description="Configured time zone (UTC recommended for log correlation)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="string",
            default_value="UTC",
            parent_path="device",
        ))
        
        # ============ MANAGEMENT ============
        self._add_concept(SecurityConcept(
            path="management",
            name="Management",
            description="Management access configuration",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
        ))
        
        # HTTP
        self._add_concept(SecurityConcept(
            path="management.http",
            name="HTTP",
            description="HTTP management access",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="management",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.http.enabled",
            name="HTTP Enabled",
            description="Whether HTTP server is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=False,
            parent_path="management.http",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.http.port",
            name="HTTP Port",
            description="HTTP server port",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=80,
            parent_path="management.http",
        ))
        
        # HTTPS
        self._add_concept(SecurityConcept(
            path="management.https",
            name="HTTPS",
            description="HTTPS management access",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="management",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.https.enabled",
            name="HTTPS Enabled",
            description="Whether HTTPS server is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="management.https",
        ))

        self._add_concept(SecurityConcept(
            path="management.http.authentication",
            name="HTTP Authentication Method",
            description="Authentication method for the HTTP(S) server from "
                        "`ip http authentication <method>` (CIS 1.1.5)",
            relevance=SecurityRelevance.HIGH,
            data_type="string",
            default_value=None,
            parent_path="management.http",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.https.port",
            name="HTTPS Port",
            description="HTTPS server port",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=443,
            parent_path="management.https",
        ))
        
        # SSH
        self._add_concept(SecurityConcept(
            path="management.ssh",
            name="SSH",
            description="SSH management access",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="management",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.enabled",
            name="SSH Enabled",
            description="Whether SSH is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="management.ssh",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.version",
            name="SSH Version",
            description="SSH protocol version",
            relevance=SecurityRelevance.HIGH,
            data_type="integer",
            default_value=2,
            allowed_values=[1, 2],
            parent_path="management.ssh",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.port",
            name="SSH Port",
            description="SSH server port",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=22,
            parent_path="management.ssh",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.timeout",
            name="SSH Timeout",
            description="SSH-related session timeout in seconds (exec-timeout derived)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=5,
            parent_path="management.ssh",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.max_retries",
            name="SSH Max Retries",
            description="Maximum SSH authentication retries",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=3,
            parent_path="management.ssh",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.auth_retries",
            name="SSH Auth Retries",
            description="SSH authentication retry limit",
            relevance=SecurityRelevance.HIGH,
            data_type="integer",
            default_value=3,
            parent_path="management.ssh",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.source_interface",
            name="SSH Source Interface",
            description="Source interface for outbound SSH connections",
            relevance=SecurityRelevance.MEDIUM,
            data_type="string",
            parent_path="management.ssh",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.strict_host_key_check",
            name="SSH Strict Host Key Check",
            description="Whether SSH host key verification is enforced",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="management.ssh",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.ssh.root_login",
            name="SSH Root/Admin Remote Login",
            description="Whether remote root or privileged admin login over SSH is denied (allow|deny)",
            relevance=SecurityRelevance.HIGH,
            data_type="enum",
            default_value="allow",
            allowed_values=["allow", "deny"],
            parent_path="management.ssh",
        ))
        
        # VTY Transport
        self._add_concept(SecurityConcept(
            path="management.vty",
            name="VTY",
            description="Virtual terminal line configuration",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="management",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.vty.transport",
            name="VTY Transport Input",
            description="Configured transport input protocols on VTY lines (ssh, telnet, ssh telnet, or none)",
            relevance=SecurityRelevance.HIGH,
            data_type="string",
            default_value="ssh",
            allowed_values=["ssh", "telnet", "ssh telnet", "telnet ssh", "none", "unknown"],
            parent_path="management.vty",
        ))
        
        # Telnet
        self._add_concept(SecurityConcept(
            path="management.telnet",
            name="Telnet",
            description="Telnet management access",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="management",
        ))
        
        self._add_concept(SecurityConcept(
            path="management.telnet.enabled",
            name="Telnet Enabled",
            description="Whether Telnet is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=False,
            parent_path="management.telnet",
        ))
        
        # ============ AUTHENTICATION ============
        self._add_concept(SecurityConcept(
            path="authentication",
            name="Authentication",
            description="Authentication settings",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.password_policy",
            name="Password Policy",
            description="Password policy settings",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="authentication",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.password_policy.min_length",
            name="Minimum Password Length",
            description="Minimum password length requirement",
            relevance=SecurityRelevance.HIGH,
            data_type="integer",
            default_value=8,
            parent_path="authentication.password_policy",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.password_policy.complexity",
            name="Password Complexity",
            description="Whether password complexity is enforced",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="authentication.password_policy",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.password_policy.expiration",
            name="Password Expiration",
            description="Password expiration in days",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=90,
            parent_path="authentication.password_policy",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.password_policy.history",
            name="Password History",
            description="Number of passwords to remember",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=10,
            parent_path="authentication.password_policy",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.password_policy.hash_algorithm",
            name="Password Hash Algorithm",
            description="Hashing algorithm used for local passwords (md5, sha1, sha256, sha512, bcrypt, scrypt)",
            relevance=SecurityRelevance.HIGH,
            data_type="string",
            default_value="md5",
            allowed_values=["md5", "sha1", "sha256", "sha512", "bcrypt", "scrypt"],
            parent_path="authentication.password_policy",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.mfa_enabled",
            name="MFA Enabled",
            description="Whether multi-factor authentication is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=False,
            parent_path="authentication",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.lockout_policy",
            name="Lockout Policy",
            description="Account lockout policy",
            relevance=SecurityRelevance.MEDIUM,
            data_type="object",
            parent_path="authentication",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.lockout_policy.max_attempts",
            name="Max Attempts",
            description="Maximum failed login attempts before lockout",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=5,
            parent_path="authentication.lockout_policy",
        ))
        
        self._add_concept(SecurityConcept(
            path="authentication.lockout_policy.lockout_duration",
            name="Lockout Duration",
            description="Account lockout duration in minutes",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=30,
            parent_path="authentication.lockout_policy",
        ))
        
        # ============ AAA ============
        self._add_concept(SecurityConcept(
            path="aaa",
            name="AAA",
            description="Authentication, Authorization, and Accounting",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="aaa.authentication_enabled",
            name="Authentication Enabled",
            description="Whether AAA authentication is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="aaa",
        ))
        
        self._add_concept(SecurityConcept(
            path="aaa.authorization_enabled",
            name="Authorization Enabled",
            description="Whether AAA authorization is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="aaa",
        ))
        
        self._add_concept(SecurityConcept(
            path="aaa.accounting_enabled",
            name="Accounting Enabled",
            description="Whether AAA accounting is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="aaa",
        ))
        
        self._add_concept(SecurityConcept(
            path="aaa.radius_configured",
            name="RADIUS Configured",
            description="Whether RADIUS is configured",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=False,
            parent_path="aaa",
        ))
        
        self._add_concept(SecurityConcept(
            path="aaa.tacacs_configured",
            name="TACACS+ Configured",
            description="Whether TACACS+ is configured",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=False,
            parent_path="aaa",
        ))
        
        # ============ LOGGING ============
        self._add_concept(SecurityConcept(
            path="logging",
            name="Logging",
            description="Logging configuration",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="logging.enabled",
            name="Logging Enabled",
            description="Whether logging is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="logging",
        ))
        
        self._add_concept(SecurityConcept(
            path="logging.level",
            name="Log Level",
            description="Logging level",
            relevance=SecurityRelevance.MEDIUM,
            data_type="string",
            default_value="informational",
            allowed_values=["emergencies", "alerts", "critical", "errors", 
                          "warnings", "notifications", "informational", "debugging"],
            parent_path="logging",
        ))
        
        self._add_concept(SecurityConcept(
            path="logging.remote_enabled",
            name="Remote Logging Enabled",
            description="Whether remote logging is enabled",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=False,
            parent_path="logging",
        ))
        
        self._add_concept(SecurityConcept(
            path="logging.remote_server",
            name="Remote Server",
            description="Remote syslog server address",
            relevance=SecurityRelevance.MEDIUM,
            data_type="string",
            parent_path="logging",
        ))
        
        self._add_concept(SecurityConcept(
            path="logging.source_interface",
            name="Source Interface",
            description="Source interface for logging",
            relevance=SecurityRelevance.LOW,
            data_type="string",
            parent_path="logging",
        ))
        
        # ============ NTP ============
        self._add_concept(SecurityConcept(
            path="ntp",
            name="NTP",
            description="Network Time Protocol configuration",
            relevance=SecurityRelevance.MEDIUM,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="ntp.configured",
            name="NTP Configured",
            description="Whether NTP is configured",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=True,
            parent_path="ntp",
        ))
        
        self._add_concept(SecurityConcept(
            path="ntp.authenticated",
            name="NTP Authenticated",
            description="Whether NTP authentication is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="ntp",
        ))
        
        self._add_concept(SecurityConcept(
            path="ntp.trusted_key",
            name="NTP Trusted Key",
            description="Whether an NTP trusted key is configured via "
                        "`ntp trusted-key <id>` (CIS 2.3.3; distinct from "
                        "merely enabling authentication)",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="ntp",
        ))

        self._add_concept(SecurityConcept(
            path="ntp.servers",
            name="NTP Servers",
            description="Configured NTP servers",
            relevance=SecurityRelevance.MEDIUM,
            data_type="list",
            default_value=[],
            parent_path="ntp",
        ))
        
        self._add_concept(SecurityConcept(
            path="ntp.version",
            name="NTP Version",
            description="NTP protocol version used for synchronization (3 or 4)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=4,
            allowed_values=[3, 4],
            parent_path="ntp",
        ))

        self._add_concept(SecurityConcept(
            path="ntp.source_interface",
            name="NTP Source Interface",
            description="Source interface for NTP traffic from "
                        "`ntp source <interface>` (CIS 2.3.4; distinct "
                        "from merely having NTP servers configured)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="string",
            default_value=None,
            parent_path="ntp",
        ))
        
        # ============ ACCESS CONTROL ============
        self._add_concept(SecurityConcept(
            path="access_control",
            name="Access Control",
            description="Access control configuration",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="access_control.acl_applied",
            name="ACL Applied",
            description="Whether access control lists are applied",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="access_control",
        ))
        
        self._add_concept(SecurityConcept(
            path="access_control.vty_access_class_applied",
            name="VTY Access-Class Applied",
            description="Whether an access list is applied to VTY lines via "
                        "`access-class <acl> in|out` (CIS 1.2.5; a defined "
                        "ACL or an interface ip access-group is not this)",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="access_control",
        ))

        self._add_concept(SecurityConcept(
            path="access_control.default_action",
            name="Default Action",
            description="Default ACL action (permit/deny)",
            relevance=SecurityRelevance.HIGH,
            data_type="string",
            default_value="deny",
            allowed_values=["permit", "deny"],
            parent_path="access_control",
        ))
        
        self._add_concept(SecurityConcept(
            path="access_control.rules_count",
            name="Rules Count",
            description="Number of access control rules",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=0,
            parent_path="access_control",
        ))
        
        # ============ CRYPTO ============
        self._add_concept(SecurityConcept(
            path="crypto",
            name="Cryptographic",
            description="Cryptographic settings",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="crypto.ssh_key_size",
            name="SSH Key Size",
            description="SSH key size in bits",
            relevance=SecurityRelevance.HIGH,
            data_type="integer",
            default_value=2048,
            allowed_values=[1024, 2048, 4096],
            parent_path="crypto",
        ))
        
        self._add_concept(SecurityConcept(
            path="crypto.https_cert_valid",
            name="HTTPS Certificate Valid",
            description="Whether HTTPS certificate is valid",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="crypto",
        ))
        
        self._add_concept(SecurityConcept(
            path="crypto.snmp_v3_auth",
            name="SNMPv3 Authentication",
            description="Whether SNMPv3 authentication is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="crypto",
        ))
        
        # ============ MONITORING ============
        self._add_concept(SecurityConcept(
            path="monitoring",
            name="Monitoring",
            description="Monitoring and audit trail configuration",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.syslog",
            name="Syslog",
            description="Syslog configuration",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="monitoring",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.syslog.enabled",
            name="Syslog Enabled",
            description="Whether syslog is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="monitoring.syslog",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.syslog.severity_level",
            name="Syslog Severity Level",
            description="Syslog severity level (0=emergencies..7=debugging)",
            relevance=SecurityRelevance.HIGH,
            data_type="integer",
            default_value=6,
            allowed_values=[0, 1, 2, 3, 4, 5, 6, 7],
            parent_path="monitoring.syslog",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.syslog.buffered_level",
            name="Buffered Log Level",
            description="Local buffer severity from `logging buffered` "
                        "(CIS 2.2.1; distinct from trap/console/monitor)",
            relevance=SecurityRelevance.LOW,
            data_type="integer",
            default_value=None,
            allowed_values=[0, 1, 2, 3, 4, 5, 6, 7],
            parent_path="monitoring.syslog",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.syslog.trap_level",
            name="Trap Log Level",
            description="Remote-server severity from `logging trap` "
                        "(CIS 2.2.5; distinct from buffered/console/monitor)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=None,
            allowed_values=[0, 1, 2, 3, 4, 5, 6, 7],
            parent_path="monitoring.syslog",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.syslog.console_level",
            name="Console Log Level",
            description="Console severity from `logging console` "
                        "(CIS 2.2.6; distinct from trap/buffered/monitor)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=None,
            allowed_values=[0, 1, 2, 3, 4, 5, 6, 7],
            parent_path="monitoring.syslog",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.syslog.monitor_level",
            name="Monitor Log Level",
            description="Terminal-monitor severity from `logging monitor` "
                        "(CIS 2.2.7; distinct from trap/buffered/console)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=None,
            allowed_values=[0, 1, 2, 3, 4, 5, 6, 7],
            parent_path="monitoring.syslog",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.syslog.source_interface",
            name="Syslog Source Interface",
            description="Source interface for syslog messages",
            relevance=SecurityRelevance.MEDIUM,
            data_type="string",
            parent_path="monitoring.syslog",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.audit_trail",
            name="Audit Trail",
            description="Audit trail configuration",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="monitoring",
        ))
        
        self._add_concept(SecurityConcept(
            path="monitoring.audit_trail.enabled",
            name="Audit Trail Enabled",
            description="Whether audit trail is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="monitoring.audit_trail",
        ))
        
        # ============ NETWORKING ============
        self._add_concept(SecurityConcept(
            path="networking",
            name="Networking",
            description="Network security configuration",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
path="networking.access_control",
            name="Access Control",
            description="Access control configuration (spec §11.1)",
            relevance=SecurityRelevance.HIGH,
            data_type="object",
            parent_path="networking",
        ))

        self._add_concept(SecurityConcept(
            path="networking.interface_blocks",
            name="Interface Blocks",
            description="Per-interface evidence for interface-scoped "
                        "controls (diagnostic; e.g. ip redirects / "
                        "unreachables / proxy-arp per interface)",
            relevance=SecurityRelevance.NONE,
            data_type="list",
            default_value=None,
            parent_path="networking",
        ))

        self._add_concept(SecurityConcept(
            path="networking.routing_processes",
            name="Routing Process Blocks",
            description="Per-routing-process evidence (router ospf/bgp/ "
                        "eigrp/rip/isis blocks with their statements) for "
                        "ROUTER_PROCESS-scoped controls",
            relevance=SecurityRelevance.NONE,
            data_type="list",
            default_value=None,
            parent_path="networking",
        ))
        
        self._add_concept(SecurityConcept(
            path="networking.access_control.enabled",
            name="Network Access Control Enabled",
            description="Whether network access control is enabled",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=True,
            parent_path="networking.access_control",
        ))
        self._add_concept(SecurityConcept(
            path="services",
            name="Services",
            description="Network services configuration",
            relevance=SecurityRelevance.MEDIUM,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="services.snmp",
            name="SNMP",
            description="SNMP service configuration",
            relevance=SecurityRelevance.MEDIUM,
            data_type="object",
            parent_path="services",
        ))
        
        self._add_concept(SecurityConcept(
            path="services.snmp.enabled",
            name="SNMP Enabled",
            description="Whether SNMP is enabled",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=False,
            parent_path="services.snmp",
        ))
        
        self._add_concept(SecurityConcept(
            path="services.snmp.version",
            name="SNMP Version",
            description="SNMP version",
            relevance=SecurityRelevance.HIGH,
            data_type="integer",
            default_value=3,
            allowed_values=[1, 2, 3],
            parent_path="services.snmp",
        ))
        
        self._add_concept(SecurityConcept(
            path="services.snmp.community_string_type",
            name="SNMP Community String Type",
            description="Type of SNMP community string",
            relevance=SecurityRelevance.HIGH,
            data_type="string",
            default_value="none",
            allowed_values=["none", "public", "private", "custom"],
            parent_path="services.snmp",
        ))
        
        # ============ INTERFACES ============
        self._add_concept(SecurityConcept(
            path="interfaces",
            name="Interfaces",
            description="Interface security configuration",
            relevance=SecurityRelevance.MEDIUM,
            data_type="object",
        ))
        
        self._add_concept(SecurityConcept(
            path="interfaces.unused_interfaces_shutdown",
            name="Unused Interfaces Shutdown",
            description="Whether unused interfaces are shutdown",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=True,
            parent_path="interfaces",
        ))
        
        self._add_concept(SecurityConcept(
            path="interfaces.management_interface_identified",
            name="Management Interface Identified",
            description="Whether management interface is identified",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=True,
            parent_path="interfaces",
        ))
        
        self._add_concept(SecurityConcept(
            path="interfaces.loopback_configured",
            name="Loopback Interface Configured",
            description="Whether a loopback interface with an address is configured",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=False,
            parent_path="interfaces",
        ))

        # ============ E05 ADDITIONS ============
        # Spec §11.1 concepts that were absent (V05-02), control-referenced
        # leaves the model did not define (V05-55, V07-05), and diagnostic
        # leaves for evidence the normalizer produces and the benchmark
        # engine consumes (conflict/multi-block structures). Diagnostic
        # leaves are structural evidence, not security state.

        self._add_concept(SecurityConcept(
            path="management.http.secure_only",
            name="HTTP Secure Only",
            description="Management access is served over HTTPS with plain HTTP "
                        "not evidenced (spec §11.1)",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=None,
            parent_path="management.http",
        ))

        self._add_concept(SecurityConcept(
            path="management.https.certificate_valid",
            name="HTTPS Certificate Valid",
            description="Whether the HTTPS management certificate is valid "
                        "(spec §11.1; no vendor syntax observed — unsupported)",
            relevance=SecurityRelevance.HIGH,
            data_type="boolean",
            default_value=None,
            parent_path="management.https",
        ))

        self._add_concept(SecurityConcept(
            path="management.ssh.key_size",
            name="SSH Key Size",
            description="SSH host key size in bits (spec §11.1)",
            relevance=SecurityRelevance.HIGH,
            data_type="integer",
            default_value=None,
            parent_path="management.ssh",
        ))

        self._add_concept(SecurityConcept(
            path="management.ssh.session_timeout",
            name="SSH Session Timeout",
            description="SSH session negotiation timeout in seconds "
                        "(ip ssh timeout derived; referenced by CIS 1.2.x controls)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=None,
            parent_path="management.ssh",
        ))

        self._add_concept(SecurityConcept(
            path="management.vty.console_timeout",
            name="Console Timeout",
            description="Exec timeout of console line blocks in seconds "
                        "(referenced by CIS 1.2.6/2.1.3 controls)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=None,
            parent_path="management.vty",
        ))

        self._add_concept(SecurityConcept(
            path="management.vty.aux_timeout",
            name="Aux Timeout",
            description="Exec timeout of aux line blocks in seconds "
                        "(referenced by CIS 1.2.7 controls)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=None,
            parent_path="management.vty",
        ))

        self._add_concept(SecurityConcept(
            path="management.vty.vty_timeout",
            name="VTY Timeout",
            description="Exec timeout of vty line blocks in seconds "
                        "(referenced by CIS 1.2.8 and NIST controls)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="integer",
            default_value=None,
            parent_path="management.vty",
        ))

        self._add_concept(SecurityConcept(
            path="services.dns",
            name="DNS",
            description="DNS service configuration (spec §11.1)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="object",
            parent_path="services",
        ))

        self._add_concept(SecurityConcept(
            path="services.dns.configured",
            name="DNS Configured",
            description="Whether DNS name resolution is configured (spec §11.1)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=None,
            parent_path="services.dns",
        ))

        self._add_concept(SecurityConcept(
            path="services.dhcp",
            name="DHCP",
            description="DHCP service configuration (spec §11.1)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="object",
            parent_path="services",
        ))

        self._add_concept(SecurityConcept(
            path="services.dhcp.enabled",
            name="DHCP Enabled",
            description="Whether a DHCP service is enabled (spec §11.1)",
            relevance=SecurityRelevance.MEDIUM,
            data_type="boolean",
            default_value=None,
            parent_path="services.dhcp",
        ))

        self._add_concept(SecurityConcept(
            path="config",
            name="Config Diagnostics",
            description="Parser/normalizer diagnostic structures (not security state)",
            relevance=SecurityRelevance.NONE,
            data_type="object",
        ))

        self._add_concept(SecurityConcept(
            path="config.conflicts",
            name="Configuration Conflicts",
            description="Conflicting duplicate settings detected during "
                        "normalization (diagnostic evidence consumed by the "
                        "benchmark engine)",
            relevance=SecurityRelevance.NONE,
            data_type="list",
            default_value=None,
            parent_path="config",
        ))

        self._add_concept(SecurityConcept(
            path="management.vty.conflicts",
            name="VTY Conflicts",
            description="Conflicting duplicate settings across line blocks "
                        "(diagnostic evidence consumed by the benchmark engine)",
            relevance=SecurityRelevance.NONE,
            data_type="list",
            default_value=None,
            parent_path="management.vty",
        ))

        self._add_concept(SecurityConcept(
            path="management.vty.exec_timeouts",
            name="Per-Block Exec Timeouts",
            description="Exec-timeout evidence per line block (diagnostic "
                        "evidence consumed by multi-block control evaluation)",
            relevance=SecurityRelevance.NONE,
            data_type="list",
            default_value=None,
            parent_path="management.vty",
        ))

        self._add_concept(SecurityConcept(
            path="management.vty.transport_blocks",
            name="Per-Block VTY Transports",
            description="Transport-input evidence per VTY line block "
                        "(diagnostic evidence consumed by multi-block "
                        "control evaluation, e.g. CIS 1.2.2)",
            relevance=SecurityRelevance.NONE,
            data_type="list",
            default_value=None,
            parent_path="management.vty",
        ))
    
    def _add_concept(self, concept: SecurityConcept) -> None:
        """Add a concept to the model"""
        self.concepts[concept.path] = concept
        
        # Add to parent's children list
        if concept.parent_path and concept.parent_path in self.concepts:
            parent = self.concepts[concept.parent_path]
            if concept.path not in parent.children:
                parent.children.append(concept.path)
    
    def get_concept(self, path: str) -> Optional[SecurityConcept]:
        """Get a concept by path"""
        return self.concepts.get(path)
    
    def get_children(self, path: str) -> list[SecurityConcept]:
        """Get child concepts of a path"""
        concept = self.get_concept(path)
        if not concept:
            return []
        return [self.concepts[child] for child in concept.children if child in self.concepts]
    
    def get_all_paths(self) -> list[str]:
        """Get all concept paths"""
        return list(self.concepts.keys())
    
    def get_high_relevance_paths(self) -> list[str]:
        """Get all high-relevance concept paths"""
        return [
            path for path, concept in self.concepts.items()
            if concept.relevance == SecurityRelevance.HIGH
        ]

    def is_valid_path(self, path: str) -> bool:
        """A path is valid only if it names an actual model node.

        No prefix-based acceptance: the model's own path set is the source
        of truth for mapper output, control targets and AI output paths.
        """
        return isinstance(path, str) and path in self.concepts

    def leaf_paths(self) -> list[str]:
        """All leaf paths (concepts with no children), sorted."""
        return sorted(
            p for p in self.concepts
            if not self.get_children(p)
        )
