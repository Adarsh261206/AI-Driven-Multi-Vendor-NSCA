"""
CIS Juniper OS Benchmark v2.1.0 - Extracted Controls

Controls extracted from the CIS Juniper OS Benchmark v2.1.0 PDF.
Uses paraphrased summaries (not verbatim copyrighted text).
Source metadata and references are retained.

Only high-value AUTOMATED controls across key domains are implemented
in this phase; the remaining benchmark recommendations are tracked for
future ingestion.
"""

from __future__ import annotations

from app.benchmarks.models import (
    AssessmentStatus,
    BenchmarkControl,
    BenchmarkRegistry,
    ControlSeverity,
    ProfileLevel,
)

BENCHMARK_ID = "CIS-JUNIPER-OS-v2.1.0"
BENCHMARK_NAME = "CIS Juniper OS Benchmark"
BENCHMARK_VERSION = "v2.1.0"
VENDOR = "juniper"
PLATFORM = "junos"
SOURCE_DOC = "CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf"


def _c(
    control_id: str,
    title: str,
    category: str,
    description: str,
    assessment_status: AssessmentStatus,
    severity: ControlSeverity,
    target_model_path: str | None,
    operator: str,
    expected_value,
    audit_command: str = "",
    audit_regex: str = "",
    remediation_command: str = "",
    negated: bool = False,
    references: list[str] | None = None,
    source_location: str = "",
    profile_level: ProfileLevel = ProfileLevel.LEVEL_1,
) -> BenchmarkControl:
    return BenchmarkControl(
        benchmark_id=BENCHMARK_ID,
        benchmark_name=BENCHMARK_NAME,
        benchmark_version=BENCHMARK_VERSION,
        vendor=VENDOR,
        platform=PLATFORM,
        control_id=control_id,
        title=title,
        category=category,
        description=description,
        assessment_status=assessment_status,
        profile_level=profile_level,
        severity=severity,
        target_model_path=target_model_path,
        operator=operator,
        expected_value=expected_value,
        audit_command=audit_command,
        audit_regex=audit_regex,
        remediation_command=remediation_command,
        negated=negated,
        references=references or [],
        source_document=SOURCE_DOC,
        source_location=source_location,
    )


def get_all_controls() -> list[BenchmarkControl]:
    """All extracted CIS Juniper OS v2.1.0 controls (implemented subset)."""
    return [
        # ------------------------------------------------------------------
        # Section 1 - General (manual example control)
        # ------------------------------------------------------------------
        _c("1.7", "Ensure logging data is monitored", "General",
           "Logging data from the device must be actively monitored by staff or a SIEM.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           audit_command="show log messages",
           remediation_command="Monitor device logs on a regular schedule",
           source_location="Page 30",
           references=["PCI DSS 3.2.1 Requirement 10.6"]),

        # ------------------------------------------------------------------
        # Section 3 - Interfaces
        # ------------------------------------------------------------------
        _c("3.8", "Ensure Loopback interface address is set", "Interfaces",
           "Configure a loopback interface address so services bind to a stable source address.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "interfaces.loopback_configured", "equals", True,
           audit_command="show interfaces lo0",
           audit_regex=r"lo0\s*\{|address\s+[\d\.]+/32",
           remediation_command="set interfaces lo0 unit 0 family inet address <ip address>",
           source_location="Page 94",
           profile_level=ProfileLevel.LEVEL_2,
           references=["Router Security Configuration Guide, NSA"]),

        # ------------------------------------------------------------------
        # Section 5 - SNMP
        # ------------------------------------------------------------------
        _c("5.1", "Ensure Common SNMP Community Strings are NOT used", "SNMP",
           "Do not use common/default SNMP community strings (public, private, admin, monitor, security).",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           None, "equals", None,
           audit_command='show snmp | match community',
           audit_regex=r"community\s+(public|private|admin|monitor|security)\b",
           remediation_command="rename community <old> to community <new>",
           negated=True,
           source_location="Page 185",
           references=["PCI DSS 3.2.1 Requirement 8.2.1, 8.5"]),

        _c("5.2", "Ensure SNMPv1/2 are set to Read Only", "SNMP",
           "SNMP versions below v3 must not permit read-write authorization.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           None, "equals", None,
           audit_command="show snmp | match authorization",
           audit_regex=r"authorization\s+read-write",
           remediation_command="delete snmp community <name> authorization read-write",
           negated=True,
           source_location="Page 187",
           references=["Router Security Configuration Guide, NSA"]),

        _c("5.4", "Ensure Default Restrict is set in all client lists", "SNMP",
           "SNMP client lists must deny any source not explicitly permitted.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           None, "equals", None,
           audit_command="show snmp | match default restrict",
           audit_regex=r"default\s+restrict",
           remediation_command="set snmp client-list <name> default restrict",
           source_location="Page 191",
           references=["CIS Cisco IOS Benchmark v2.2 Requirement 1.1.5.6"]),

        # ------------------------------------------------------------------
        # Section 6.1 - Accounting
        # ------------------------------------------------------------------
        _c("6.1.2", "Ensure Accounting of Logins", "Accounting",
           "Login events must be sent to configured accounting destinations when external AAA is used.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "aaa.accounting_enabled", "equals", True,
           audit_command="show system accounting",
           audit_regex=r"accounting\s*\{|events\s+login",
           remediation_command="set system accounting events login",
           source_location="Page 207",
           references=["PCI DSS 3.2.1 Requirement 10.2"]),

        # ------------------------------------------------------------------
        # Section 6.6 - Login
        # ------------------------------------------------------------------
        _c("6.6.1.1", "Ensure Max 3 Failed Login Attempts", "Login",
           "A maximum of 3 failed login attempts should be allowed before the session is disconnected.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "authentication.lockout_policy.max_attempts", "less_than_or_equal", 3,
           audit_command="show system login retry-options tries-before-disconnect",
           audit_regex=r"tries-before-disconnect\s+\d+",
           remediation_command="set system login retry-options tries-before-disconnect 3",
           source_location="Page 245",
           references=["NSA Router Security Configuration Guide 1.1b"]),

        _c("6.6.1.5", "Ensure Lockout-period is set to at least 30 minutes", "Login",
           "After the backoff threshold is reached, users must be locked out for at least 30 minutes.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "authentication.lockout_policy.lockout_duration", "greater_than_or_equal", 1800,
           audit_command="show system login retry-options lockout-period",
           audit_regex=r"lockout-period\s+\d+",
           remediation_command="set system login retry-options lockout-period 30",
           source_location="Page 253",
           references=["NSA Router Security Configuration Guide 1.1b"]),

        _c("6.6.11", "Ensure local passwords are at least 10 characters", "Login",
           "Local user account passwords must be at least 10 characters.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "authentication.password_policy.min_length", "greater_than_or_equal", 10,
           audit_command="show system login password minimum-length",
           audit_regex=r"minimum-length\s+\d+",
           remediation_command="set system login password minimum-length 10",
           source_location="Page 277",
           references=["PCI DSS 3.2.1 Requirement 8.1"]),

        _c("6.6.12", "Ensure SHA512 is used to hash local passwords", "Login",
           "Local passwords must be hashed with SHA512 (or at least SHA1 on unsupported platforms).",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "authentication.password_policy.hash_algorithm", "equals", "sha512",
           audit_command="show system login password format",
           audit_regex=r"format\s+sha512",
           remediation_command="set system login password format sha512",
           source_location="Page 279",
           references=["NSA Router Security Configuration Guide 1.1b"]),

        # ------------------------------------------------------------------
        # Section 6.7 - NTP
        # ------------------------------------------------------------------
        _c("6.7.1", "Ensure External NTP Servers are set", "NTP",
           "At least one external NTP server must be configured.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "ntp.servers", "is_set", None,
           audit_command="show system ntp | match server",
           audit_regex=r"ntp\s+server\s+[\d\.\:a-fA-F]+|server\s+[\d\.\:a-fA-F]+",
           remediation_command="set system ntp server <server IP>",
           source_location="Page 288",
           references=["PCI DSS 3.2.1 Requirement 10.4"]),

        _c("6.7.4", "Ensure NTP uses version 4", "NTP",
           "NTP must use protocol version 4.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "ntp.version", "equals", 4,
           audit_command="show system ntp",
           audit_regex=r"version\s+4",
           remediation_command="set system ntp version 4",
           source_location="Page 297",
           references=["IETF BCP 13"]),

        # ------------------------------------------------------------------
        # Section 6.10 - Services
        # ------------------------------------------------------------------
        _c("6.10.1.2", "Ensure SSH is Restricted to Version 2", "SSH",
           "Remote console connections must only use SSH Version 2.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.version", "equals", 2,
           audit_command="show system services ssh protocol-version",
           audit_regex=r"protocol-version\s+v2",
           remediation_command="set system services ssh protocol-version v2",
           source_location="Page 334",
           references=["NSA Router Security Configuration Guide 1.1b"]),

        _c("6.10.1.5", "Ensure Remote Root-Login is denied via SSH", "SSH",
           "Remote access to the root user account over SSH must be denied.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.root_login", "equals", "deny",
           audit_command="show system services ssh | match root-login",
           audit_regex=r"root-login\s+deny",
           remediation_command="set system services ssh root-login deny",
           source_location="Page 340",
           references=["Juniper JUNOS 9.2 System Basics Configuration Guide"]),

        _c("6.10.6", "Ensure Telnet is Not Set", "Services",
           "Cleartext management services such as Telnet must be disabled.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.telnet.enabled", "equals", False,
           audit_command="show system services | match telnet",
           audit_regex=r"telnet",
           remediation_command="delete system services telnet",
           source_location="Page 427",
           references=["PCI DSS 3.2.1 Requirement 2.3, 8.2.1"]),

        # ------------------------------------------------------------------
        # Section 6.12 - SYSLOG
        # ------------------------------------------------------------------
        _c("6.12.1", "Ensure External SYSLOG Host is Set", "Logging",
           "Logging data must be sent to at least one external SYSLOG server with any/info severity.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "logging.remote_enabled", "equals", True,
           audit_command="show system syslog host",
           audit_regex=r"syslog\s*\{|host\s+[\d\.\:a-fA-F]+",
           remediation_command="set system syslog host <server> any info",
           source_location="Page 449",
           references=["PCI DSS 3.2.1 Requirement 10.5"]),

        # ------------------------------------------------------------------
        # Section 6.18 - Time Zone
        # ------------------------------------------------------------------
        _c("6.18", "Ensure Time-Zone is Set to UTC", "System",
           "All devices should use the UTC time zone for consistent log correlation.",
           AssessmentStatus.AUTOMATED, ControlSeverity.LOW,
           "device.time_zone", "equals", "UTC",
           audit_command="show system time-zone",
           audit_regex=r"time-zone\s+UTC|time-zone\s+GMT",
           remediation_command="set system time-zone UTC",
           source_location="Page 476",
           profile_level=ProfileLevel.LEVEL_2,
           references=["NSA Router Security Configuration Guide 1.1b"]),
    ]


def get_registry() -> BenchmarkRegistry:
    """Build the benchmark registry for CIS Juniper OS v2.1.0.

    Authoritative attribution (F3): every control in this module is DEFINED
    by CIS; framework/version/rule-confidence are stamped here.
    """
    from app.benchmarks.selection import assign_control_metadata

    controls = [assign_control_metadata(c, "CIS") for c in get_all_controls()]
    return BenchmarkRegistry(
        benchmark_id=BENCHMARK_ID,
        benchmark_name=BENCHMARK_NAME,
        benchmark_version=BENCHMARK_VERSION,
        vendor=VENDOR,
        platform=PLATFORM,
        controls=controls,
    )
