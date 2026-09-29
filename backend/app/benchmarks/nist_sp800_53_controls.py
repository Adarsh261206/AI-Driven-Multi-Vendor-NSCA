"""
NIST SP 800-53 Rev. 5 - Extracted Controls for Network Device Configuration Security

Controls extracted from NIST Special Publication 800-53 Revision 5.
Focuses on controls applicable to network device configuration assessment.
Source: https://csf.tools/reference/nist-sp-800-53/r5/
"""

from __future__ import annotations

from app.benchmarks.models import (
    AssessmentStatus,
    BenchmarkControl,
    BenchmarkRegistry,
    ControlSeverity,
    ProfileLevel,
)

BENCHMARK_ID = "NIST-SP-800-53-r5"
BENCHMARK_NAME = "NIST SP 800-53 Rev. 5"
BENCHMARK_VERSION = "5.0"
VENDOR = "universal"
PLATFORM = "network_device"
SOURCE_DOC = "NIST_SP_800-53_Rev._5.pdf"


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


def _build_registry() -> BenchmarkRegistry:
    controls = get_all_controls()
    return BenchmarkRegistry(
        benchmark_id=BENCHMARK_ID,
        benchmark_name=BENCHMARK_NAME,
        benchmark_version=BENCHMARK_VERSION,
        vendor=VENDOR,
        platform=PLATFORM,
        controls=controls,
    )


def get_all_controls() -> list[BenchmarkControl]:
    return [
        # =====================================================================
        # AC - Access Control
        # =====================================================================

        # AC-2: Account Management
        _c("AC-2", "Account Management", "Access Control",
           "The organization manages information system accounts, including establishing, activating, modifying, reviewing, disabling, and removing accounts.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           audit_command="show running-config | include username",
           references=["NIST SP 800-53 Rev. 5 AC-2"],
           source_location="AC-2"),

        _c("AC-2(1)", "Automated System Account Management", "Access Control",
           "The organization employs automated mechanisms to support the management of system accounts.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "aaa.authentication_enabled", "equals", True,
           audit_command="show running-config | include aaa new-model",
           audit_regex=r"aaa\s+new-model",
           remediation_command="aaa new-model",
           references=["NIST SP 800-53 Rev. 5 AC-2(1)"],
           source_location="AC-2(1)"),

        _c("AC-2(2)", "Automated Removal of Temporary Accounts", "Access Control",
           "The information system automatically removes temporary accounts after a defined time period.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 AC-2(2)"],
           source_location="AC-2(2)"),

        _c("AC-2(3)", "Disable Accounts for Inactivity", "Access Control",
           "The organization disables information system accounts after a defined period of inactivity.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "management.vty.vty_timeout", "less_than", 601,
           audit_command="show running-config | section line vty",
           audit_regex=r"exec-timeout\s+(\d+)\s+(\d+)",
           remediation_command="line vty 0 15\n exec-timeout 10 0",
           references=["NIST SP 800-53 Rev. 5 AC-2(3)"],
           source_location="AC-2(3)"),

        # AC-3: Access Enforcement
        _c("AC-3", "Access Enforcement", "Access Control",
           "The information system enforces approved authorizations for logical access to the system in accordance with applicable policy.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "aaa.authentication_enabled", "equals", True,
           audit_command="show running-config | include aaa new-model",
           audit_regex=r"aaa\s+new-model",
           remediation_command="aaa new-model",
           references=["NIST SP 800-53 Rev. 5 AC-3"],
           source_location="AC-3"),

        _c("AC-3(7)", "Role-Based Access Control", "Access Control",
           "The information system enforces a role-based access control policy over defined subjects and objects.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "aaa.authorization_enabled", "equals", True,
           audit_command="show running-config | include aaa authorization",
           audit_regex=r"aaa\s+authorization",
           remediation_command="aaa authorization exec default local",
           references=["NIST SP 800-53 Rev. 5 AC-3(7)"],
           source_location="AC-3(7)"),

        # AC-4: Information Flow Enforcement
        _c("AC-4", "Information Flow Enforcement", "Access Control",
           "The information system enforces approved authorizations for controlling the flow of information within the system and between interconnected systems.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "access_control.acl_applied", "equals", True,
           audit_command="show ip access-lists",
           audit_regex=r"Extended IP access list",
           references=["NIST SP 800-53 Rev. 5 AC-4"],
           source_location="AC-4"),

        # AC-6: Least Privilege
        _c("AC-6", "Least Privilege", "Access Control",
           "The organization employs the principle of least privilege, allowing only authorized accesses necessary to accomplish assigned tasks.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           None, "equals", None,
           audit_command="show running-config | include privilege",
           references=["NIST SP 800-53 Rev. 5 AC-6"],
           source_location="AC-6"),

        _c("AC-6(1)", "Least Privilege / Authorized Access", "Access Control",
           "The organization authorizes access to the information system based on a valid need-to-know and assigns appropriate privileges.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 AC-6(1)"],
           source_location="AC-6(1)"),

        _c("AC-6(5)", "Least Privilege / Privileged Accounts", "Access Control",
           "The organization restricts privileged accounts to authorized personnel.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "aaa.authentication_enabled", "equals", True,
           audit_command="show running-config | include enable secret",
           audit_regex=r"enable\s+secret",
           remediation_command="enable secret <password>",
           references=["NIST SP 800-53 Rev. 5 AC-6(5)"],
           source_location="AC-6(5)"),

        # AC-7: Unsuccessful Logon Attempts
        _c("AC-7", "Unsuccessful Logon Attempts", "Access Control",
           "The information system enforces a limit on the number of consecutive invalid access attempts.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "management.ssh.auth_retries", "less_than", 6,
           audit_command="show ip ssh | include retries",
           audit_regex=r"Authentication retries:\s+(\d+)",
           remediation_command="ip ssh authentication-retries 3",
           references=["NIST SP 800-53 Rev. 5 AC-7"],
           source_location="AC-7"),

        # AC-8: System Use Notification
        _c("AC-8", "System Use Notification", "Access Control",
           "The information system displays an approved system use notification message before granting access.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           audit_command="show running-config | include banner",
           references=["NIST SP 800-53 Rev. 5 AC-8"],
           source_location="AC-8"),

        # AC-17: Remote Access
        _c("AC-17", "Remote Access", "Access Control",
           "The organization establishes and implements restrictions on the use of external information systems.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.vty.transport", "equals", "ssh",
           audit_command="show running-config | section vty",
           audit_regex=r"transport\s+input\s+ssh",
           remediation_command="line vty 0 15\n transport input ssh",
           references=["NIST SP 800-53 Rev. 5 AC-17"],
           source_location="AC-17"),

        _c("AC-17(1)", "Remote Access / Encrypted Connections", "Access Control",
           "The organization employs encryption mechanisms for remote access sessions.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.version", "equals", 2,
           audit_command="show ip ssh",
           audit_regex=r"SSH Enabled - version 2\.0",
           remediation_command="ip ssh version 2",
           references=["NIST SP 800-53 Rev. 5 AC-17(1)"],
           source_location="AC-17(1)"),

        # AC-18: Wireless Access
        _c("AC-18", "Wireless Access", "Access Control",
           "The organization establishes restrictions on the use of wireless local area network (WLAN) capabilities.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 AC-18"],
           source_location="AC-18"),

        # =====================================================================
        # AU - Audit and Accountability
        # =====================================================================

        # AU-2: Event Logging
        _c("AU-2", "Event Logging", "Audit and Accountability",
           "The information system is configured to log events in accordance with organizational requirements.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "monitoring.audit_trail.enabled", "is_set", True,
           audit_command="show running-config | include logging buffered",
           audit_regex=r"logging\s+buffered",
           remediation_command="logging buffered informational",
           references=["NIST SP 800-53 Rev. 5 AU-2"],
           source_location="AU-2"),

        # AU-3: Content of Audit Records
        _c("AU-3", "Content of Audit Records", "Audit and Accountability",
           "The information system generates audit records containing information that establishes what type of event occurred, when it occurred, where it occurred, and the outcome.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "monitoring.audit_trail.enabled", "is_set", True,
           audit_command="show running-config | include service timestamps log",
           audit_regex=r"service\s+timestamps\s+log\s+datetime",
           remediation_command="service timestamps log datetime msec",
           references=["NIST SP 800-53 Rev. 5 AU-3"],
           source_location="AU-3"),

        _c("AU-3(1)", "Additional Audit Information / Destination", "Audit and Accountability",
           "The information system generates audit records containing the destination of each audit event.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "monitoring.syslog.enabled", "is_set", True,
           audit_command="show running-config | include logging host",
           audit_regex=r"logging\s+host",
           remediation_command="logging host <ip-address>",
           references=["NIST SP 800-53 Rev. 5 AU-3(1)"],
           source_location="AU-3(1)"),

        # AU-4: Audit Log Storage Capacity
        _c("AU-4", "Audit Log Storage Capacity", "Audit and Accountability",
           "The organization allocates audit log storage capacity adequate for audit log retention requirements.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "monitoring.syslog.enabled", "is_set", True,
           audit_command="show running-config | include logging buffered",
           audit_regex=r"logging\s+buffered",
           remediation_command="logging buffered 64000",
           references=["NIST SP 800-53 Rev. 5 AU-4"],
           source_location="AU-4"),

        # AU-5: Response to Audit Logging Process Failures
        _c("AU-5", "Response to Audit Logging Process Failures", "Audit and Accountability",
           "The information system alerts designated organizational staff in the event of an audit logging process failure.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 AU-5"],
           source_location="AU-5"),

        # AU-6: Audit Record Review, Analysis, and Reporting
        _c("AU-6", "Audit Record Review, Analysis, and Reporting", "Audit and Accountability",
           "The organization reviews, analyzes, and reports audit records to detect unusual activity and potential threats.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 AU-6"],
           source_location="AU-6"),

        # AU-8: Time Stamps
        _c("AU-8", "Time Stamps", "Audit and Accountability",
           "The information system uses internal system clocks to generate time stamps for audit records.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "ntp.configured", "equals", True,
           audit_command="show running-config | include ntp server",
           audit_regex=r"ntp\s+server",
           remediation_command="ntp server <ip-address>",
           references=["NIST SP 800-53 Rev. 5 AU-8"],
           source_location="AU-8"),

        _c("AU-8(1)", "Time Stamps / Synchronized", "Audit and Accountability",
           "The information system synchronizes internal clocks to an authoritative time source.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "ntp.authenticated", "equals", True,
           audit_command="show running-config | include ntp authenticate",
           audit_regex=r"ntp\s+authenticate",
           remediation_command="ntp authenticate\nntp authentication-key 1 md5 <key>",
           references=["NIST SP 800-53 Rev. 5 AU-8(1)"],
           source_location="AU-8(1)"),

        # AU-9: Protection of Audit Information
        _c("AU-9", "Protection of Audit Information", "Audit and Accountability",
           "The information system protects audit information from unauthorized access, modification, and deletion.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "aaa.authorization_enabled", "equals", True,
           audit_command="show running-config | include aaa authorization exec",
           audit_regex=r"aaa\s+authorization\s+exec",
           remediation_command="aaa authorization exec default local",
           references=["NIST SP 800-53 Rev. 5 AU-9"],
           source_location="AU-9"),

        # AU-11: Audit Record Retention
        _c("AU-11", "Audit Record Retention", "Audit and Accountability",
           "The organization retains audit records for a time period consistent with retention requirements.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 AU-11"],
           source_location="AU-11"),

        # AU-12: Audit Record Generation
        _c("AU-12", "Audit Record Generation", "Audit and Accountability",
           "The information system generates audit records for the events defined in AU-2.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "monitoring.audit_trail.enabled", "is_set", True,
           audit_command="show running-config | include logging",
           audit_regex=r"^logging\s",
           references=["NIST SP 800-53 Rev. 5 AU-12"],
           source_location="AU-12"),

        # =====================================================================
        # CA - Assessment, Authorization, and Monitoring
        # =====================================================================

        # CA-2: Control Assessments
        _c("CA-2", "Control Assessments", "Assessment and Authorization",
           "The organization develops and implements a security assessment plan for the information system.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CA-2"],
           source_location="CA-2"),

        # CA-7: Continuous Monitoring
        _c("CA-7", "Continuous Monitoring", "Assessment and Authorization",
           "The organization develops and implements a continuous monitoring strategy for the information system.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CA-7"],
           source_location="CA-7"),

        # =====================================================================
        # CM - Configuration Management
        # =====================================================================

        # CM-2: Baseline Configuration
        _c("CM-2", "Baseline Configuration", "Configuration Management",
           "The organization develops and maintains a current baseline configuration of the information system.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-2"],
           source_location="CM-2"),

        _c("CM-2(1)", "Baseline Configuration / Automated Baseline", "Configuration Management",
           "The organization reviews and updates the baseline configuration of the information system at least annually.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-2(1)"],
           source_location="CM-2(1)"),

        # CM-3: Configuration Change Control
        _c("CM-3", "Configuration Change Control", "Configuration Management",
           "The organization establishes and documents a change control process for the information system.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-3"],
           source_location="CM-3"),

        # CM-4: Impact Analyses
        _c("CM-4", "Impact Analyses", "Configuration Management",
           "The organization analyzes changes to the information system to determine potential security impacts.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-4"],
           source_location="CM-4"),

        # CM-5: Access Restrictions for Change
        _c("CM-5", "Access Restrictions for Change", "Configuration Management",
           "The organization defines, documents, approves, and enforces physical and logical access restrictions for changes to the information system.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "aaa.authorization_enabled", "equals", True,
           audit_command="show running-config | include aaa authorization",
           audit_regex=r"aaa\s+authorization",
           remediation_command="aaa authorization exec default local",
           references=["NIST SP 800-53 Rev. 5 CM-5"],
           source_location="CM-5"),

        # CM-6: Configuration Settings
        _c("CM-6", "Configuration Settings", "Configuration Management",
           "The information system is configured to implement the most restrictive security settings consistent with operational requirements.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-6"],
           source_location="CM-6"),

        # CM-7: Least Functionality
        _c("CM-7", "Least Functionality", "Configuration Management",
           "The information system is configured to provide only essential capabilities and disables unnecessary functions.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           None, "equals", None,
           audit_command="show running-config | include no service finger|no service pad|no service tcp-small-servers",
           audit_regex=r"no\s+service\s+(finger|pad|tcp-small-servers)",
           remediation_command="no service finger\nno service pad\nno service tcp-small-servers",
           references=["NIST SP 800-53 Rev. 5 CM-7"],
           source_location="CM-7"),

        _c("CM-7(1)", "Least Functionality / Non-Essential Ports", "Configuration Management",
           "The organization disables non-essential ports and protocols on the information system.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           None, "equals", None,
           audit_command="show running-config | include no ip http server",
           audit_regex=r"no\s+ip\s+http\s+server",
           remediation_command="no ip http server",
           references=["NIST SP 800-53 Rev. 5 CM-7(1)"],
           source_location="CM-7(1)"),

        # CM-8: System Component Inventory
        _c("CM-8", "System Component Inventory", "Configuration Management",
           "The organization develops and maintains an inventory of all information system components.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-8"],
           source_location="CM-8"),

        # CM-9: Configuration Management Plan
        _c("CM-9", "Configuration Management Plan", "Configuration Management",
           "The organization develops and implements a configuration management plan for the information system.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-9"],
           source_location="CM-9"),

        # CM-10: Software Usage Restrictions
        _c("CM-10", "Software Usage Restrictions", "Configuration Management",
           "The organization reviews and approves information system software and documentation.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-10"],
           source_location="CM-10"),

        # CM-11: User-Installed Software
        _c("CM-11", "User-Installed Software", "Configuration Management",
           "The organization enforces restrictions on the installation of software by users.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CM-11"],
           source_location="CM-11"),

        # =====================================================================
        # IA - Identification and Authentication
        # =====================================================================

        # IA-1: Identification and Authentication Policy and Procedures
        _c("IA-1", "Identification and Authentication Policy and Procedures", "Identification and Authentication",
           "The organization develops and documents identification and authentication policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IA-1"],
           source_location="IA-1"),

        # IA-2: Identification and Authentication (Organizational Users)
        _c("IA-2", "Identification and Authentication (Organizational Users)", "Identification and Authentication",
           "The information system uniquely identifies and authenticates organizational users before allowing access.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "aaa.authentication_enabled", "equals", True,
           audit_command="show running-config | include aaa new-model",
           audit_regex=r"aaa\s+new-model",
           remediation_command="aaa new-model",
           references=["NIST SP 800-53 Rev. 5 IA-2"],
           source_location="IA-2"),

        _c("IA-2(1)", "Multi-Factor Authentication", "Identification and Authentication",
           "The information system implements multi-factor authentication for network access to privileged accounts.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IA-2(1)"],
           source_location="IA-2(1)"),

        _c("IA-2(2)", "Multi-Factor Authentication / Non-Privileged", "Identification and Authentication",
           "The information system implements multi-factor authentication for network access to non-privileged accounts.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IA-2(2)"],
           source_location="IA-2(2)"),

        _c("IA-2(6)", "Access to Accounts / Separate Device", "Identification and Authentication",
           "The information system implements multi-factor authentication using a separate device.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IA-2(6)"],
           source_location="IA-2(6)"),

        _c("IA-2(8)", "Access to Accounts / Replay Resistant", "Identification and Authentication",
           "The information system implements replay-resistant authentication mechanisms.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.version", "equals", 2,
           audit_command="show ip ssh",
           audit_regex=r"SSH Enabled - version 2\.0",
           remediation_command="ip ssh version 2",
           references=["NIST SP 800-53 Rev. 5 IA-2(8)"],
           source_location="IA-2(8)"),

        # IA-4: Identifier Management
        _c("IA-4", "Identifier Management", "Identification and Authentication",
           "The organization manages system identifiers by disabling individual identifiers after a defined period of inactivity.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IA-4"],
           source_location="IA-4"),

        # IA-5: Authenticator Management
        _c("IA-5", "Authenticator Management", "Identification and Authentication",
           "The organization manages information system authenticators by enforcing password complexity and rotation requirements.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "authentication.password_policy.min_length", "greater_than", 13,
           audit_command="show running-config | include security passwords min-length",
           audit_regex=r"security\s+passwords\s+min-length\s+([0-9]+)",
           remediation_command="security passwords min-length 14",
           references=["NIST SP 800-53 Rev. 5 IA-5"],
           source_location="IA-5"),

        _c("IA-5(1)", "Password-Based Authentication / Complexity", "Identification and Authentication",
           "The information system enforces password complexity requirements.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "authentication.password_policy.complexity", "equals", True,
           audit_command="show running-config | include service password-encryption",
           audit_regex=r"service\s+password-encryption",
           remediation_command="service password-encryption",
           references=["NIST SP 800-53 Rev. 5 IA-5(1)"],
           source_location="IA-5(1)"),

        _c("IA-5(2)", "Password-Based Authentication / Password Reuse", "Identification and Authentication",
           "The information system enforces a minimum password lifetime to prevent password reuse.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IA-5(2)"],
           source_location="IA-5(2)"),

        _c("IA-5(4)", "Password-Based Authentication / Temporary Passwords", "Identification and Authentication",
           "The information system requires that initial temporary passwords be changed after first use.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IA-5(4)"],
           source_location="IA-5(4)"),

        # IA-6: Authentication Feedback
        _c("IA-6", "Authentication Feedback", "Identification and Authentication",
           "The information system obscures feedback of authentication information during the authentication process.",
           AssessmentStatus.AUTOMATED, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IA-6"],
           source_location="IA-6"),

        # IA-7: Cryptographic Module Authentication
        _c("IA-7", "Cryptographic Module Authentication", "Identification and Authentication",
           "The information system implements mechanisms for authentication to a cryptographic module that meet requirements.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.version", "equals", 2,
           audit_command="show ip ssh",
           audit_regex=r"SSH Enabled - version 2\.0",
           remediation_command="ip ssh version 2",
           references=["NIST SP 800-53 Rev. 5 IA-7"],
           source_location="IA-7"),

        # IA-8: Identification and Authentication (Non-Organizational Users)
        _c("IA-8", "Identification and Authentication (Non-Organizational Users)", "Identification and Authentication",
           "The information system uniquely identifies and authenticates non-organizational users before allowing access.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "aaa.authentication_enabled", "equals", True,
           audit_command="show running-config | include aaa new-model",
           audit_regex=r"aaa\s+new-model",
           remediation_command="aaa new-model",
           references=["NIST SP 800-53 Rev. 5 IA-8"],
           source_location="IA-8"),

        # =====================================================================
        # SC - System and Communications Protection
        # =====================================================================

        # SC-1: System and Communications Protection Policy and Procedures
        _c("SC-1", "System and Communications Protection Policy and Procedures", "System and Communications Protection",
           "The organization develops and documents system and communications protection policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-1"],
           source_location="SC-1"),

        # SC-2: Application Partitioning
        _c("SC-2", "Application Partitioning", "System and Communications Protection",
           "The information system separates user functionality from system management functionality.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-2"],
           source_location="SC-2"),

        # SC-4: Information in Shared Resources
        _c("SC-4", "Information in Shared Resources", "System and Communications Protection",
           "The information system prevents unauthorized and unintended information transfer via shared system resources.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-4"],
           source_location="SC-4"),

        # SC-5: Denial of Service Protection
        _c("SC-5", "Denial of Service Protection", "System and Communications Protection",
           "The information system protects against or limits the effects of denial of service attacks.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.auth_retries", "less_than", 6,
           audit_command="show ip ssh | include retries",
           audit_regex=r"Authentication retries:\s+(\d+)",
           remediation_command="ip ssh authentication-retries 3",
           references=["NIST SP 800-53 Rev. 5 SC-5"],
           source_location="SC-5"),

        # SC-7: Boundary Protection
        _c("SC-7", "Boundary Protection", "System and Communications Protection",
           "The information system monitors and controls communications at the external boundary and at key internal boundaries.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "access_control.acl_applied", "equals", True,
           audit_command="show ip access-lists",
           audit_regex=r"Extended IP access list",
           references=["NIST SP 800-53 Rev. 5 SC-7"],
           source_location="SC-7"),

        _c("SC-7(1)", "Physically Separated Subnetworks", "System and Communications Protection",
           "The organization implements physically separated subnetworks for public-facing services.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-7(1)"],
           source_location="SC-7(1)"),

        # SC-8: Transmission Confidentiality and Integrity
        _c("SC-8", "Transmission Confidentiality and Integrity", "System and Communications Protection",
           "The information system protects the confidentiality and integrity of transmitted information.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.version", "equals", 2,
           audit_command="show ip ssh",
           audit_regex=r"SSH Enabled - version 2\.0",
           remediation_command="ip ssh version 2",
           references=["NIST SP 800-53 Rev. 5 SC-8"],
           source_location="SC-8"),

        _c("SC-8(1)", "Transit Confidentiality and Integrity / Cryptographic Protection", "System and Communications Protection",
           "The information system implements cryptographic mechanisms to prevent unauthorized disclosure and modification during transmission.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.version", "equals", 2,
           audit_command="show ip ssh",
           audit_regex=r"SSH Enabled - version 2\.0",
           remediation_command="ip ssh version 2",
           references=["NIST SP 800-53 Rev. 5 SC-8(1)"],
           source_location="SC-8(1)"),

        # SC-10: Network Disconnect
        _c("SC-10", "Network Disconnect", "System and Communications Protection",
           "The information system disconnects or disables remote access to the information system after a defined period of inactivity.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "management.vty.vty_timeout", "less_than", 601,
           audit_command="show running-config | section line vty",
           audit_regex=r"exec-timeout\s+(\d+)\s+(\d+)",
           remediation_command="line vty 0 15\n exec-timeout 10 0",
           references=["NIST SP 800-53 Rev. 5 SC-10"],
           source_location="SC-10"),

        # SC-12: Cryptographic Key Establishment and Management
        _c("SC-12", "Cryptographic Key Establishment and Management", "System and Communications Protection",
           "The organization establishes and manages cryptographic keys for cryptographic protection of information.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "ntp.authenticated", "equals", True,
           audit_command="show running-config | include ntp authenticate",
           audit_regex=r"ntp\s+authenticate",
           remediation_command="ntp authenticate\nntp authentication-key 1 md5 <key>",
           references=["NIST SP 800-53 Rev. 5 SC-12"],
           source_location="SC-12"),

        # SC-13: Cryptographic Protection
        _c("SC-13", "Cryptographic Protection", "System and Communications Protection",
           "The information system implements FIPS-validated cryptography for data at rest and in transit.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.version", "equals", 2,
           audit_command="show ip ssh",
           audit_regex=r"SSH Enabled - version 2\.0",
           remediation_command="ip ssh version 2",
           references=["NIST SP 800-53 Rev. 5 SC-13"],
           source_location="SC-13"),

        # SC-17: PKI Certificates
        _c("SC-17", "PKI Certificates", "System and Communications Protection",
           "The organization issues public key certificates under an appropriate certificate policy.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-17"],
           source_location="SC-17"),

        # SC-20: Secure Name and Address Resolution Service
        _c("SC-20", "Secure Name and Address Resolution Service", "System and Communications Protection",
           "The information system provides additional origin authentication and integrity verification for name and address resolution responses.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-20"],
           source_location="SC-20"),

        # SC-21: Secure Name and Address Resolution Service (Authoritative Source)
        _c("SC-21", "Secure Name and Address Resolution Service (Authoritative Source)", "System and Communications Protection",
           "The information system provides additional origin authentication and integrity verification for authoritative name and address resolution.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-21"],
           source_location="SC-21"),

        # SC-22: Architecture and Design Reviews
        _c("SC-22", "Architecture and Design Reviews", "System and Communications Protection",
           "The organization reviews the information system architecture and design to ensure security principles are reflected.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-22"],
           source_location="SC-22"),

        # SC-23: Session Authenticity
        _c("SC-23", "Session Authenticity", "System and Communications Protection",
           "The information system protects the authenticity of communications sessions.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "management.ssh.version", "equals", 2,
           audit_command="show ip ssh",
           audit_regex=r"SSH Enabled - version 2\.0",
           remediation_command="ip ssh version 2",
           references=["NIST SP 800-53 Rev. 5 SC-23"],
           source_location="SC-23"),

        # SC-24: Fail in Known State
        _c("SC-24", "Fail in Known State", "System and Communications Protection",
           "The information system fails to a known, secure state for covered components when a failure is detected.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SC-24"],
           source_location="SC-24"),

        # =====================================================================
        # SI - System and Information Integrity
        # =====================================================================

        # SI-1: System and Information Integrity Policy and Procedures
        _c("SI-1", "System and Information Integrity Policy and Procedures", "System and Information Integrity",
           "The organization develops and documents system and information integrity policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-1"],
           source_location="SI-1"),

        # SI-2: Flaw Remediation
        _c("SI-2", "Flaw Remediation", "System and Information Integrity",
           "The organization identifies, reports, and corrects information system flaws in a timely manner.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-2"],
           source_location="SI-2"),

        _c("SI-2(1)", "Flaw Remediation / Central Flaw Management", "System and Information Integrity",
           "The organization centrally manages flaw remediation for information system components.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-2(1)"],
           source_location="SI-2(1)"),

        # SI-3: Malicious Code Protection
        _c("SI-3", "Malicious Code Protection", "System and Information Integrity",
           "The information system implements malicious code protection mechanisms.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-3"],
           source_location="SI-3"),

        # SI-4: System Monitoring
        _c("SI-4", "System Monitoring", "System and Information Integrity",
           "The organization monitors the information system to detect attacks and indicators of potential attacks.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "monitoring.syslog.enabled", "is_set", True,
           audit_command="show running-config | include logging host",
           audit_regex=r"logging\s+host",
           remediation_command="logging host <ip-address>",
           references=["NIST SP 800-53 Rev. 5 SI-4"],
           source_location="SI-4"),

        _c("SI-4(1)", "System Monitoring / Automated Alerts", "System and Information Integrity",
           "The organization employs automated mechanisms to alert when unauthorized network connections are detected.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-4(1)"],
           source_location="SI-4(1)"),

        _c("SI-4(4)", "Inbound and Outbound Traffic", "System and Information Integrity",
           "The organization monitors the information system to detect unauthorized inbound and outbound network connections.",
           AssessmentStatus.AUTOMATED, ControlSeverity.HIGH,
           "monitoring.syslog.enabled", "is_set", True,
           audit_command="show running-config | include logging trap",
           audit_regex=r"logging\s+trap",
           remediation_command="logging trap informational",
           references=["NIST SP 800-53 Rev. 5 SI-4(4)"],
           source_location="SI-4(4)"),

        # SI-5: Security Alerts, Advisories, and Directives
        _c("SI-5", "Security Alerts, Advisatories, and Directives", "System and Information Integrity",
           "The organization receives and responds to security alerts, advisories, and directives.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-5"],
           source_location="SI-5"),

        # SI-6: Security and Privacy Function Verification
        _c("SI-6", "Security and Privacy Function Verification", "System and Information Integrity",
           "The information system verifies the integrity of security and privacy functions at startup.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-6"],
           source_location="SI-6"),

        # SI-7: Software and Information Integrity
        _c("SI-7", "Software and Information Integrity", "System and Information Integrity",
           "The information system verifies the integrity of software and information being executed.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-7"],
           source_location="SI-7"),

        # SI-8: Spam Protection
        _c("SI-8", "Spam Protection", "System and Information Integrity",
           "The information system implements spam protection mechanisms.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-8"],
           source_location="SI-8"),

        # SI-10: Information Input Validation
        _c("SI-10", "Information Input Validation", "System and Information Integrity",
           "The information system checks the validity of information input.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-10"],
           source_location="SI-10"),

        # SI-11: Error Handling
        _c("SI-11", "Error Handling", "System and Information Integrity",
           "The information system implements error handling for information processing.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-11"],
           source_location="SI-11"),

        # SI-12: Information Management and Retention
        _c("SI-12", "Information Management and Retention", "System and Information Integrity",
           "The organization manages the retention of information to ensure it is available when needed.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-12"],
           source_location="SI-12"),

        # SI-13: Predictable Failure Prevention
        _c("SI-13", "Predictable Failure Prevention", "System and Information Integrity",
           "The organization implements measures to ensure system reliability and availability.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-13"],
           source_location="SI-13"),

        # SI-14: Non-Restorable Functions
        _c("SI-14", "Non-Restorable Functions", "System and Information Integrity",
           "The organization implements non-restorable functions for critical system operations.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SI-14"],
           source_location="SI-14"),

        # =====================================================================
        # CP - Contingency Planning
        # =====================================================================

        # CP-1: Contingency Planning Policy and Procedures
        _c("CP-1", "Contingency Planning Policy and Procedures", "Contingency Planning",
           "The organization develops and documents contingency planning policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CP-1"],
           source_location="CP-1"),

        # CP-2: Contingency Plan
        _c("CP-2", "Contingency Plan", "Contingency Planning",
           "The organization develops a contingency plan for the information system covering essential functions.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CP-2"],
           source_location="CP-2"),

        # CP-9: System Recovery and Reconstitution
        _c("CP-9", "System Recovery and Reconstitution", "Contingency Planning",
           "The organization provides for the recovery and reconstitution of the information system to a known state.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 CP-9"],
           source_location="CP-9"),

        # =====================================================================
        # MP - Media Protection
        # =====================================================================

        # MP-1: Media Protection Policy and Procedures
        _c("MP-1", "Media Protection Policy and Procedures", "Media Protection",
           "The organization develops and documents media protection policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MP-1"],
           source_location="MP-1"),

        # MP-2: Media Access
        _c("MP-2", "Media Access", "Media Protection",
           "The organization restricts access to information system media to authorized individuals.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MP-2"],
           source_location="MP-2"),

        # MP-3: Media Marking
        _c("MP-3", "Media Marking", "Media Protection",
           "The organization marks information system media indicating the classification level and handling caveats.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MP-3"],
           source_location="MP-3"),

        # MP-4: Media Storage
        _c("MP-4", "Media Storage", "Media Protection",
           "The organization stores information system media within controlled areas.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MP-4"],
           source_location="MP-4"),

        # MP-5: Media Transport
        _c("MP-5", "Media Transport", "Media Protection",
           "The organization protects and controls information system media during transport.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MP-5"],
           source_location="MP-5"),

        # MP-6: Media Sanitization
        _c("MP-6", "Media Sanitization", "Media Protection",
           "The organization sanitizes information system media before disposal or reuse.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MP-6"],
           source_location="MP-6"),

        # MP-7: Media Use
        _c("MP-7", "Media Use", "Media Protection",
           "The organization restricts the use of removable media to authorized individuals.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MP-7"],
           source_location="MP-7"),

        # =====================================================================
        # PE - Physical and Environmental Protection
        # =====================================================================

        # PE-1: Physical and Environmental Protection Policy and Procedures
        _c("PE-1", "Physical and Environmental Protection Policy and Procedures", "Physical and Environmental Protection",
           "The organization develops and documents physical and environmental protection policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PE-1"],
           source_location="PE-1"),

        # PE-2: Physical Access Authorizations
        _c("PE-2", "Physical Access Authorizations", "Physical and Environmental Protection",
           "The organization develops and implements physical access authorizations for information system facilities.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PE-2"],
           source_location="PE-2"),

        # PE-3: Physical Access Control
        _c("PE-3", "Physical Access Control", "Physical and Environmental Protection",
           "The organization implements physical access control to information system facilities.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PE-3"],
           source_location="PE-3"),

        # =====================================================================
        # PL - Planning
        # =====================================================================

        # PL-1: Security and Privacy Planning Policy and Procedures
        _c("PL-1", "Security and Privacy Planning Policy and Procedures", "Planning",
           "The organization develops and documents security and privacy planning policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PL-1"],
           source_location="PL-1"),

        # PL-2: System Security and Privacy Plans
        _c("PL-2", "System Security and Privacy Plans", "Planning",
           "The organization develops a system security plan and privacy plan for the information system.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PL-2"],
           source_location="PL-2"),

        # =====================================================================
        # RA - Risk Assessment
        # =====================================================================

        # RA-1: Risk Assessment Policy and Procedures
        _c("RA-1", "Risk Assessment Policy and Procedures", "Risk Assessment",
           "The organization develops and documents risk assessment policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 RA-1"],
           source_location="RA-1"),

        # RA-2: Security Categorization
        _c("RA-2", "Security Categorization", "Risk Assessment",
           "The organization categorizes the information system based on risk assessment.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 RA-2"],
           source_location="RA-2"),

        # RA-3: Risk Assessment
        _c("RA-3", "Risk Assessment", "Risk Assessment",
           "The organization performs risk assessments on the information system at least annually.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 RA-3"],
           source_location="RA-3"),

        # RA-5: Vulnerability Monitoring and Scanning
        _c("RA-5", "Vulnerability Monitoring and Scanning", "Risk Assessment",
           "The organization monitors and scans the information system for vulnerabilities.",
           AssessmentStatus.MANUAL, ControlSeverity.HIGH,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 RA-5"],
           source_location="RA-5"),

        # =====================================================================
        # SA - System and Services Acquisition
        # =====================================================================

        # SA-1: System and Services Acquisition Policy and Procedures
        _c("SA-1", "System and Services Acquisition Policy and Procedures", "System and Services Acquisition",
           "The organization develops and documents system and services acquisition policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SA-1"],
           source_location="SA-1"),

        # SA-3: System Development Life Cycle
        _c("SA-3", "System Development Life Cycle", "System and Services Acquisition",
           "The organization manages the information system using a system development life cycle methodology.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SA-3"],
           source_location="SA-3"),

        # SA-4: Acquisition Process
        _c("SA-4", "Acquisition Process", "System and Services Acquisition",
           "The organization incorporates security and privacy requirements into the acquisition process.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SA-4"],
           source_location="SA-4"),

        # SA-11: Developer Testing and Evaluation
        _c("SA-11", "Developer Testing and Evaluation", "System and Services Acquisition",
           "The organization requires developer testing and evaluation of security and privacy controls.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SA-11"],
           source_location="SA-11"),

        # =====================================================================
        # AT - Awareness and Training
        # =====================================================================

        # AT-1: Security and Privacy Awareness and Training Policy and Procedures
        _c("AT-1", "Security and Privacy Awareness and Training Policy and Procedures", "Awareness and Training",
           "The organization develops and documents security and privacy awareness and training policy.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 AT-1"],
           source_location="AT-1"),

        # AT-2: Literacy Training and Awareness
        _c("AT-2", "Literacy Training and Awareness", "Awareness and Training",
           "The organization provides security and privacy literacy training to users at least annually.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 AT-2"],
           source_location="AT-2"),

        # =====================================================================
        # PS - Personnel Security
        # =====================================================================

        # PS-1: Personnel Security Policy and Procedures
        _c("PS-1", "Personnel Security Policy and Procedures", "Personnel Security",
           "The organization develops and documents personnel security policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PS-1"],
           source_location="PS-1"),

        # PS-2: Position Risk Designation
        _c("PS-2", "Position Risk Designation", "Personnel Security",
           "The organization designates positions and assigns risk designations.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PS-2"],
           source_location="PS-2"),

        # =====================================================================
        # IR - Incident Response
        # =====================================================================

        # IR-1: Incident Response Policy and Procedures
        _c("IR-1", "Incident Response Policy and Procedures", "Incident Response",
           "The organization develops and documents incident response policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IR-1"],
           source_location="IR-1"),

        # IR-2: Incident Response Training
        _c("IR-2", "Incident Response Training", "Incident Response",
           "The organization provides incident response training to personnel at least annually.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IR-2"],
           source_location="IR-2"),

        # IR-4: Incident Handling
        _c("IR-4", "Incident Handling", "Incident Response",
           "The organization implements an incident handling capability for security incidents.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IR-4"],
           source_location="IR-4"),

        # IR-5: Incident Monitoring
        _c("IR-5", "Incident Monitoring", "Incident Response",
           "The organization tracks and monitors information system security incidents.",
           AssessmentStatus.AUTOMATED, ControlSeverity.MEDIUM,
           "monitoring.audit_trail.enabled", "is_set", True,
           audit_command="show running-config | include logging buffered",
           audit_regex=r"logging\s+buffered",
           remediation_command="logging buffered informational",
           references=["NIST SP 800-53 Rev. 5 IR-5"],
           source_location="IR-5"),

        # IR-6: Incident Reporting
        _c("IR-6", "Incident Reporting", "Incident Response",
           "The organization reports information system security incidents to designated authorities.",
           AssessmentStatus.MANUAL, ControlSeverity.MEDIUM,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 IR-6"],
           source_location="IR-6"),

        # =====================================================================
        # MA - Maintenance
        # =====================================================================

        # MA-1: System Maintenance Policy and Procedures
        _c("MA-1", "System Maintenance Policy and Procedures", "Maintenance",
           "The organization develops and documents system maintenance policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MA-1"],
           source_location="MA-1"),

        # MA-2: Controlled Maintenance
        _c("MA-2", "Controlled Maintenance", "Maintenance",
           "The organization schedules, performs, documents, and reviews maintenance activities.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MA-2"],
           source_location="MA-2"),

        # MA-3: Maintenance Tools
        _c("MA-3", "Maintenance Tools", "Maintenance",
           "The organization authorizes, controls, and monitors maintenance tools.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 MA-3"],
           source_location="MA-3"),

        # =====================================================================
        # PM - Program Management
        # =====================================================================

        # PM-1: Information Security Program Plan
        _c("PM-1", "Information Security Program Plan", "Program Management",
           "The organization develops and disseminates an information security program plan.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PM-1"],
           source_location="PM-1"),

        # PM-2: Information Security Program Plan / Organizational Processes
        _c("PM-2", "Information Security Program Plan / Organizational Processes", "Program Management",
           "The organization defines, documents, and implements organization-wide information security processes.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 PM-2"],
           source_location="PM-2"),

        # =====================================================================
        # SR - Supply Chain Risk Management
        # =====================================================================

        # SR-1: Supply Chain Risk Management Policy and Procedures
        _c("SR-1", "Supply Chain Risk Management Policy and Procedures", "Supply Chain Risk Management",
           "The organization develops and documents supply chain risk management policy and procedures.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SR-1"],
           source_location="SR-1"),

        # SR-2: Supply Chain Risk Management Plan
        _c("SR-2", "Supply Chain Risk Management Plan", "Supply Chain Risk Management",
           "The organization develops a supply chain risk management plan.",
           AssessmentStatus.MANUAL, ControlSeverity.LOW,
           None, "equals", None,
           references=["NIST SP 800-53 Rev. 5 SR-2"],
           source_location="SR-2"),
    ]


def get_registry() -> BenchmarkRegistry:
    """Build and return the complete NIST SP 800-53 Rev. 5 benchmark registry.

    Authoritative attribution (F3): every control in this module is DEFINED
    by NIST; framework/version/rule-confidence are stamped here.
    """
    from app.benchmarks.selection import assign_control_metadata

    controls = [assign_control_metadata(c, "NIST") for c in get_all_controls()]
    registry = BenchmarkRegistry(
        benchmark_id=BENCHMARK_ID,
        benchmark_name=BENCHMARK_NAME,
        benchmark_version=BENCHMARK_VERSION,
        vendor=VENDOR,
        platform=PLATFORM,
        controls=controls,
    )
    return registry
