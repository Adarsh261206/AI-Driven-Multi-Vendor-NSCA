"""
CIS Cisco IOS Controls

DEPRECATED — retired legacy inventory (F10). Initial set of 10 high-quality
CIS controls for Cisco IOS. Each control traces:
RAW → PARSED → NORMALIZED → CONTROL → EXPECTED → ACTUAL → RESULT

Only consumed by the deprecated ControlLoader; the canonical path uses the
196-control registry in app.benchmarks. Retained for backward compatibility.
"""

from __future__ import annotations

from app.engines.compliance.models import (
    Control, ControlRule, RuleType, RuleTarget, ExpectedValue, Operator,
    Severity, RemediationTemplate,
)


CISCO_IOS_CONTROLS: list[Control] = [
    # ============================================================
    # MANAGEMENT ACCESS
    # ============================================================
    Control(
        id="CIS-Cisco-IOS-1.1",
        framework="CIS",
        framework_version="2024.1",
        category="management",
        title="Disable HTTP Server",
        description=(
            "The HTTP server feature on Cisco IOS devices allows web-based management. "
            "If enabled, it should be disabled in favor of HTTPS to prevent "
            "cleartext transmission of management credentials."
        ),
        severity=Severity.HIGH,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.VALUE_CHECK,
            target=RuleTarget(model_path="management.http.enabled"),
            expected=ExpectedValue(
                value=False,
                operator=Operator.IS_FALSE,
                description="HTTP server should be disabled",
            ),
        ),
        remediation=RemediationTemplate(
            title="Disable HTTP Server",
            description="Remove or disable the HTTP server configuration.",
            why_it_matters=(
                "HTTP transmits management credentials in cleartext, "
                "allowing network attackers to intercept administrative passwords."
            ),
            recommended_config="no ip http server",
            verification_steps=[
                "Run 'show running-config | include http' and verify no 'ip http server' line exists",
                "Verify HTTPS is enabled instead: 'show running-config | include secure-server'",
            ],
            rollback_steps=["ip http server"],
            references=[
                "https://www.cisco.com/c/en/us/support/docs/ios-nx-os-software/ios-software-releases-122sx/117712-secure-ios-access.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 1.1",
            "NIST SP 800-53 SC-7",
        ],
    ),
    
    Control(
        id="CIS-Cisco-IOS-1.2",
        framework="CIS",
        framework_version="2024.1",
        category="management",
        title="Enable HTTPS Server",
        description=(
            "HTTPS provides encrypted web management access. "
            "The HTTPS server should be enabled as a secure alternative to HTTP."
        ),
        severity=Severity.HIGH,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.VALUE_CHECK,
            target=RuleTarget(model_path="management.https.enabled"),
            expected=ExpectedValue(
                value=True,
                operator=Operator.IS_TRUE,
                description="HTTPS server should be enabled",
            ),
        ),
        remediation=RemediationTemplate(
            title="Enable HTTPS Server",
            description="Configure the HTTPS server for secure web management.",
            why_it_matters=(
                "HTTPS encrypts management traffic, preventing credential "
                "theft and configuration tampering during web-based management."
            ),
            recommended_config="ip http secure-server",
            verification_steps=[
                "Run 'show running-config | include secure-server'",
                "Verify certificate is generated: 'show crypto pki certificates'",
            ],
            rollback_steps=["no ip http secure-server"],
            references=[
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr/configuration/15-mt/sec-sec-usr-15-mt-book.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 1.2",
        ],
    ),
    
    # ============================================================
    # SSH
    # ============================================================
    Control(
        id="CIS-Cisco-IOS-2.1",
        framework="CIS",
        framework_version="2024.1",
        category="ssh",
        title="Enforce SSH Version 2",
        description=(
            "SSH version 1 has known vulnerabilities. "
            "SSH version 2 should be enforced for all management access."
        ),
        severity=Severity.CRITICAL,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.VALUE_CHECK,
            target=RuleTarget(model_path="management.ssh.version"),
            expected=ExpectedValue(
                value=2,
                operator=Operator.EQUALS,
                description="SSH version must be 2",
            ),
        ),
        remediation=RemediationTemplate(
            title="Enforce SSH Version 2",
            description="Configure the device to use SSH version 2 only.",
            why_it_matters=(
                "SSH version 1 has cryptographic weaknesses and is vulnerable "
                "to man-in-the-middle attacks. Version 2 provides stronger security."
            ),
            recommended_config="ip ssh version 2",
            verification_steps=[
                "Run 'show ip ssh' and verify 'SSH Enabled - version 2.0'",
            ],
            rollback_steps=["no ip ssh version 2"],
            references=[
                "https://www.cisco.com/c/en/us/support/docs/ip/ssh-protocol/70670-ssh-patching.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 2.1",
            "NIST SP 800-53 SC-8",
        ],
    ),
    
    Control(
        id="CIS-Cisco-IOS-2.2",
        framework="CIS",
        framework_version="2024.1",
        category="ssh",
        title="Disable Telnet",
        description=(
            "Telnet transmits data in cleartext including credentials. "
            "It should be disabled in favor of SSH for remote management."
        ),
        severity=Severity.CRITICAL,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.VALUE_CHECK,
            target=RuleTarget(model_path="management.telnet.enabled"),
            expected=ExpectedValue(
                value=False,
                operator=Operator.IS_FALSE,
                description="Telnet should be disabled",
            ),
        ),
        remediation=RemediationTemplate(
            title="Disable Telnet",
            description="Remove Telnet transport from VTY lines and use SSH only.",
            why_it_matters=(
                "Telnet transmits all data including passwords in cleartext. "
                "Attackers can sniff network traffic to capture administrative credentials."
            ),
            recommended_config="line vty 0 4\n transport input ssh",
            verification_steps=[
                "Run 'show running-config | section line vty' and verify 'transport input ssh'",
                "Verify no 'transport input telnet' exists",
            ],
            rollback_steps=["line vty 0 4\n transport input telnet ssh"],
            references=[
                "https://www.cisco.com/c/en/us/support/docs/ip/telnet-protocol/14007-42.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 2.2",
            "NIST SP 800-53 SC-7",
        ],
    ),
    
    Control(
        id="CIS-Cisco-IOS-2.3",
        framework="CIS",
        framework_version="2024.1",
        category="ssh",
        title="Set SSH Timeout",
        description=(
            "SSH sessions should have a timeout to prevent "
            "abandoned sessions from remaining open."
        ),
        severity=Severity.MEDIUM,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.THRESHOLD_CHECK,
            target=RuleTarget(model_path="management.ssh.timeout"),
            expected=ExpectedValue(
                value=300,
                operator=Operator.LESS_EQUAL,
                description="SSH timeout should be 300 seconds (5 minutes) or less",
            ),
        ),
        remediation=RemediationTemplate(
            title="Set SSH Timeout",
            description="Configure SSH exec-timeout to 5 minutes or less.",
            why_it_matters=(
                "Idle SSH sessions can be hijacked by attackers with physical "
                "or console access. Short timeouts reduce this risk."
            ),
            recommended_config="line vty 0 4\n exec-timeout 5 0",
            verification_steps=[
                "Run 'show running-config | section line vty' and verify exec-timeout is 5 0 or less",
            ],
            rollback_steps=[],
            references=[
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_usr/configuration/15-mt/sec-sec-usr-15-mt-book.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 2.3",
        ],
    ),
    
    # ============================================================
    # AUTHENTICATION
    # ============================================================
    Control(
        id="CIS-Cisco-IOS-3.1",
        framework="CIS",
        framework_version="2024.1",
        category="authentication",
        title="Enable AAA Authentication",
        description=(
            "AAA (Authentication, Authorization, and Accounting) provides "
            "centralized access control. It should be enabled for all management access."
        ),
        severity=Severity.CRITICAL,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.VALUE_CHECK,
            target=RuleTarget(model_path="aaa.authentication_enabled"),
            expected=ExpectedValue(
                value=True,
                operator=Operator.IS_TRUE,
                description="AAA authentication should be enabled",
            ),
        ),
        remediation=RemediationTemplate(
            title="Enable AAA Authentication",
            description="Configure AAA authentication for management access.",
            why_it_matters=(
                "AAA provides centralized, auditable access control. "
                "Without AAA, access control is distributed and difficult to audit."
            ),
            recommended_config="aaa new-model\naaa authentication login default local",
            verification_steps=[
                "Run 'show running-config | include aaa' and verify 'aaa new-model' exists",
                "Verify authentication method is configured",
            ],
            rollback_steps=["no aaa new-model"],
            references=[
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/sec_secctx/configuration/15-2mt/sec-secctx-15-2mt-book.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 3.1",
            "NIST SP 800-53 IA-2",
        ],
    ),
    
    Control(
        id="CIS-Cisco-IOS-3.2",
        framework="CIS",
        framework_version="2024.1",
        category="authentication",
        title="Set Minimum Password Length",
        description=(
            "Passwords should meet minimum length requirements "
            "to resist brute-force attacks."
        ),
        severity=Severity.HIGH,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.THRESHOLD_CHECK,
            target=RuleTarget(model_path="authentication.password_policy.min_length"),
            expected=ExpectedValue(
                value=8,
                operator=Operator.GREATER_EQUAL,
                description="Minimum password length should be at least 8 characters",
            ),
        ),
        remediation=RemediationTemplate(
            title="Set Minimum Password Length",
            description="Configure the minimum password length requirement.",
            why_it_matters=(
                "Short passwords are easily cracked through brute-force "
                "or dictionary attacks. Minimum length increases password entropy."
            ),
            recommended_config="security passwords min-length 8",
            verification_steps=[
                "Run 'show running-config | include min-length' and verify value >= 8",
            ],
            rollback_steps=["no security passwords min-length"],
            references=[
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/s15/sec-s15-book.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 3.2",
            "NIST SP 800-53 IA-5",
        ],
    ),
    
    # ============================================================
    # LOGGING
    # ============================================================
    Control(
        id="CIS-Cisco-IOS-4.1",
        framework="CIS",
        framework_version="2024.1",
        category="logging",
        title="Enable Remote Logging",
        description=(
            "Syslog should be configured to send logs to a central "
            "log server for aggregation, analysis, and retention."
        ),
        severity=Severity.HIGH,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.VALUE_CHECK,
            target=RuleTarget(model_path="logging.remote_enabled"),
            expected=ExpectedValue(
                value=True,
                operator=Operator.IS_TRUE,
                description="Remote syslog logging should be enabled",
            ),
        ),
        remediation=RemediationTemplate(
            title="Enable Remote Logging",
            description="Configure syslog to send logs to a central logging server.",
            why_it_matters=(
                "Local logs can be overwritten or tampered with by attackers. "
                "Centralized logging provides tamper-evident audit trails."
            ),
            recommended_config="logging host <syslog-server-ip>\nlogging trap informational",
            verification_steps=[
                "Run 'show running-config | include logging host' and verify a syslog server is configured",
                "Verify logging level: 'show running-config | include logging trap'",
            ],
            rollback_steps=["no logging host <syslog-server-ip>"],
            references=[
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/security/d15sco.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 4.1",
            "NIST SP 800-53 AU-2",
        ],
    ),
    
    # ============================================================
    # SNMP
    # ============================================================
    Control(
        id="CIS-Cisco-IOS-5.1",
        framework="CIS",
        framework_version="2024.1",
        category="snmp",
        title="Use SNMPv3 with Authentication",
        description=(
            "SNMPv1 and SNMPv2c transmit community strings in cleartext. "
            "SNMPv3 should be used with authentication and encryption."
        ),
        severity=Severity.HIGH,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.VALUE_CHECK,
            target=RuleTarget(model_path="services.snmp.version"),
            expected=ExpectedValue(
                value=3,
                operator=Operator.EQUALS,
                description="SNMP version should be 3",
            ),
        ),
        remediation=RemediationTemplate(
            title="Use SNMPv3 with Authentication",
            description="Configure SNMPv3 with authentication and privacy.",
            why_it_matters=(
                "SNMPv1/v2c community strings are sent in cleartext. "
                "SNMPv3 provides authentication, encryption, and access controls."
            ),
            recommended_config=(
                "snmp-server group admin v3 auth\n"
                "snmp-server user admin admin v3 auth sha <password> priv aes 128 <password>"
            ),
            verification_steps=[
                "Run 'show running-config | include snmp-server' and verify v3 is used",
                "Verify no community strings: 'show running-config | include snmp-server community'",
            ],
            rollback_steps=[],
            references=[
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/configuration/15-mt/snmp-15-mt-book.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 5.1",
            "NIST SP 800-53 SC-8",
        ],
    ),
    
    Control(
        id="CIS-Cisco-IOS-5.2",
        framework="CIS",
        framework_version="2024.1",
        category="snmp",
        title="Avoid Default SNMP Community Strings",
        description=(
            "Default community strings (public/private) are well-known "
            "and should not be used. Custom strings should be configured."
        ),
        severity=Severity.CRITICAL,
        vendor="cisco",
        platform="ios",
        rule=ControlRule(
            type=RuleType.VALUE_CHECK,
            target=RuleTarget(model_path="services.snmp.community_string_type"),
            expected=ExpectedValue(
                value=["none", "custom"],
                operator=Operator.IN,
                description="Community string should not be 'public' or 'private'",
            ),
        ),
        remediation=RemediationTemplate(
            title="Replace Default SNMP Community Strings",
            description="Remove default community strings and configure custom ones.",
            why_it_matters=(
                "Default community strings 'public' and 'private' are publicly known. "
                "Attackers can use them to read or modify device configurations."
            ),
            recommended_config="no snmp-server community public\nno snmp-server community private",
            verification_steps=[
                "Run 'show running-config | include snmp-server community'",
                "Verify no 'public' or 'private' community strings exist",
            ],
            rollback_steps=[],
            references=[
                "https://www.cisco.com/c/en/us/td/docs/ios-xml/ios/snmp/configuration/15-mt/snmp-15-mt-book.html",
            ],
        ),
        references=[
            "CIS Cisco IOS Benchmark 5.2",
            "NIST SP 800-53 IA-5",
        ],
    ),
]


def get_cisco_ios_controls() -> list[Control]:
    """Get all Cisco IOS controls"""
    return CISCO_IOS_CONTROLS.copy()


def get_controls_by_category(category: str) -> list[Control]:
    """Get controls filtered by category"""
    return [c for c in CISCO_IOS_CONTROLS if c.category == category]


def get_controls_by_severity(severity: Severity) -> list[Control]:
    """Get controls filtered by severity"""
    return [c for c in CISCO_IOS_CONTROLS if c.severity == severity]
