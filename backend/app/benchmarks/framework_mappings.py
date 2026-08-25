"""
Cross-Framework Security Concept Mappings

One normalized universal security concept can be evaluated against multiple
framework controls. This module defines the mapping layer:

    Universal concept (e.g., management.ssh.version)
        → CIS Juniper OS control (e.g., 6.10.1.2)
        → Juniper Router RTR STIG rule (e.g., JUNI-RT-xxxxxx)
        → Juniper SRX SG NDM STIG rule (e.g., JUSX-DM-xxxxxx)

This is a framework mapping problem - NOT separate parsing or evaluation
logic. The normalization and execution layers are shared.

STIG Analysis (v1.0.0, 07-27-2022):
  - Juniper Router RTR STIG: 96 rule IDs (JUNI-RT-*), ALL Manual status.
    Profile: CAT I/II/III severity categories.
  - Juniper SRX SG NDM STIG: 71 rule IDs (JUSX-DM-*), ALL Manual status.
  Both STIG documents do not mark any rule as Automated; automation for
  these rules must NOT be claimed. Manual status is preserved.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class FrameworkReference:
    """A control in a specific framework/benchmark."""
    framework: str            # e.g., "CIS Juniper OS", "RTR STIG", "NDM STIG"
    control_id: str           # e.g., "6.10.1.2", "JUNI-RT-000010"
    title: str = ""
    assessment_status: str = "Manual"  # Automated | Manual
    severity: str = ""
    source_document: str = ""
    source_location: str = ""


@dataclass
class ConceptMapping:
    """One universal security concept mapped across frameworks."""
    universal_path: str                       # e.g., "management.ssh.version"
    description: str = ""
    references: list[FrameworkReference] = field(default_factory=list)

    def add(self, ref: FrameworkReference) -> None:
        self.references.append(ref)


# ---------------------------------------------------------------------------
# Cross-framework mappings
# ---------------------------------------------------------------------------

def get_concept_mappings() -> list[ConceptMapping]:
    """Universal concept → framework references (CIS Juniper + RTR + NDM STIG)."""
    return [
        ConceptMapping(
            universal_path="management.ssh.version",
            description="SSH protocol version restricted to v2",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.10.1.2",
                    title="Ensure SSH is Restricted to Version 2",
                    assessment_status="Automated", severity="HIGH",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 334"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000190",
                    title="Juniper router must be configured to use only approved cryptographic algorithms",
                    assessment_status="Manual", severity="CAT II"),
                FrameworkReference(
                    framework="NDM STIG", control_id="JUSX-DM-000015",
                    title="Juniper device manager must use FIPS-validated cryptography",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="management.telnet.enabled",
            description="Telnet (cleartext management) disabled",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.10.6",
                    title="Ensure Telnet is Not Set",
                    assessment_status="Automated", severity="HIGH",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 427"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000290",
                    title="Juniper router must be configured to prohibit the use of unencrypted management protocols",
                    assessment_status="Manual", severity="CAT II"),
                FrameworkReference(
                    framework="NDM STIG", control_id="JUSX-DM-000019",
                    title="Juniper device manager must prohibit unencrypted remote management",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="ntp.servers",
            description="External NTP servers configured",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.7.1",
                    title="Ensure External NTP Servers are set",
                    assessment_status="Automated", severity="MEDIUM",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 288"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000480",
                    title="Juniper router must be configured to synchronize internal information system clocks",
                    assessment_status="Manual", severity="CAT II"),
                FrameworkReference(
                    framework="NDM STIG", control_id="JUSX-DM-000041",
                    title="Juniper device manager must synchronize internal clocks",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="ntp.version",
            description="NTP protocol version 4",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.7.4",
                    title="Ensure NTP uses version 4",
                    assessment_status="Automated", severity="MEDIUM",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 297"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000480",
                    title="Juniper router must be configured to synchronize internal information system clocks",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="aaa.accounting_enabled",
            description="Accounting of login/configuration events",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.1.2",
                    title="Ensure Accounting of Logins",
                    assessment_status="Automated", severity="MEDIUM",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 207"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000300",
                    title="Juniper router must be configured to generate audit records for successful/unsuccessful logon attempts",
                    assessment_status="Manual", severity="CAT II"),
                FrameworkReference(
                    framework="NDM STIG", control_id="JUSX-DM-000020",
                    title="Juniper device manager must generate audit records for logon events",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="logging.remote_enabled",
            description="External syslog/SIEM host configured",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.12.1",
                    title="Ensure External SYSLOG Host is Set",
                    assessment_status="Automated", severity="MEDIUM",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 449"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000310",
                    title="Juniper router must be configured to send log data to a central log server",
                    assessment_status="Manual", severity="CAT II"),
                FrameworkReference(
                    framework="NDM STIG", control_id="JUSX-DM-000021",
                    title="Juniper device manager must send audit records to a central server",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="authentication.password_policy.min_length",
            description="Local password minimum length (>= 10)",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.6.11",
                    title="Ensure local passwords are at least 10 characters",
                    assessment_status="Automated", severity="HIGH",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 277"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000360",
                    title="Juniper router must be configured to enforce a minimum 15-character password length",
                    assessment_status="Manual", severity="CAT II"),
                FrameworkReference(
                    framework="NDM STIG", control_id="JUSX-DM-000024",
                    title="Juniper device manager must enforce minimum password length",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="management.ssh.root_login",
            description="Remote root login over SSH denied",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.10.1.5",
                    title="Ensure Remote Root-Login is denied via SSH",
                    assessment_status="Automated", severity="HIGH",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 340"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000380",
                    title="Juniper router must be configured to protect the root account",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="device.time_zone",
            description="System time zone set to UTC",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="6.18",
                    title="Ensure Time-Zone is Set to UTC",
                    assessment_status="Automated", severity="LOW",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 476"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000500",
                    title="Juniper router must be configured to record time stamps for audit records",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
        ConceptMapping(
            universal_path="interfaces.loopback_configured",
            description="Loopback interface with address configured",
            references=[
                FrameworkReference(
                    framework="CIS Juniper OS", control_id="3.8",
                    title="Ensure Loopback interface address is set",
                    assessment_status="Automated", severity="MEDIUM",
                    source_document="CIS_Juniper_OS_Benchmark_v2.1.0 PDF.pdf",
                    source_location="Page 94"),
                FrameworkReference(
                    framework="RTR STIG", control_id="JUNI-RT-000230",
                    title="Juniper router must be configured to bind management services to the loopback interface",
                    assessment_status="Manual", severity="CAT II"),
            ],
        ),
    ]


def get_mappings_for_universal_path(path: str) -> Optional[ConceptMapping]:
    """Get the cross-framework mapping for a universal model path."""
    for mapping in get_concept_mappings():
        if mapping.universal_path == path:
            return mapping
    return None
