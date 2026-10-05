"""
Vendor Detection Engine

Identifies device vendor, platform, and firmware version from configuration content.

Evidence-first contract (E03 F1-F17):
  * the pattern scorer always decides the vendor, platform, firmware and evidence;
  * a vendor claim requires >= 2 distinct matched patterns including >= 1
    structural match (COMMAND_SYNTAX / CONFIG_STRUCTURE / KEYWORD) — banner
    text alone never claims a vendor and never beats structural evidence;
  * two vendors with strong structural evidence means the file mixes dialects
    and the verdict is 'unknown' (F8);
  * the ML model is accepted only when it agrees with the pattern verdict; its
    confidence formula and platform claims never override the scorer (F1/F3);
  * content that consists only of Cisco '!' comment lines yields 'unknown' (F7).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum

logger = logging.getLogger(__name__)


class DetectionMethod(str, Enum):
    """Method used for vendor detection"""
    BANNER = "banner"
    COMMAND_SYNTAX = "command_syntax"
    CONFIG_STRUCTURE = "config_structure"
    KEYWORD = "keyword"
    PATTERN = "pattern"


@dataclass
class DetectionEvidence:
    """Evidence for vendor detection"""
    method: DetectionMethod
    pattern: str
    matched_text: str
    line_number: Optional[int] = None


@dataclass
class VendorIdentification:
    """Result of vendor detection"""
    vendor: str
    platform: str
    confidence: float
    firmware_version: Optional[str] = None
    detection_method: DetectionMethod = DetectionMethod.KEYWORD
    detection_evidence: list[DetectionEvidence] = field(default_factory=list)
    device_type: str = "unknown"  # switch, router, firewall, unknown
    hostname: Optional[str] = None


# Vendors that have a compliance parser/controls behind them (Engines 04/07).
# Anything else this engine can recognise — notably paloalto — is
# detection-only: reported by name, never handed to a parser (E03 F2/F10).
SUPPORTED_COMPLIANCE_VENDORS = frozenset({"cisco", "juniper", "fortinet"})

# One canonical platform vocabulary: the ML model emits "ios_xe" while the
# pattern table uses "ios". Everything downstream sees "ios" (E03 F3/F5).
PLATFORM_ALIASES = {"ios_xe": "ios"}

# A vendor claim needs at least this many distinct pieces of evidence —
# a (pattern, line) pair counts once. Banner + one structural line qualifies;
# a single match on a single line does not (a single pattern matching several
# independent lines does, e.g. JUNOS hierarchical "system {"/"interfaces {").
MIN_EVIDENCE_PATTERNS = 2

# Two vendors with at least this much structural evidence each means the file
# mixes dialects — report unknown instead of guessing (E03 F8). The runner-up
# must also be comparable to the leader (>= 25% of its structural score):
# two stray "##" comment lines must not veto a file whose real dialect has
# dozens of structural matches.
MIXED_VENDOR_STRUCTURAL_FLOOR = 2
MIXED_VENDOR_STRUCTURAL_RATIO = 0.25

# Legacy ML acceptance gate. Kept as-is; no confidence threshold was invented
# for the compliance gate (E03 F16: confidence stays informational).
ML_CONFIDENCE_GATE = 0.55


class VendorDetector:
    """
    Vendor Detection Engine

    Detects:
    - Vendor (Cisco, Fortinet, Juniper, etc.)
    - Platform (IOS, NX-OS, FortiOS, Junos, etc.)
    - Firmware version (when available)
    """

    # Vendor detection patterns
    VENDOR_PATTERNS = {
        "cisco": {
            "platforms": {
                "ios": [
                    (r"^(?:hostname|version)\s+\d+", DetectionMethod.COMMAND_SYNTAX),
                    (r"^(?:interface|router|switch)\s+", DetectionMethod.COMMAND_SYNTAX),
                    (r"^!", DetectionMethod.CONFIG_STRUCTURE),
                    (r"(?:enable\s+secret|enable\s+password)", DetectionMethod.KEYWORD),
                    (r"(?:line\s+(?:vty|console|aux))", DetectionMethod.COMMAND_SYNTAX),
                ],
                "nx-os": [
                    (r"^(?:feature|switchport)", DetectionMethod.COMMAND_SYNTAX),
                    (r"(?:vlan\s+database|interface\s+(?:Ethernet|Management))", DetectionMethod.COMMAND_SYNTAX),
                ],
                "asa": [
                    (r"^(?:object|access-list|nat)", DetectionMethod.COMMAND_SYNTAX),
                    (r"(?:firewall\s+mode|threat-detection)", DetectionMethod.KEYWORD),
                ],
            },
            "banner_patterns": [
                (r"Cisco\s+(?:IOS|NX-OS|ASA)", DetectionMethod.BANNER),
                (r"(?:Router|Switch|Firewall)\s+Management", DetectionMethod.BANNER),
            ],
            "version_patterns": [
                r"version\s+(\d+\.\d+(?:\.\d+)*(?:\(\w+\))?\w*)",
                r"Cisco\s+(?:IOS|NX-OS)\s+Software.*?Version\s+(\S+)",
            ],
        },
        "fortinet": {
            "platforms": {
                "fortios": [
                    # bare "config system ..." (FortiOS `show` output) or the
                    # "# config system ..." commented form — both are real
                    # FortiOS block syntax (E02 validation accepts both).
                    (r"^\s*#?\s*config\s+[a-z][\w-]*(?:\s+[\w-]+)*", DetectionMethod.CONFIG_STRUCTURE),
                    (r"(?:set\s+(?:status|mode|type))", DetectionMethod.COMMAND_SYNTAX),
                    (r"(?:end|next)\s*$", DetectionMethod.CONFIG_STRUCTURE),
                    (r"^\s*execute\s+[a-z][\w-]*", DetectionMethod.COMMAND_SYNTAX),
                ],
            },
            "banner_patterns": [
                (r"Forti(?:gate|Gate|Switch|AP)", DetectionMethod.BANNER),
                (r"FortiOS", DetectionMethod.BANNER),
            ],
            "version_patterns": [
                r"(?:FortiOS|version)\s+(?:v)?(\d+\.\d+(?:\.\d+)?)",
            ],
        },
        "juniper": {
            "platforms": {
                "junos": [
                    # "##" comment marker — but NOT "###..." bars (FortiOS /
                    # markdown comment rules are not JUNOS evidence).
                    (r"^##(?!#)", DetectionMethod.CONFIG_STRUCTURE),
                    # top-level hierarchical blocks (same set E02 validation
                    # accepts as JUNOS content)
                    (r"^\s*(?:system|protocols|routing-options|interfaces|snmp|"
                      r"security|vlans|policy-options|forwarding-options|chassis|"
                      r"applications|routing-instances|class-of-service|"
                      r"configuration)\s*\{", DetectionMethod.CONFIG_STRUCTURE),
                    # set-style JUNOS; "(?=\s)" keeps FortiOS keys like
                    # "set security-status ..." from matching "set security".
                    (r"(?:set\s+(?:system|protocols|routing-options|interfaces|"
                      r"snmp|security|vlans|policy-options|forwarding-options|"
                      r"chassis|applications|routing-instances|"
                      r"class-of-service|firewall|groups)(?=\s))",
                     DetectionMethod.COMMAND_SYNTAX),
                ],
            },
            "banner_patterns": [
                (r"Juniper\s+Networks", DetectionMethod.BANNER),
                (r"JUNOS", DetectionMethod.BANNER),
            ],
            "version_patterns": [
                r"(?:JUNOS|Junos)\s+Software\s+Release\s+(\S+)",
                r"version\s+(\d+\.\d+[A-Z]?\d*(?:\.\d+)?)",
            ],
        },
        "paloalto": {
            "platforms": {
                "panos": [
                    (r"(?:set\s+deviceconfig\s+)", DetectionMethod.COMMAND_SYNTAX),
                    (r"(?:set\s+rulebase\s+)", DetectionMethod.COMMAND_SYNTAX),
                    (r"(?:set\s+network\s+)", DetectionMethod.COMMAND_SYNTAX),
                ],
            },
            "banner_patterns": [
                (r"Palo\s+Alto", DetectionMethod.BANNER),
                (r"PAN-OS", DetectionMethod.BANNER),
            ],
            "version_patterns": [
                r"PAN-OS\s+(\d+\.\d+(?:\.\d+)?)",
            ],
        },
    }

    # Device type patterns — switch vs router vs firewall
    DEVICE_TYPE_PATTERNS = {
        "switch": [
            (r"interface\s+(?:FastEthernet|GigabitEthernet|Ethernet|TenGigabit)", DetectionMethod.COMMAND_SYNTAX),
            (r"switchport\s+mode", DetectionMethod.COMMAND_SYNTAX),
            (r"spanning-tree", DetectionMethod.KEYWORD),
            (r"vlan\s+\d+", DetectionMethod.COMMAND_SYNTAX),
            (r"Switch", DetectionMethod.KEYWORD),
        ],
        "router": [
            (r"router\s+(?:ospf|bgp|eigrp|rip|isis)", DetectionMethod.COMMAND_SYNTAX),
            (r"interface\s+(?:Serial|Loopback)", DetectionMethod.COMMAND_SYNTAX),
            (r"ip\s+route\s+", DetectionMethod.COMMAND_SYNTAX),
            (r"Router", DetectionMethod.KEYWORD),
        ],
        "firewall": [
            (r"access-list|access-group", DetectionMethod.COMMAND_SYNTAX),
            (r"nat\s+\(|object\s+network", DetectionMethod.COMMAND_SYNTAX),
            (r"threat-detection|inspect\s+", DetectionMethod.KEYWORD),
            (r"Firewall", DetectionMethod.KEYWORD),
            (r"config\s+firewall\s+policy", DetectionMethod.CONFIG_STRUCTURE),
            (r"set\s+rulebase\s+security", DetectionMethod.COMMAND_SYNTAX),
        ],
    }

    def detect(self, content: str) -> VendorIdentification:
        """
        Detect vendor from configuration content.

        The pattern scorer decides vendor/platform/firmware/evidence; the ML
        model (TF-IDF + LogisticRegression) is accepted only when it agrees
        with the pattern verdict, and its confidence is reported as
        min(0.99, ml_conf * 1.05).

        Args:
            content: Configuration content string

        Returns:
            VendorIdentification with detection results

        Raises:
            TypeError: if content is not a str (E03 F13)
        """
        if not isinstance(content, str):
            raise TypeError("content must be a string")

        comment_only = self._is_cisco_comment_only(content)
        scores: dict[str, dict] = {} if comment_only else self._score_vendors(content)
        vendor, platform, confidence, ev_vendor, ev_platform = self._decide(scores)

        device_type = self._detect_device_type(content)
        platform = self._postprocess_platform(vendor, platform, content)
        if platform == "asa":
            device_type = "firewall"
        hostname = self._extract_hostname(content)
        firmware_version = self._extract_firmware(content, vendor)
        evidence = self._collect_evidence(content, ev_vendor, ev_platform)
        detection_method = evidence[0].method if evidence else DetectionMethod.KEYWORD

        # === ML path (real model, corroborated) ===
        try:
            from app.ml.model import get_ml_detector
            ml = get_ml_detector()
            if ml.is_available:
                ml_vendor, ml_platform, ml_device, ml_conf, ml_method = ml.predict(content)
                if (
                    ml_conf >= ML_CONFIDENCE_GATE
                    and ml_vendor != "unknown"
                    and vendor != "unknown"
                    and ml_vendor == vendor
                ):
                    ml_evidence = self._collect_evidence(content, ev_vendor, ev_platform)
                    ml_evidence.insert(0, DetectionEvidence(
                        method=DetectionMethod.PATTERN,
                        pattern="ML model: TF-IDF + LogisticRegression",
                        matched_text=f"ML predicted {ml_vendor}/{ml_platform} ({ml_device}) conf={ml_conf:.2f}",
                        line_number=None,
                    ))
                    if platform == "asa":
                        ml_device_type = "firewall"
                    else:
                        ml_device_type = (
                            ml_device if ml_device != "unknown" else device_type
                        )
                    return VendorIdentification(
                        vendor=ml_vendor,
                        platform=platform,
                        confidence=min(0.99, ml_conf * 1.05),
                        firmware_version=firmware_version,
                        detection_method=DetectionMethod.PATTERN,
                        detection_evidence=ml_evidence[:10],
                        device_type=ml_device_type,
                        hostname=hostname,
                    )
        except Exception as exc:
            logger.warning(
                "Vendor ML detection failed: %s; falling back to regex",
                type(exc).__name__,
            )

        return VendorIdentification(
            vendor=vendor,
            platform=platform,
            confidence=confidence,
            firmware_version=firmware_version,
            detection_method=detection_method,
            detection_evidence=evidence,
            device_type=device_type,
            hostname=hostname,
        )

    def _score_vendors(self, content: str) -> dict[str, dict]:
        """Score every vendor: banner score, structural score, per-platform
        score and the set of distinct (pattern, line) evidence pairs that
        matched (E03 F1)."""
        lines = content.splitlines()
        scores: dict[str, dict] = {}

        for vendor, spec in self.VENDOR_PATTERNS.items():
            banner = 0.0
            structural = 0.0
            platforms: dict[str, float] = {}
            distinct: set[tuple[str, int]] = set()

            for pattern, _method in spec.get("banner_patterns", []):
                for i, line in enumerate(lines):
                    if re.search(pattern, line, re.IGNORECASE):
                        banner += 3.0
                        distinct.add((pattern, i))

            for platform_name, platform_patterns in spec.get("platforms", {}).items():
                platform_score = 0.0
                for pattern, _method in platform_patterns:
                    for i, line in enumerate(lines):
                        if re.search(pattern, line, re.IGNORECASE):
                            platform_score += 1.0
                            distinct.add((pattern, i))
                platforms[platform_name] = platform_score
                structural += platform_score

            scores[vendor] = {
                "banner": banner,
                "structural": structural,
                "total": banner + structural,
                "platforms": platforms,
                "distinct": distinct,
            }
        return scores

    def _decide(self, scores: dict) -> tuple[str, str, float, Optional[str], Optional[str]]:
        """Apply the evidence hierarchy and eligibility gate to the score map.

        Returns (vendor, platform, confidence, evidence_vendor, evidence_platform).
        evidence_* names the best candidate even when it was too weak to claim
        the file, so reviewers still see what matched.
        """
        top: Optional[str] = None
        for vendor, s in scores.items():
            if top is None or (s["structural"], s["total"]) > (
                scores[top]["structural"], scores[top]["total"]
            ):
                top = vendor
        if top is None:
            return "unknown", "unknown", 0.0, None, None

        ev_platform = self._best_platform(scores[top]["platforms"])

        def eligible(vendor: str) -> bool:
            s = scores[vendor]
            return (
                len(s["distinct"]) >= MIN_EVIDENCE_PATTERNS
                and s["structural"] > 0.0
            )

        strong = [
            v for v in scores
            if eligible(v) and scores[v]["structural"] >= MIXED_VENDOR_STRUCTURAL_FLOOR
        ]
        if len(strong) >= 2:
            ranked = sorted(
                (scores[v]["structural"] for v in strong), reverse=True
            )
            if ranked[1] >= ranked[0] * MIXED_VENDOR_STRUCTURAL_RATIO:
                return "unknown", "unknown", 0.0, top, ev_platform

        if not eligible(top):
            return "unknown", "unknown", 0.0, top, ev_platform

        s = scores[top]
        platform = ev_platform or "unknown"
        return top, platform, self._regex_confidence(s["total"]), top, ev_platform

    @staticmethod
    def _best_platform(platforms: dict[str, float]) -> Optional[str]:
        best_name: Optional[str] = None
        best_score = 0.0
        for name, score in platforms.items():
            if score > best_score:
                best_score = score
                best_name = name
        return best_name

    @staticmethod
    def _regex_confidence(total: float) -> float:
        if total >= 5.0:
            return min(0.95, 0.7 + (total * 0.02))
        if total >= 3.0:
            return min(0.90, 0.6 + (total * 0.02))
        if total >= 1.0:
            return min(0.70, 0.4 + (total * 0.02))
        return 0.0

    def _postprocess_platform(
        self, vendor: str, platform: str, content: str
    ) -> str:
        """Shared ASA correction (both paths) then canonical normalization.

        nameif / security-level are ASA-only syntax, so their presence is the
        marker — no device-type heuristic required (E03 F3: one correction
        order on both paths: raw platform -> ASA correction -> aliases).
        """
        if (
            vendor == "cisco"
            and platform in ("ios", "ios_xe")
            and re.search(r"nameif|security-level\s+\d+", content, re.IGNORECASE)
        ):
            platform = "asa"
        return PLATFORM_ALIASES.get(platform, platform)

    @staticmethod
    def _is_cisco_comment_only(content: str) -> bool:
        """True when every non-blank line is a Cisco '!' comment.

        Syntax-aware on purpose: FortiOS '#' and JUNOS '##' are live syntax
        and are never treated as comments (E03 F7).
        """
        lines = [line for line in content.splitlines() if line.strip()]
        if not lines:
            return False
        return all(line.lstrip().startswith("!") for line in lines)

    def _extract_firmware(self, content: str, vendor: Optional[str]) -> Optional[str]:
        if vendor and vendor in self.VENDOR_PATTERNS:
            firmware = self._extract_firmware_version(
                content, self.VENDOR_PATTERNS[vendor].get("version_patterns", [])
            )
            if firmware is not None:
                return firmware
        all_patterns = [
            pattern
            for spec in self.VENDOR_PATTERNS.values()
            for pattern in spec.get("version_patterns", [])
        ]
        return self._extract_firmware_version(content, all_patterns)

    def _extract_firmware_version(
        self,
        content: str,
        version_patterns: list[str]
    ) -> Optional[str]:
        """Extract firmware version from content"""
        for pattern in version_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    def _collect_evidence(
        self,
        content: str,
        vendor: Optional[str],
        platform: Optional[str]
    ) -> list[DetectionEvidence]:
        """Collect detection evidence"""
        evidence = []

        if not vendor or vendor not in self.VENDOR_PATTERNS:
            return evidence

        vendor_patterns = self.VENDOR_PATTERNS[vendor]
        lines = content.splitlines()

        # Check banner patterns
        for pattern, method in vendor_patterns.get("banner_patterns", []):
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    evidence.append(DetectionEvidence(
                        method=method,
                        pattern=pattern,
                        matched_text=line.strip()[:100],
                        line_number=i,
                    ))

        # Check platform patterns
        if platform and platform in vendor_patterns.get("platforms", {}):
            for pattern, method in vendor_patterns["platforms"][platform]:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        evidence.append(DetectionEvidence(
                            method=method,
                            pattern=pattern,
                            matched_text=line.strip()[:100],
                            line_number=i,
                        ))
                        break  # Only one evidence per pattern

        return evidence[:10]  # Limit evidence to 10 items

    def _detect_device_type(self, content: str) -> str:
        """Detect device type: switch, router, firewall"""
        scores: dict[str, float] = {"switch": 0, "router": 0, "firewall": 0}
        for dtype, patterns in self.DEVICE_TYPE_PATTERNS.items():
            for pattern, _ in patterns:
                for line in content.splitlines():
                    if re.search(pattern, line, re.IGNORECASE):
                        scores[dtype] += 1.0
                        break
        best = max(scores, key=scores.get)
        return best if scores[best] >= 2.0 else "unknown"

    def _extract_hostname(self, content: str) -> Optional[str]:
        """Extract hostname from config"""
        for pattern in [r"^\s*hostname\s+(\S+)", r"^\s*host-name\s+(\S+)", r"^\s*set\s+system\s+host-name\s+(\S+)", r"^\s*set\s+hostname\s+\"?(\S+)\"?"]:
            m = re.search(pattern, content, re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip('"').strip("'").strip(";")
        return None
