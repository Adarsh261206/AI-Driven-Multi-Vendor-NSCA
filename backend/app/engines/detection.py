"""
Vendor Detection Engine

Identifies device vendor, platform, and firmware version from configuration content.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


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
                r"version\s+(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)",
                r"Cisco\s+(?:IOS|NX-OS)\s+Software.*?Version\s+(\S+)",
            ],
        },
        "fortinet": {
            "platforms": {
                "fortios": [
                    (r"^#\s*config\s+(?:system|firewall|router)", DetectionMethod.CONFIG_STRUCTURE),
                    (r"(?:set\s+(?:status|mode|type))", DetectionMethod.COMMAND_SYNTAX),
                    (r"(?:end|next)\s*$", DetectionMethod.CONFIG_STRUCTURE),
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
                    (r"^##", DetectionMethod.CONFIG_STRUCTURE),
                    (r"(?:system\s+\{|interfaces\s+\{|protocols\s+\{)", DetectionMethod.CONFIG_STRUCTURE),
                    (r"(?:set\s+(?:system|interfaces|protocols))", DetectionMethod.COMMAND_SYNTAX),
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
        Detect vendor from configuration content
        
        Uses ML model (TF-IDF + LogisticRegression) if available, fallback to regex.
        
        Args:
            content: Configuration content string
            
        Returns:
            VendorIdentification with detection results
        """
        # === ML path (real model) ===
        try:
            from app.ml.model import get_ml_detector
            ml = get_ml_detector()
            if ml.is_available:
                ml_vendor, ml_platform, ml_device, ml_conf, ml_method = ml.predict(content)
                if ml_conf >= 0.55 and ml_vendor != "unknown":
                    # ML confident — use it, but also gather evidence via regex for explainability
                    firmware_version = self._extract_firmware_version(
                        content,
                        self.VENDOR_PATTERNS.get(ml_vendor, {}).get("version_patterns", [])
                    )
                    hostname = self._extract_hostname(content)
                    # Device type from ML if confident, else regex
                    device_type = ml_device if ml_device != "unknown" else self._detect_device_type(content)
                    # Next-level: Correct platform for Cisco ASA firewall (detected as ios_xe but should be asa)
                    if ml_vendor == "cisco" and device_type == "firewall" and ml_platform == "ios_xe":
                        if re.search(r"nameif|security-level\s+\d+", content, re.IGNORECASE):
                            ml_platform = "asa"
                    evidence = self._collect_evidence(content, ml_vendor, ml_platform)
                    # Add ML evidence marker
                    evidence.insert(0, DetectionEvidence(
                        method=DetectionMethod.PATTERN,
                        pattern="ML model: TF-IDF + LogisticRegression",
                        matched_text=f"ML predicted {ml_vendor}/{ml_platform} ({ml_device}) conf={ml_conf:.2f}",
                        line_number=None,
                    ))
                    return VendorIdentification(
                        vendor=ml_vendor,
                        platform=ml_platform,
                        confidence=min(0.99, ml_conf * 1.05),  # slight boost for ML
                        firmware_version=firmware_version,
                        detection_method=DetectionMethod.PATTERN,
                        detection_evidence=evidence,
                        device_type=device_type,
                        hostname=hostname,
                    )
        except Exception:
            pass  # Fallback to regex

        lines = content.splitlines()
        
        # Track scores for each vendor
        vendor_scores: dict[str, dict[str, float]] = {}
        
        for vendor, patterns in self.VENDOR_PATTERNS.items():
            vendor_scores[vendor] = {"total": 0.0, "platforms": {}}
            
            # Check banner patterns (high confidence)
            for pattern, method in patterns.get("banner_patterns", []):
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        vendor_scores[vendor]["total"] += 3.0
            
            # Check platform patterns
            for platform, platform_patterns in patterns.get("platforms", {}).items():
                platform_score = 0.0
                for pattern, method in platform_patterns:
                    for i, line in enumerate(lines, 1):
                        if re.search(pattern, line, re.IGNORECASE):
                            platform_score += 1.0
                
                vendor_scores[vendor]["platforms"][platform] = platform_score
                vendor_scores[vendor]["total"] += platform_score
        
        # Find best match
        best_vendor = None
        best_platform = None
        best_score = 0.0
        
        for vendor, scores in vendor_scores.items():
            if scores["total"] > best_score:
                best_score = scores["total"]
                best_vendor = vendor
                if scores["platforms"]:
                    best_platform = max(scores["platforms"], key=scores["platforms"].get)
        
        # Calculate confidence (capped at 0.95)
        if best_score >= 5.0:
            confidence = min(0.95, 0.7 + (best_score * 0.02))
        elif best_score >= 3.0:
            confidence = min(0.90, 0.6 + (best_score * 0.02))
        elif best_score >= 1.0:
            confidence = min(0.70, 0.4 + (best_score * 0.02))
        else:
            confidence = 0.0
        
        # Extract firmware version if available
        firmware_version = None
        if best_vendor:
            firmware_version = self._extract_firmware_version(
                content,
                self.VENDOR_PATTERNS[best_vendor].get("version_patterns", [])
            )
        
        # Detect device type (switch/router/firewall)
        device_type = self._detect_device_type(content)
        
        # Extract hostname
        hostname = self._extract_hostname(content)

        # Collect detection evidence
        evidence = self._collect_evidence(content, best_vendor, best_platform)
        
        # Determine detection method
        detection_method = DetectionMethod.KEYWORD
        if evidence:
            detection_method = evidence[0].method
        
        return VendorIdentification(
            vendor=best_vendor or "unknown",
            platform=best_platform or "unknown",
            confidence=confidence,
            firmware_version=firmware_version,
            detection_method=detection_method,
            detection_evidence=evidence,
            device_type=device_type,
            hostname=hostname,
        )
    
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
