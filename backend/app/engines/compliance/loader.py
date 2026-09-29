"""
Control Definition Loader

DEPRECATED — retired legacy loader (F10). Loads the 10-control legacy
inventory; the canonical path loads the 196-control registry from
app.benchmarks instead. Retained only so existing unit tests keep
importing; no production code in the audit path uses it.

Loads compliance controls from Python definitions.
Supports filtering by framework, vendor, platform, category, and severity.
"""

from __future__ import annotations

from typing import Optional

from app.engines.compliance.models import Control, Framework, Severity
from app.engines.compliance.cisco_controls import get_cisco_ios_controls


class ControlLoader:
    """
    Control Definition Loader
    
    Loads and manages compliance controls from Python definitions.
    """
    
    def __init__(self):
        self._controls: dict[str, Control] = {}
        self._frameworks: dict[str, Framework] = {}
        self._load_controls()
    
    def _load_controls(self) -> None:
        """Load all control definitions"""
        # Load Cisco IOS controls
        cisco_controls = get_cisco_ios_controls()
        for control in cisco_controls:
            self._controls[control.id] = control
        
        # Build frameworks
        self._build_frameworks()
    
    def _build_frameworks(self) -> None:
        """Build framework registry from loaded controls"""
        frameworks: dict[str, dict] = {}
        
        for control in self._controls.values():
            fw_id = control.framework
            if fw_id not in frameworks:
                frameworks[fw_id] = {
                    "id": fw_id,
                    "name": f"{fw_id} Security Benchmark",
                    "description": f"{fw_id} compliance framework",
                    "versions": set(),
                    "controls": [],
                }
            
            fw = frameworks[fw_id]
            fw["versions"].add(control.framework_version)
            fw["controls"].append(control)
        
        # Convert to Framework objects
        for fw_id, fw_data in frameworks.items():
            versions = sorted(fw_data["versions"])
            self._frameworks[fw_id] = Framework(
                id=fw_id,
                name=fw_data["name"],
                description=fw_data["description"],
                versions=versions,
                current_version=versions[-1] if versions else "unknown",
                controls=fw_data["controls"],
            )
    
    def get_control(self, control_id: str) -> Optional[Control]:
        """Get a specific control by ID"""
        return self._controls.get(control_id)
    
    def get_all_controls(self) -> list[Control]:
        """Get all controls"""
        return list(self._controls.values())
    
    def get_controls(
        self,
        framework: Optional[str] = None,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        category: Optional[str] = None,
        severity: Optional[Severity] = None,
    ) -> list[Control]:
        """Get controls with optional filters"""
        results = list(self._controls.values())
        
        if framework:
            results = [c for c in results if c.framework == framework]
        if vendor:
            results = [c for c in results if c.vendor == vendor or c.vendor is None]
        if platform:
            results = [c for c in results if c.platform == platform or c.platform is None]
        if category:
            results = [c for c in results if c.category == category]
        if severity:
            results = [c for c in results if c.severity == severity]
        
        return results
    
    def get_framework(self, framework_id: str) -> Optional[Framework]:
        """Get a specific framework"""
        return self._frameworks.get(framework_id)
    
    def get_all_frameworks(self) -> list[Framework]:
        """Get all frameworks"""
        return list(self._frameworks.values())
    
    def get_categories(self, framework: Optional[str] = None) -> list[str]:
        """Get unique categories across controls"""
        controls = self.get_controls(framework=framework)
        return sorted(set(c.category for c in controls))
    
    def get_stats(self) -> dict:
        """Get control statistics"""
        by_framework: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        by_category: dict[str, int] = {}
        
        for control in self._controls.values():
            by_framework[control.framework] = by_framework.get(control.framework, 0) + 1
            by_severity[control.severity.value] = by_severity.get(control.severity.value, 0) + 1
            by_category[control.category] = by_category.get(control.category, 0) + 1
        
        return {
            "total": len(self._controls),
            "by_framework": by_framework,
            "by_severity": by_severity,
            "by_category": by_category,
        }
