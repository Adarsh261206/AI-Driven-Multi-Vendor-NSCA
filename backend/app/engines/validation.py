"""
Configuration Validation Engine

Validates configuration content for structural integrity and security concerns.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from enum import Enum


class ValidationSeverity(str, Enum):
    """Severity of validation issues"""
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class ValidationIssue:
    """Single validation issue"""
    severity: ValidationSeverity
    code: str
    message: str
    line_number: Optional[int] = None
    column: Optional[int] = None


@dataclass
class ValidationResult:
    """Result of configuration validation"""
    is_valid: bool
    issues: list[ValidationIssue] = field(default_factory=list)
    warnings: list[ValidationIssue] = field(default_factory=list)
    info: list[ValidationIssue] = field(default_factory=list)
    
    @property
    def error_count(self) -> int:
        return len([i for i in self.issues if i.severity == ValidationSeverity.ERROR])
    
    @property
    def warning_count(self) -> int:
        return len([i for i in self.issues if i.severity == ValidationSeverity.WARNING])
    
    def add_error(self, code: str, message: str, line_number: Optional[int] = None) -> None:
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.ERROR,
            code=code,
            message=message,
            line_number=line_number,
        ))
        self.is_valid = False
    
    def add_warning(self, code: str, message: str, line_number: Optional[int] = None) -> None:
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.WARNING,
            code=code,
            message=message,
            line_number=line_number,
        ))
    
    def add_info(self, code: str, message: str, line_number: Optional[int] = None) -> None:
        self.issues.append(ValidationIssue(
            severity=ValidationSeverity.INFO,
            code=code,
            message=message,
            line_number=line_number,
        ))


class ConfigurationValidator:
    """
    Configuration Content Validator
    
    Validates:
    - Content structure
    - Encoding issues
    - Potential security concerns
    - Syntax patterns
    """
    
    # Patterns that may indicate sensitive data
    SENSITIVE_PATTERNS = [
        (r'(?:password|passwd|pwd)\s*[=:]\s*\S+', "Potential plaintext password"),
        (r'(?:community|community-string)\s+\S+', "Potential SNMP community string"),
        (r'(?:secret|enable\s+secret)\s+\S+', "Potential enable secret"),
        (r'(?:key|key-chain)\s+\S+\s+\S+', "Potential cryptographic key"),
        (r'(?:username|user)\s+\S+\s+\S+\s+\S+', "Potential user credentials"),
    ]
    
    # Patterns that may indicate insecure configurations
    INSECURE_PATTERNS = [
        (r'(?:transport\s+input\s+telnet)', "Telnet transport enabled (insecure)"),
        (r'(?:ip\s+http\s+server)', "HTTP server enabled (insecure)"),
        (r'(?:snmp-server\s+community\s+(?:public|private))', "Default SNMP community string"),
    ]
    
    def validate(
        self,
        content: str,
        vendor_hint: Optional[str] = None,
        check_sensitive: bool = True,
        check_insecure: bool = True,
    ) -> ValidationResult:
        """
        Validate configuration content
        
        Args:
            content: Configuration content string
            vendor_hint: Optional vendor hint for vendor-specific validation
            check_sensitive: Check for sensitive data patterns
            check_insecure: Check for insecure configuration patterns
            
        Returns:
            ValidationResult with all issues found
        """
        result = ValidationResult(is_valid=True)
        
        # Check for empty content first
        if not content.strip():
            result.add_warning("EMPTY_CONTENT", "Configuration file is empty")
            return result
        
        # Check for binary content indicators
        if self._has_binary_content(content):
            result.add_error("BINARY_CONTENT", "File appears to contain binary data")
            return result
        
        # Check for mixed line endings (before splitting)
        if self._has_mixed_line_endings(content):
            result.add_info("MIXED_LINE_ENDINGS", "Mixed line endings detected")
        
        lines = content.splitlines()
        
        # Basic structure validation
        self._validate_structure(lines, result)
        
        # Check for sensitive data
        if check_sensitive:
            self._check_sensitive_patterns(lines, result)
        
        # Check for insecure configurations
        if check_insecure:
            self._check_insecure_patterns(lines, result)
        
        return result
    
    def _validate_structure(self, lines: list[str], result: ValidationResult) -> None:
        """Validate basic configuration structure"""
        for i, line in enumerate(lines, 1):
            # Check for null bytes
            if '\x00' in line:
                result.add_error(
                    "NULL_BYTE",
                    f"Null byte detected on line {i}",
                    line_number=i,
                )
            
            # Check for extremely long lines
            if len(line) > 10000:
                result.add_warning(
                    "LONG_LINE",
                    f"Line {i} is extremely long ({len(line)} characters)",
                    line_number=i,
                )
    
    def _check_sensitive_patterns(self, lines: list[str], result: ValidationResult) -> None:
        """Check for patterns that may contain sensitive data"""
        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('#'):
                continue
            
            for pattern, message in self.SENSITIVE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    result.add_warning(
                        "SENSITIVE_DATA",
                        f"{message} on line {i}",
                        line_number=i,
                    )
    
    def _check_insecure_patterns(self, lines: list[str], result: ValidationResult) -> None:
        """Check for patterns indicating insecure configurations"""
        for i, line in enumerate(lines, 1):
            # Skip comments
            stripped = line.strip()
            if stripped.startswith('!') or stripped.startswith('#'):
                continue
            
            for pattern, message in self.INSECURE_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    result.add_warning(
                        "INSECURE_CONFIG",
                        f"{message} on line {i}",
                        line_number=i,
                    )
    
    def _has_binary_content(self, content: str) -> bool:
        """Check if content appears to be binary"""
        # Check for null bytes
        if '\x00' in content:
            return True
        
        # Check for high percentage of non-printable characters
        non_printable = sum(1 for c in content if not c.isprintable() and c not in '\n\r\t')
        if len(content) > 0 and (non_printable / len(content)) > 0.1:
            return True
        
        return False
    
    def _has_mixed_line_endings(self, content: str) -> bool:
        """Check if content has mixed line endings (\\r\\n and \\n)"""
        has_crlf = '\r\n' in content
        # Check for lone \n (not preceded by \r)
        has_lf = False
        for i, c in enumerate(content):
            if c == '\n' and (i == 0 or content[i-1] != '\r'):
                has_lf = True
                break
        return has_crlf and has_lf
