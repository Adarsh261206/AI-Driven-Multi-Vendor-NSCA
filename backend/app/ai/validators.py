"""
Structured Output Schema and Validators

Strict schemas for AI responses with validation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum


class SecurityRelevance(str, Enum):
    """Security relevance levels"""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class AlternativeInterpretation:
    """Alternative interpretation of configuration"""
    meaning: str
    confidence: float
    reasoning: str


@dataclass
class AIHypothesis:
    """AI hypothesis for unknown configuration syntax"""
    raw_syntax: str
    meaning: str
    confidence: float
    reasoning: str
    security_relevance: SecurityRelevance
    universal_model_path: Optional[str] = None
    alternatives: list[AlternativeInterpretation] = field(default_factory=list)
    explanation: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_syntax": self.raw_syntax,
            "meaning": self.meaning,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "security_relevance": self.security_relevance.value,
            "universal_model_path": self.universal_model_path,
            "alternatives": [
                {"meaning": a.meaning, "confidence": a.confidence, "reasoning": a.reasoning}
                for a in self.alternatives
            ],
            "explanation": self.explanation,
        }


@dataclass
class SemanticSection:
    """Semantic interpretation of a configuration section"""
    path: str
    meaning: str
    security_relevance: SecurityRelevance
    confidence: float
    universal_model_path: Optional[str] = None
    explanation: str = ""


class OutputValidator:
    """
    Validates AI responses against strict schemas.
    Catches hallucinations, invalid outputs, and dangerous patterns.
    """
    
    # Dangerous patterns that should never appear in AI output
    DANGEROUS_PATTERNS = [
        r"execute\s+command",
        r"run\s+shell",
        r"delete\s+all",
        r"remove\s+firewall",
        r"disable\s+security",
        r"open\s+all\s+ports",
        r"allow\s+all\s+traffic",
        r"password\s*=\s*\S+",
    ]
    
    # Valid universal model paths (prefixes)
    VALID_PATH_PREFIXES = [
        "device",
        "management",
        "authentication",
        "aaa",
        "logging",
        "ntp",
        "access_control",
        "crypto",
        "services",
        "interfaces",
    ]
    
    def validate_hypothesis(self, raw_output: str, raw_syntax: str) -> Optional[AIHypothesis]:
        """
        Validate and parse AI hypothesis response
        
        Returns:
            AIHypothesis if valid, None if invalid
        """
        try:
            # Parse JSON
            data = json.loads(raw_output.strip())
        except json.JSONDecodeError:
            return None
        
        # Validate required fields
        required_fields = ["meaning", "confidence", "reasoning", "security_relevance"]
        for field in required_fields:
            if field not in data:
                return None
        
        # Validate confidence range
        confidence = data.get("confidence", 0)
        if not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            return None
        
        # Validate security relevance
        try:
            sec_rel = SecurityRelevance(data["security_relevance"])
        except (ValueError, KeyError):
            return None
        
        # Check for dangerous patterns
        meaning = data.get("meaning", "")
        reasoning = data.get("reasoning", "")
        full_text = f"{meaning} {reasoning}"
        
        for pattern in self.DANGEROUS_PATTERNS:
            if re.search(pattern, full_text, re.IGNORECASE):
                return None
        
        # Validate universal model path if provided
        model_path = data.get("universal_model_path")
        if model_path and not self._validate_model_path(model_path):
            model_path = None
        
        # Parse alternatives
        alternatives = []
        for alt in data.get("alternatives", []):
            if isinstance(alt, dict) and "meaning" in alt and "confidence" in alt:
                alternatives.append(AlternativeInterpretation(
                    meaning=alt["meaning"],
                    confidence=float(alt["confidence"]),
                    reasoning=alt.get("reasoning", ""),
                ))
        
        return AIHypothesis(
            raw_syntax=raw_syntax,
            meaning=str(data["meaning"]),
            confidence=confidence,
            reasoning=str(data["reasoning"]),
            security_relevance=sec_rel,
            universal_model_path=model_path,
            alternatives=alternatives,
            explanation=str(data.get("explanation", "")),
        )
    
    def validate_semantic_sections(self, raw_output: str) -> list[SemanticSection]:
        """Validate and parse semantic analysis response"""
        try:
            data = json.loads(raw_output.strip())
        except json.JSONDecodeError:
            return []
        
        if not isinstance(data, list):
            return []
        
        sections = []
        for item in data:
            if not isinstance(item, dict):
                continue
            
            required = ["path", "meaning", "security_relevance", "confidence"]
            if not all(f in item for f in required):
                continue
            
            try:
                sec_rel = SecurityRelevance(item["security_relevance"])
            except (ValueError, KeyError):
                continue
            
            confidence = item.get("confidence", 0)
            if not 0 <= confidence <= 1:
                continue
            
            sections.append(SemanticSection(
                path=str(item["path"]),
                meaning=str(item["meaning"]),
                security_relevance=sec_rel,
                confidence=confidence,
                universal_model_path=item.get("universal_model_path"),
                explanation=str(item.get("explanation", "")),
            ))
        
        return sections
    
    def _validate_model_path(self, path: str) -> bool:
        """Validate universal model path against the model itself.

        Delegates to the canonical kb_domain.is_valid_model_path (E06 §25):
        a path is valid only if it names an actual UniversalSecurityModel
        node. Token shape is still enforced.
        """
        if not path:
            return False

        parts = path.split(".")
        if not parts:
            return False

        # Check all parts are alphanumeric/underscore
        for part in parts:
            if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", part):
                return False

        # The model's own path set is the source of truth (no prefixes).
        from app.ai import kb_domain as _kb_domain
        return _kb_domain.is_valid_model_path(path)
    
    def check_hallucination(self, hypothesis: AIHypothesis) -> list[str]:
        """Check for hallucination indicators"""
        warnings = []
        
        # Suspiciously high confidence for unknown syntax
        if hypothesis.confidence > 0.95:
            warnings.append("Suspiciously high confidence for unknown syntax")
        
        # Too short explanation
        if len(hypothesis.explanation) < 20:
            warnings.append("Explanation too short")
        
        # Missing reasoning
        if len(hypothesis.reasoning) < 10:
            warnings.append("Reasoning too brief")
        
        # Generic/placeholder meanings
        generic_meanings = ["unknown", "not sure", "cannot determine", "unclear"]
        if any(g in hypothesis.meaning.lower() for g in generic_meanings):
            warnings.append("Meaning appears generic/placeholder")
        
        return warnings
