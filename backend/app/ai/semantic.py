"""
Semantic Analysis Engine

Analyzes configuration sections, detects unknowns, and queries AI for interpretations.
AI UNDERSTANDS. DETERMINISTIC RULES DECIDE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any

from app.ai.client import AIClient
from app.ai.validators import (
    OutputValidator, AIHypothesis, SemanticSection, SecurityRelevance,
)
from app.ai.prompts import build_hypothesis_prompt, SYSTEM_PROMPT
from app.ai.providers import AIRequest


@dataclass
class UnknownSection:
    """A configuration section that couldn't be parsed deterministically"""
    path: list[str]
    raw_text: str
    line_numbers: list[int]
    ai_hypothesis: Optional[AIHypothesis] = None
    kb_mapping_id: Optional[str] = None
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "raw_text": self.raw_text,
            "line_numbers": self.line_numbers,
            "has_hypothesis": self.ai_hypothesis is not None,
            "hypothesis": self.ai_hypothesis.to_dict() if self.ai_hypothesis else None,
            "kb_mapping_id": self.kb_mapping_id,
        }


@dataclass
class SemanticAnalysis:
    """Result of semantic analysis"""
    known_sections: list[dict]
    unknown_sections: list[UnknownSection]
    interpretations: list[SemanticSection]
    ai_used: bool = False
    ai_errors: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "known_sections": self.known_sections,
            "unknown_sections": [u.to_dict() for u in self.unknown_sections],
            "interpretations": [
                {
                    "path": i.path,
                    "meaning": i.meaning,
                    "security_relevance": i.security_relevance.value,
                    "confidence": i.confidence,
                    "universal_model_path": i.universal_model_path,
                }
                for i in self.interpretations
            ],
            "ai_used": self.ai_used,
            "ai_errors": self.ai_errors,
        }


class SemanticAnalyzer:
    """
    Semantic Analysis Engine
    
    Analyzes configurations to:
    1. Identify known patterns (deterministic)
    2. Detect unknown sections
    3. Query AI for interpretations of unknowns
    4. Return structured results
    
    AI is used ONLY for hypothesis generation, never for compliance decisions.
    """
    
    def __init__(self, ai_client: Optional[AIClient] = None):
        self.ai_client = ai_client
        self.validator = OutputValidator()
    
    async def analyze(
        self,
        parse_result: Any,
        vendor: str,
        platform: str,
        query_ai: bool = True,
        knowledge_base: Any = None,
    ) -> SemanticAnalysis:
        """
        Analyze configuration parse results
        
        Args:
            parse_result: ParseResult from parsing engine
            vendor: Device vendor
            platform: Device platform
            query_ai: Whether to query AI for unknowns
            knowledge_base: Optional knowledge base (E06 F1, spec 9.2
                steps 1-2). Confirmed, trusted mappings resolve unknowns
                without AI; anything else stays unresolved.
            
        Returns:
            SemanticAnalysis with known/unknown sections
        """
        analysis = SemanticAnalysis(
            known_sections=[],
            unknown_sections=[],
            interpretations=[],
        )
        
        # Process parse tree (iterative: safe for deeply nested trees)
        stack: list[tuple[Any, list[str]]] = [
            (node, []) for node in reversed(parse_result.parse_tree)]
        while stack:
            node, path = stack.pop()
            self._process_node(node, path, analysis, vendor, platform)
            current_path = path + [
                f"{node.key}:{node.value}" if node.value else node.key]
            stack.extend(
                (child, current_path) for child in reversed(node.children))
        
        # Process unknown sections from parser
        for unknown in parse_result.unknown_sections:
            unknown_section = UnknownSection(
                path=unknown.path,
                raw_text=unknown.raw_text,
                line_numbers=unknown.line_numbers,
            )
            analysis.unknown_sections.append(unknown_section)
        
        # E06 F1 (spec 9.2 steps 1-2): consult the knowledge base for
        # unknowns before spending AI calls. Only confirmed mappings at or
        # above the trust threshold resolve a section; suggestions and
        # low-confidence rows never become authoritative here.
        if knowledge_base is not None:
            self._apply_kb_mappings(analysis, vendor, platform,
                                    knowledge_base)
        
        # Query AI for unknowns if enabled
        if query_ai and analysis.unknown_sections and self.ai_client:
            await self._query_ai_for_unknowns(analysis, vendor, platform)
        
        return analysis

    def _apply_kb_mappings(
        self,
        analysis: SemanticAnalysis,
        vendor: str,
        platform: str,
        knowledge_base: Any,
    ) -> None:
        """Resolve unknown sections from confirmed, trusted KB mappings."""
        from app.ai import kb_domain as dom

        for unknown in analysis.unknown_sections:
            if unknown.kb_mapping_id is not None:
                continue
            try:
                hit = knowledge_base.lookup(
                    vendor=vendor,
                    platform=platform,
                    raw_syntax=unknown.raw_text,
                    require_confirmed=True,
                )
            except Exception as exc:  # noqa: BLE001 - KB must not break analysis
                analysis.ai_errors.append(
                    f"KB lookup failed for '{unknown.raw_text[:50]}': "
                    f"{type(exc).__name__}")
                continue
            if hit is None:
                continue
            if not dom.is_trusted(admin_confirmed=hit.admin_confirmed,
                                  confidence=hit.confidence):
                continue
            unknown.kb_mapping_id = hit.id
            analysis.interpretations.append(SemanticSection(
                path=".".join(unknown.path),
                meaning=hit.semantic_meaning,
                security_relevance=SecurityRelevance(
                    dom.relevance_for_path(hit.universal_model_path)),
                confidence=hit.confidence,
                universal_model_path=hit.universal_model_path,
                explanation=f"Confirmed knowledge-base mapping {hit.id}",
            ))
    
    def _process_node(
        self,
        node: Any,
        path: list[str],
        analysis: SemanticAnalysis,
        vendor: str,
        platform: str,
    ) -> None:
        """Process a single parse tree node (non-recursive; the caller in
        analyze() drives traversal iteratively so deep trees cannot exhaust
        the stack)."""
        current_path = path + [f"{node.key}:{node.value}" if node.value else node.key]

        # Add to known sections
        analysis.known_sections.append({
            "path": current_path,
            "key": node.key,
            "value": node.value,
            "children_count": len(node.children),
        })
    
    async def _query_ai_for_unknowns(
        self,
        analysis: SemanticAnalysis,
        vendor: str,
        platform: str,
    ) -> None:
        """Query AI for interpretations of unknown sections"""
        for unknown in analysis.unknown_sections:
            if unknown.kb_mapping_id is not None:
                continue  # resolved from the knowledge base; no AI needed
            try:
                hypothesis = await self._generate_hypothesis(
                    raw_syntax=unknown.raw_text,
                    vendor=vendor,
                    platform=platform,
                    section_path=".".join(unknown.path),
                )
                
                if hypothesis:
                    unknown.ai_hypothesis = hypothesis
                    analysis.ai_used = True
                    
                    # Add interpretation
                    analysis.interpretations.append(SemanticSection(
                        path=".".join(unknown.path),
                        meaning=hypothesis.meaning,
                        security_relevance=hypothesis.security_relevance,
                        confidence=hypothesis.confidence,
                        universal_model_path=hypothesis.universal_model_path,
                        explanation=hypothesis.explanation,
                    ))
                    
            except Exception as e:
                analysis.ai_errors.append(f"AI query failed for '{unknown.raw_text[:50]}': {str(e)}")
    
    async def _generate_hypothesis(
        self,
        raw_syntax: str,
        vendor: str,
        platform: str,
        section_path: str = "",
    ) -> Optional[AIHypothesis]:
        """Generate AI hypothesis for unknown syntax"""
        if not self.ai_client:
            return None
        
        prompt = build_hypothesis_prompt(
            raw_syntax=raw_syntax,
            vendor=vendor,
            platform=platform,
            section_path=section_path,
        )
        
        request = AIRequest(
            prompt=prompt,
            system_prompt=SYSTEM_PROMPT,
            model=None,  # Use provider's default model
            temperature=0.3,
            max_tokens=1000,
            response_format="json",
        )
        
        response, error = await self.ai_client.complete(request)
        
        if error or not response:
            return None
        
        # Validate and parse response
        hypothesis = self.validator.validate_hypothesis(response.content, raw_syntax)
        
        if hypothesis:
            # Check for hallucinations
            warnings = self.validator.check_hallucination(hypothesis)
            if warnings:
                # Reduce confidence if hallucination indicators found
                hypothesis.confidence *= 0.8
        
        return hypothesis
    
    async def generate_hypothesis(
        self,
        raw_syntax: str,
        vendor: str,
        platform: str,
        section_path: str = "",
    ) -> dict:
        """
        Generate AI hypothesis for unknown syntax
        
        Public method for use by training API.
        
        Returns:
            Dictionary with meaning, confidence, reasoning, etc.
        """
        hypothesis = await self._generate_hypothesis(
            raw_syntax=raw_syntax,
            vendor=vendor,
            platform=platform,
            section_path=section_path,
        )
        
        if hypothesis:
            return {
                "meaning": hypothesis.meaning,
                "confidence": hypothesis.confidence,
                "reasoning": hypothesis.explanation,
                "universal_model_path": hypothesis.universal_model_path,
                "security_relevance": hypothesis.security_relevance.value,
                "alternatives": [
                    {
                        "meaning": alt.get("meaning", ""),
                        "confidence": alt.get("confidence", 0.0),
                        "reasoning": alt.get("reasoning", ""),
                    }
                    for alt in hypothesis.alternatives
                ] if hypothesis.alternatives else [],
            }
        
        return {
            "meaning": "Unable to determine",
            "confidence": 0.0,
            "reasoning": "AI service unavailable or no hypothesis generated",
            "universal_model_path": None,
            "security_relevance": "unknown",
            "alternatives": [],
        }
    
    def get_confidence_summary(self, analysis: SemanticAnalysis) -> dict:
        """Get confidence summary for analysis"""
        if not analysis.interpretations:
            return {"avg_confidence": 0.0, "count": 0}
        
        confidences = [i.confidence for i in analysis.interpretations]
        return {
            "avg_confidence": sum(confidences) / len(confidences),
            "min_confidence": min(confidences),
            "max_confidence": max(confidences),
            "count": len(confidences),
            "low_confidence_count": sum(1 for c in confidences if c < 0.7),
        }
