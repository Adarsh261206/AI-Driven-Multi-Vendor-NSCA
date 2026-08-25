"""
Adaptive Learning Engine

Orchestrates the AI-assisted adaptive learning workflow:
1. Detect unknown syntax
2. Check Knowledge Base
3. Query AI if not found
4. Present hypothesis to admin
5. Admin confirms/edits/rejects
6. Persist to Knowledge Base
7. Re-analyze configuration

AI UNDERSTANDS. DETERMINISTIC RULES DECIDE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Any
from datetime import datetime

from app.ai.semantic import SemanticAnalyzer, UnknownSection, SemanticAnalysis
from app.ai.knowledge_base import KnowledgeBase, TrainingMapping
from app.ai.client import AIClient
from app.ai.validators import AIHypothesis, SecurityRelevance


@dataclass
class HypothesisRequest:
    """Request for AI hypothesis"""
    raw_syntax: str
    vendor: str
    platform: str
    section_path: str = ""


@dataclass
class HypothesisResponse:
    """Response with AI hypothesis"""
    raw_syntax: str
    hypothesis: Optional[AIHypothesis]
    from_knowledge_base: bool = False
    kb_mapping_id: Optional[str] = None
    ai_errors: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "raw_syntax": self.raw_syntax,
            "hypothesis": self.hypothesis.to_dict() if self.hypothesis else None,
            "from_knowledge_base": self.from_knowledge_base,
            "kb_mapping_id": self.kb_mapping_id,
            "ai_errors": self.ai_errors,
        }


@dataclass
class TrainingResult:
    """Result of admin training"""
    mapping: TrainingMapping
    reanalysis: Optional[SemanticAnalysis] = None
    success: bool = True
    message: str = ""
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "mapping": self.mapping.to_dict(),
            "reanalysis": self.reanalysis.to_dict() if self.reanalysis else None,
            "success": self.success,
            "message": self.message,
        }


class AdaptiveLearningEngine:
    """
    Adaptive Learning Engine
    
    Orchestrates the complete adaptive learning workflow.
    """
    
    def __init__(
        self,
        ai_client: Optional[AIClient] = None,
        knowledge_base: Optional[KnowledgeBase] = None,
    ):
        self.ai_client = ai_client
        self.kb = knowledge_base or KnowledgeBase()
        self.semantic_analyzer = SemanticAnalyzer(ai_client)
    
    async def get_hypothesis(
        self,
        request: HypothesisRequest,
    ) -> HypothesisResponse:
        """
        Get hypothesis for unknown syntax
        
        Workflow:
        1. Check Knowledge Base for existing mapping
        2. If found, return KB mapping
        3. If not found, query AI
        4. Return hypothesis
        """
        # Step 1: Check Knowledge Base
        kb_mapping = self.kb.lookup(
            vendor=request.vendor,
            platform=request.platform,
            raw_syntax=request.raw_syntax,
            require_confirmed=True,
        )
        
        if kb_mapping:
            # Found in KB - convert to hypothesis
            hypothesis = AIHypothesis(
                raw_syntax=kb_mapping.raw_syntax,
                meaning=kb_mapping.semantic_meaning,
                confidence=kb_mapping.confidence,
                reasoning="From confirmed knowledge base mapping",
                security_relevance=SecurityRelevance.MEDIUM,
                universal_model_path=kb_mapping.universal_model_path,
            )
            
            return HypothesisResponse(
                raw_syntax=request.raw_syntax,
                hypothesis=hypothesis,
                from_knowledge_base=True,
                kb_mapping_id=kb_mapping.id,
            )
        
        # Step 2: Query AI
        if not self.ai_client or not self.ai_client.provider.is_available():
            return HypothesisResponse(
                raw_syntax=request.raw_syntax,
                hypothesis=None,
                ai_errors=["AI provider not available"],
            )
        
        hypothesis = await self.semantic_analyzer._generate_hypothesis(
            raw_syntax=request.raw_syntax,
            vendor=request.vendor,
            platform=request.platform,
            section_path=request.section_path,
        )
        
        return HypothesisResponse(
            raw_syntax=request.raw_syntax,
            hypothesis=hypothesis,
            ai_errors=[] if hypothesis else ["Failed to generate hypothesis"],
        )
    
    def confirm_mapping(
        self,
        raw_syntax: str,
        vendor: str,
        platform: str,
        semantic_meaning: str,
        universal_model_path: Optional[str] = None,
        admin_notes: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> TrainingMapping:
        """
        Admin confirms a mapping
        
        Creates or updates the knowledge base entry.
        """
        return self.kb.create(
            vendor=vendor,
            platform=platform,
            raw_syntax=raw_syntax,
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            admin_confirmed=True,
            admin_notes=admin_notes,
            created_by_id=user_id,
        )
    
    def edit_mapping(
        self,
        mapping_id: str,
        semantic_meaning: str,
        universal_model_path: Optional[str] = None,
        admin_notes: Optional[str] = None,
        change_reason: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> TrainingMapping:
        """
        Admin edits an existing mapping
        
        Creates a new version of the mapping.
        """
        return self.kb.update(
            mapping_id=mapping_id,
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            admin_notes=admin_notes,
            change_reason=change_reason,
            changed_by_id=user_id,
        )
    
    def reject_mapping(
        self,
        raw_syntax: str,
        vendor: str,
        platform: str,
        user_id: Optional[str] = None,
    ) -> bool:
        """
        Admin rejects a mapping
        
        Removes any unconfirmed mappings for this syntax.
        """
        mappings = self.kb.list_mappings(
            vendor=vendor,
            platform=platform,
            confirmed_only=False,
        )
        
        rejected = False
        for mapping in mappings:
            if mapping.raw_syntax.strip() == raw_syntax.strip():
                if not mapping.admin_confirmed:
                    del self.kb._mappings[mapping.id]
                    rejected = True
        
        return rejected
    
    async def reanalyze_with_mapping(
        self,
        config_content: str,
        vendor: str,
        platform: str,
        mapping: TrainingMapping,
    ) -> SemanticAnalysis:
        """
        Re-analyze configuration after a mapping is confirmed
        
        Uses the confirmed mapping to interpret previously unknown sections.
        """
        # The re-analysis uses the updated knowledge base
        # When the semantic analyzer encounters the same unknown syntax,
        # it will now find the confirmed mapping in the KB
        from app.engines.parsing.cisco import CiscoIOSParser
        
        parser = CiscoIOSParser()
        parse_result = parser.parse(config_content)
        
        analysis = await self.semantic_analyzer.analyze(
            parse_result=parse_result,
            vendor=vendor,
            platform=platform,
            query_ai=False,  # Don't query AI again, use KB
        )
        
        return analysis
    
    def get_training_mappings(
        self,
        vendor: Optional[str] = None,
        platform: Optional[str] = None,
        confirmed_only: bool = False,
    ) -> list[TrainingMapping]:
        """Get training mappings"""
        return self.kb.list_mappings(
            vendor=vendor,
            platform=platform,
            confirmed_only=confirmed_only,
        )
    
    def get_mapping_versions(self, mapping_id: str) -> list[dict]:
        """Get version history of a mapping"""
        versions = self.kb.get_versions(mapping_id)
        return [v.to_dict() for v in versions]
    
    def get_stats(self) -> dict:
        """Get adaptive learning statistics"""
        kb_stats = self.kb.get_stats()
        
        ai_metrics = {}
        if self.ai_client:
            ai_metrics = self.ai_client.get_metrics()
        
        return {
            "knowledge_base": kb_stats,
            "ai_metrics": ai_metrics,
        }
