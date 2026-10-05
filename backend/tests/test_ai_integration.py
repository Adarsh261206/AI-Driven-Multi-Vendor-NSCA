"""
Unit Tests for AI Integration

Tests the complete adaptive learning workflow:
- AI provider abstraction
- AI client with retry/error handling
- Structured output validation
- Semantic analysis
- Unknown detection
- Knowledge base persistence
- Confidence validation
- Admin training
- Re-analysis after confirmation
"""

import pytest
import asyncio
from app.ai.providers import MockAIProvider, AIRequest, AIError
from app.ai.client import AIClient
from app.ai.validators import OutputValidator, AIHypothesis, SecurityRelevance
from app.ai.prompts import build_hypothesis_prompt, SYSTEM_PROMPT
from app.ai.semantic import SemanticAnalyzer, UnknownSection
from app.ai.knowledge_base import KnowledgeBase, TrainingMapping
from app.ai.adaptive import AdaptiveLearningEngine, HypothesisRequest


class TestMockAIProvider:
    """Tests for Mock AI Provider"""
    
    def setup_method(self):
        self.provider = MockAIProvider()
    
    def test_provider_type(self):
        assert self.provider.get_provider_type().value == "mock"
    
    def test_is_available(self):
        assert self.provider.is_available() is True
    
    def test_set_failure(self):
        self.provider.set_failure(unavailable=True)
        assert self.provider.is_available() is False
    
    def test_reset(self):
        self.provider.set_failure(unavailable=True)
        self.provider.reset()
        assert self.provider.is_available() is True


class TestAIClient:
    """Tests for AI Client"""
    
    def setup_method(self):
        self.provider = MockAIProvider()
        self.client = AIClient(provider=self.provider, max_retries=2)
    
    def test_successful_completion(self):
        async def run():
            request = AIRequest(prompt="test prompt")
            response, error = await self.client.complete(request)
            assert response is not None
            assert error is None
            assert response.content is not None
        
        asyncio.run(run())
    
    def test_retry_on_failure(self):
        async def run():
            self.provider.set_failure(AIError(
                code="TEST_ERROR",
                message="Test failure",
                retryable=True,
            ))
            
            request = AIRequest(prompt="test prompt")
            response, error = await self.client.complete(request)
            
            assert response is None
            assert error is not None
            assert self.provider.call_count == 2  # Initial + 1 retry
        
        asyncio.run(run())
    
    def test_no_retry_when_provider_unavailable(self):
        async def run():
            self.provider.set_failure(AIError(
                code="PROVIDER_UNAVAILABLE",
                message="Provider not available",
                retryable=False,
            ), unavailable=True)
            
            request = AIRequest(prompt="test prompt")
            response, error = await self.client.complete(request)
            
            assert response is None
            assert error is not None
            assert error.code == "PROVIDER_UNAVAILABLE"
            assert self.provider.call_count == 0  # Provider not called when unavailable
        
        asyncio.run(run())
    
    def test_caching(self):
        async def run():
            request = AIRequest(prompt="cached prompt")
            
            response1, _ = await self.client.complete(request)
            response2, _ = await self.client.complete(request)
            
            assert response1 is not None
            assert response2 is not None
            assert response2.cached is True
            assert self.provider.call_count == 1  # Second call from cache
        
        asyncio.run(run())
    
    def test_metrics(self):
        async def run():
            request = AIRequest(prompt="test")
            await self.client.complete(request)
            
            metrics = self.client.get_metrics()
            assert metrics["request_count"] == 1
            assert metrics["provider"] == "mock"
        
        asyncio.run(run())


class TestOutputValidator:
    """Tests for Output Validator"""
    
    def setup_method(self):
        self.validator = OutputValidator()
    
    def test_valid_hypothesis(self):
        raw = '''{
            "meaning": "This enables SSH service",
            "confidence": 0.85,
            "reasoning": "The 'ssh' keyword in system services enables SSH",
            "security_relevance": "high",
            "universal_model_path": "management.ssh.enabled",
            "alternatives": []
        }'''
        
        result = self.validator.validate_hypothesis(raw, "ssh")
        assert result is not None
        assert result.meaning == "This enables SSH service"
        assert result.confidence == 0.85
        assert result.security_relevance == SecurityRelevance.HIGH
    
    def test_invalid_json(self):
        result = self.validator.validate_hypothesis("not json", "test")
        assert result is None
    
    def test_missing_fields(self):
        raw = '{"meaning": "test"}'
        result = self.validator.validate_hypothesis(raw, "test")
        assert result is None
    
    def test_invalid_confidence(self):
        raw = '{"meaning": "test", "confidence": 1.5, "reasoning": "r", "security_relevance": "high"}'
        result = self.validator.validate_hypothesis(raw, "test")
        assert result is None
    
    def test_invalid_security_relevance(self):
        raw = '{"meaning": "test", "confidence": 0.8, "reasoning": "r", "security_relevance": "invalid"}'
        result = self.validator.validate_hypothesis(raw, "test")
        assert result is None
    
    def test_dangerous_pattern(self):
        raw = '''{
            "meaning": "execute command to disable firewall",
            "confidence": 0.9,
            "reasoning": "test",
            "security_relevance": "high"
        }'''
        result = self.validator.validate_hypothesis(raw, "test")
        assert result is None
    
    def test_valid_model_path(self):
        assert self.validator._validate_model_path("management.ssh.enabled") is True
        assert self.validator._validate_model_path("authentication.password_policy.min_length") is True
    
    def test_invalid_model_path(self):
        assert self.validator._validate_model_path("invalid.path") is False
        assert self.validator._validate_model_path("") is False
    
    def test_hallucination_check(self):
        hypothesis = AIHypothesis(
            raw_syntax="test",
            meaning="unknown",
            confidence=0.98,  # Suspiciously high
            reasoning="r",
            security_relevance=SecurityRelevance.HIGH,
            explanation="short",  # Too short
        )
        
        warnings = self.validator.check_hallucination(hypothesis)
        assert len(warnings) > 0


class TestKnowledgeBase:
    """Tests for Knowledge Base.

    E06: a universal model path and an actor are part of the create/update
    contract, and REJECT retains the row instead of deleting it.
    """
    
    def setup_method(self):
        self.kb = KnowledgeBase()
    
    def test_create_mapping(self):
        mapping = self.kb.create(
            vendor="cisco",
            platform="ios",
            raw_syntax="ip ssh version 2",
            semantic_meaning="Enables SSH version 2",
            universal_model_path="management.ssh",
            admin_confirmed=True,
            actor="admin-1",
        )
        
        assert mapping.id is not None
        assert mapping.version == 1
        assert mapping.admin_confirmed is True
    
    def test_create_requires_path_and_actor(self):
        from app.ai.kb_domain import KBValidationError
        
        with pytest.raises(KBValidationError):
            self.kb.create(
                vendor="cisco", platform="ios", raw_syntax="x",
                semantic_meaning="y", actor="admin-1",
            )
        with pytest.raises(KBValidationError):
            self.kb.create(
                vendor="cisco", platform="ios", raw_syntax="x",
                semantic_meaning="y", universal_model_path="management.ssh",
            )
    
    def test_lookup_exact(self):
        self.kb.create(
            vendor="cisco",
            platform="ios",
            raw_syntax="ip ssh version 2",
            semantic_meaning="Enables SSH version 2",
            universal_model_path="management.ssh",
            admin_confirmed=True,
            actor="admin-1",
        )
        
        result = self.kb.lookup("cisco", "ios", "ip ssh version 2")
        assert result is not None
        assert result.semantic_meaning == "Enables SSH version 2"
    
    def test_lookup_not_found(self):
        result = self.kb.lookup("cisco", "ios", "unknown command")
        assert result is None
    
    def test_lookup_is_total(self):
        for hostile in (None, 123, ["cisco"], {"vendor": "cisco"}, object()):
            assert self.kb.lookup(hostile, "ios", "x") is None
    
    def test_lookup_unconfirmed(self):
        self.kb.create(
            vendor="cisco",
            platform="ios",
            raw_syntax="test",
            semantic_meaning="test",
            universal_model_path="management.ssh",
            admin_confirmed=False,
            actor="admin-1",
        )
        
        # Should not return unconfirmed by default
        result = self.kb.lookup("cisco", "ios", "test", require_confirmed=True)
        assert result is None
        
        # Should return when allow unconfirmed
        result = self.kb.lookup("cisco", "ios", "test", require_confirmed=False)
        assert result is not None
    
    def test_update_creates_version(self):
        mapping = self.kb.create(
            vendor="cisco",
            platform="ios",
            raw_syntax="test",
            semantic_meaning="original",
            universal_model_path="management.ssh",
            actor="admin-1",
        )
        
        updated = self.kb.update(
            mapping_id=mapping.id,
            semantic_meaning="updated",
            change_reason="Fixed meaning",
            actor="admin-1",
        )
        
        assert updated.version == 2
        assert updated.semantic_meaning == "updated"
        
        versions = self.kb.get_versions(mapping.id)
        # One post-change record per real mutation: create (v1) and edit (v2).
        assert len(versions) == 2
        assert versions[0].semantic_meaning == "original"
        assert versions[1].semantic_meaning == "updated"
    
    def test_edit_never_confirms(self):
        mapping = self.kb.create(
            vendor="cisco", platform="ios", raw_syntax="neutral",
            semantic_meaning="original", universal_model_path="management.ssh",
            confidence=0.5, admin_confirmed=False, actor="hypothesis-1",
        )
        edited = self.kb.update(
            mapping_id=mapping.id, semantic_meaning="edited",
            change_reason="clarified", actor="admin-1",
        )
        assert edited.admin_confirmed is False
        assert edited.confidence == 0.5
    
    def test_reject_retains_row(self):
        mapping = self.kb.create(
            vendor="cisco", platform="ios", raw_syntax="bad",
            semantic_meaning="wrong", universal_model_path="management.ssh",
            admin_confirmed=True, actor="admin-1",
        )
        rejected = self.kb.reject(mapping.id, actor="admin-1", reason="wrong")
        assert rejected is not None
        assert rejected.admin_confirmed is False
        assert (rejected.admin_notes or "").startswith("REJECTED:")
        assert rejected.version == 2
        assert self.kb.lookup("cisco", "ios", "bad") is None
        assert self.kb.lookup("cisco", "ios", "bad", require_confirmed=False) is not None
    
    def test_list_mappings(self):
        self.kb.create("cisco", "ios", "a", "meaning a", universal_model_path="management.ssh",
                       admin_confirmed=True, actor="admin-1")
        self.kb.create("cisco", "ios", "b", "meaning b", universal_model_path="management.ssh",
                       admin_confirmed=False, actor="admin-1")
        self.kb.create("fortinet", "fortios", "c", "meaning c",
                       universal_model_path="management.ssh", admin_confirmed=True,
                       actor="admin-1")
        
        all_mappings = self.kb.list_mappings()
        assert len(all_mappings) == 3
        
        confirmed = self.kb.list_mappings(confirmed_only=True)
        assert len(confirmed) == 2
        
        cisco = self.kb.list_mappings(vendor="cisco")
        assert len(cisco) == 2
    
    def test_stats(self):
        self.kb.create("cisco", "ios", "a", "a", universal_model_path="management.ssh",
                       admin_confirmed=True, actor="admin-1")
        self.kb.create("cisco", "ios", "b", "b", universal_model_path="management.ssh",
                       admin_confirmed=False, actor="admin-1")
        
        stats = self.kb.get_stats()
        assert stats["total_mappings"] == 2
        assert stats["confirmed_mappings"] == 1
        assert "cisco" in stats["vendors"]


class TestAdaptiveLearning:
    """Tests for Adaptive Learning Engine"""
    
    def setup_method(self):
        self.provider = MockAIProvider()
        self.ai_client = AIClient(provider=self.provider)
        self.kb = KnowledgeBase()
        self.engine = AdaptiveLearningEngine(
            ai_client=self.ai_client,
            knowledge_base=self.kb,
        )
    
    def test_confirm_mapping(self):
        mapping = self.engine.confirm_mapping(
            raw_syntax="some vendor command",
            vendor="cisco",
            platform="ios",
            semantic_meaning="This is a test command",
            universal_model_path="management.ssh",
            user_id="admin-1",
        )
        
        assert mapping.admin_confirmed is True
        assert mapping.confidence == 1.0
        
        # Should be findable in KB
        found = self.kb.lookup("cisco", "ios", "some vendor command")
        assert found is not None
    
    def test_edit_mapping(self):
        mapping = self.engine.confirm_mapping(
            raw_syntax="test",
            vendor="cisco",
            platform="ios",
            semantic_meaning="original",
            universal_model_path="management.ssh",
            user_id="admin-1",
        )
        
        updated = self.engine.edit_mapping(
            mapping_id=mapping.id,
            semantic_meaning="updated",
            change_reason="Fixed",
            user_id="admin-1",
        )
        
        assert updated.version == 2
        assert updated.semantic_meaning == "updated"
        assert updated.admin_confirmed is True
    
    def test_reject_unconfirmed_mapping(self):
        # Create an unconfirmed mapping first
        self.kb.create(
            vendor="cisco",
            platform="ios",
            raw_syntax="unconfirmed-cmd",
            semantic_meaning="unconfirmed",
            universal_model_path="management.ssh",
            admin_confirmed=False,
            actor="hypothesis-1",
        )
        
        # Reject should work for unconfirmed
        rejected = self.engine.reject_mapping(
            raw_syntax="unconfirmed-cmd",
            vendor="cisco",
            platform="ios",
            user_id="admin-1",
            reason="wrong",
        )
        
        assert rejected is True
        # E06: the row is retained, unconfirmed, with a REJECTED note.
        row = self.kb.lookup("cisco", "ios", "unconfirmed-cmd", require_confirmed=False)
        assert row is not None
        assert row.admin_confirmed is False
        assert (row.admin_notes or "").startswith("REJECTED:")
        # Rejected knowledge is never auto-reused.
        assert self.kb.lookup("cisco", "ios", "unconfirmed-cmd") is None
    
    def test_reject_confirmed_mapping_unconfirms_it(self):
        # An explicit REJECT is always allowed - including for a previously
        # confirmed row - and downgrades it to unconfirmed.
        self.engine.confirm_mapping(
            raw_syntax="confirmed-cmd",
            vendor="cisco",
            platform="ios",
            semantic_meaning="confirmed",
            universal_model_path="management.ssh",
            user_id="admin-1",
        )
        
        rejected = self.engine.reject_mapping(
            raw_syntax="confirmed-cmd",
            vendor="cisco",
            platform="ios",
            user_id="admin-2",
            reason="misleading",
        )
        
        assert rejected is True
        assert self.kb.lookup("cisco", "ios", "confirmed-cmd") is None
        row = self.kb.lookup("cisco", "ios", "confirmed-cmd", require_confirmed=False)
        assert row is not None and row.admin_confirmed is False
    
    def test_reject_unknown_syntax_is_false(self):
        assert self.engine.reject_mapping(
            raw_syntax="never-seen", vendor="cisco", platform="ios",
            user_id="admin-1",
        ) is False
    
    def test_get_hypothesis_from_kb(self):
        # Add to KB first
        self.engine.confirm_mapping(
            raw_syntax="ip http server",
            vendor="cisco",
            platform="ios",
            semantic_meaning="Enables HTTP server",
            universal_model_path="management.http",
            user_id="admin-1",
        )
        
        async def run():
            request = HypothesisRequest(
                raw_syntax="ip http server",
                vendor="cisco",
                platform="ios",
            )
            
            response = await self.engine.get_hypothesis(request)
            assert response.from_knowledge_base is True
            assert response.hypothesis is not None
            assert response.hypothesis.meaning == "Enables HTTP server"
        
        asyncio.run(run())
    
    def test_get_hypothesis_from_ai(self):
        async def run():
            request = HypothesisRequest(
                raw_syntax="unknown vendor command",
                vendor="cisco",
                platform="ios",
            )
            
            response = await self.engine.get_hypothesis(request)
            assert response.from_knowledge_base is False
            # Will get mock response
        
        asyncio.run(run())
    
    def test_stats(self):
        self.engine.confirm_mapping("a", "cisco", "ios", "a",
                                    universal_model_path="management.ssh", user_id="admin-1")
        self.engine.confirm_mapping("b", "cisco", "ios", "b",
                                    universal_model_path="management.ssh", user_id="admin-1")
        
        stats = self.engine.get_stats()
        assert stats["knowledge_base"]["total_mappings"] == 2


class TestEndToEndAdaptiveWorkflow:
    """End-to-end test of the adaptive learning workflow"""
    
    def setup_method(self):
        self.provider = MockAIProvider()
        self.ai_client = AIClient(provider=self.provider)
        self.kb = KnowledgeBase()
        self.engine = AdaptiveLearningEngine(
            ai_client=self.ai_client,
            knowledge_base=self.kb,
        )
    
    def test_full_workflow(self):
        """Test: UNKNOWN → AI HYPOTHESIS → ADMIN CONFIRM → KB UPDATE → RE-ANALYSIS"""
        
        # Step 1: Unknown syntax detected
        unknown_syntax = "some-unknown-vendor-command value1 value2"
        
        # Step 2: Check KB (not found)
        found = self.kb.lookup("cisco", "ios", unknown_syntax)
        assert found is None
        
        # Step 3: Get AI hypothesis (mock)
        async def run():
            request = HypothesisRequest(
                raw_syntax=unknown_syntax,
                vendor="cisco",
                platform="ios",
            )
            response = await self.engine.get_hypothesis(request)
            return response
        
        response = asyncio.run(run())
        assert response.from_knowledge_base is False
        
        # Step 4: Admin confirms mapping
        mapping = self.engine.confirm_mapping(
            raw_syntax=unknown_syntax,
            vendor="cisco",
            platform="ios",
            semantic_meaning="This command configures a test feature",
            universal_model_path="management.vty",
            admin_notes="Confirmed by admin after review",
            user_id="admin-1",
        )
        
        assert mapping.admin_confirmed is True
        
        # Step 5: Now KB has the mapping
        found = self.kb.lookup("cisco", "ios", unknown_syntax)
        assert found is not None
        assert found.semantic_meaning == "This command configures a test feature"
        
        # Step 6: Future queries use KB
        async def run2():
            request = HypothesisRequest(
                raw_syntax=unknown_syntax,
                vendor="cisco",
                platform="ios",
            )
            return await self.engine.get_hypothesis(request)
        
        response2 = asyncio.run(run2())
        assert response2.from_knowledge_base is True
        assert response2.kb_mapping_id == mapping.id
        
        print("✓ Full adaptive workflow completed successfully")
