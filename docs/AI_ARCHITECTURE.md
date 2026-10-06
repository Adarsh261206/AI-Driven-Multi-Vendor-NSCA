# AI ARCHITECTURE DOCUMENT

## AI-Driven Multi-Vendor Network Security Compliance Auditor

**Version:** 1.0
**Last Updated:** 2026-08-25
**Status:** Design Phase

---

## Table of Contents

1. [AI Architecture Overview](#1-ai-architecture-overview)
2. [AI Usage Principles](#2-ai-usage-principles)
3. [AI Components](#3-ai-components)
4. [Semantic Analysis Engine](#4-semantic-analysis-engine)
5. [Adaptive Learning Engine](#5-adaptive-learning-engine)
6. [AI Safety Measures](#6-ai-safety-measures)
7. [Prompt Engineering](#7-prompt-engineering)
8. [Model Selection](#8-model-selection)
9. [Integration Architecture](#9-integration-architecture)
10. [Performance Optimization](#10-performance-optimization)
11. [Cost Management](#11-cost-management)
12. [Monitoring and Observability](#12-monitoring-and-observability)

---

## 1. AI Architecture Overview

### 1.1 AI Role in the System

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AI ROLE BOUNDARIES                                │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    AI HANDLES                                    │    │
│  │  • Semantic interpretation of unknown syntax                    │    │
│  │  • Natural language explanation generation                      │    │
│  │  • Confidence estimation for interpretations                    │    │
│  │  • Remediation explanation and guidance                         │    │
│  │  • Vendor detection assistance                                  │    │
│  │  • Configuration meaning inference                              │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                DETERMINISTIC ENGINE HANDLES                      │    │
│  │  • Compliance pass/fail decisions                               │    │
│  │  • Severity classification                                      │    │
│  │  • Risk score calculation                                       │    │
│  │  • Evidence chain validation                                    │    │
│  │  • Control rule evaluation                                      │    │
│  │  • Compliance score calculation                                 │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.2 Design Principle

**"AI UNDERSTANDS. DETERMINISTIC RULES DECIDE."**

| AI Assists | Rules Decide |
|------------|--------------|
| Interpret unknown syntax | Whether configuration complies |
| Explain why something matters | Severity of findings |
| Suggest remediation steps | Risk score calculation |
| Estimate confidence | Compliance pass/fail |
| Generate natural language | Evidence chain validation |

### 1.3 AI Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AI ARCHITECTURE                                   │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐                                                         │
│  │   Input     │  Configuration syntax, context, vendor info            │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Prompt     │  Construct structured prompts                         │
│  │  Builder    │                                                         │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │   AI API    │  OpenAI GPT-4 / Alternative                          │
│  │   Client    │                                                         │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Response   │  Parse, validate, extract structured data             │
│  │  Parser     │                                                         │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Validator  │  Validate against schema, confidence check            │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │   Output    │  Structured interpretation with confidence            │
│  └─────────────┘                                                         │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. AI Usage Principles

### 2.1 When to Use AI

| Use Case | AI Necessity | Rationale |
|----------|--------------|-----------|
| Unknown vendor syntax | **Required** | No deterministic parser exists |
| Semantic interpretation | **Recommended** | AI excels at natural language understanding |
| Confidence estimation | **Recommended** | AI can assess uncertainty |
| Explanation generation | **Recommended** | AI generates human-readable text |
| Vendor detection | **Optional** | Pattern matching may suffice |
| Compliance evaluation | **Never** | Must be deterministic |

### 2.2 When NOT to Use AI

| Use Case | Reason | Alternative |
|----------|--------|-------------|
| Compliance decisions | Must be auditable | Deterministic rules |
| Severity assignment | Must be consistent | Rule-based classification |
| Risk calculation | Must be reproducible | Mathematical formula |
| Evidence validation | Must be verifiable | Deterministic checks |
| Score calculation | Must be deterministic | Arithmetic operations |

### 2.3 AI Confidence Thresholds

| Confidence | Action | Description |
|------------|--------|-------------|
| 0.9 - 1.0 | **High Trust** | AI output used directly |
| 0.7 - 0.9 | **Medium Trust** | AI output used with REVIEW flag |
| 0.5 - 0.7 | **Low Trust** | AI output requires admin confirmation |
| 0.0 - 0.5 | **No Trust** | AI output rejected, manual review required |

---

## 3. AI Components

### 3.1 AI Module Structure

```
backend/app/ai/
├── __init__.py
├── client.py           # API client for AI models
├── prompts.py          # Prompt templates
├── parsers.py          # Response parsers
├── validators.py       # Output validators
├── semantic.py         # Semantic analysis engine
├── adaptive.py         # Adaptive learning engine
├── confidence.py       # Confidence estimation
└── cache.py            # Response caching
```

### 3.2 Component Responsibilities

| Component | Responsibility |
|-----------|---------------|
| `client.py` | API communication, retry logic, rate limiting |
| `prompts.py` | Prompt construction, template management |
| `parsers.py` | Response parsing, structured extraction |
| `validators.py` | Output validation, schema checking |
| `semantic.py` | Semantic interpretation of configurations |
| `adaptive.py` | Adaptive learning from admin feedback |
| `confidence.py` | Confidence score calculation |
| `cache.py` | Response caching, deduplication |

---

## 4. Semantic Analysis Engine

### 4.1 Semantic Analysis Process

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    SEMANTIC ANALYSIS WORKFLOW                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐                                                         │
│  │  Parse      │  Extract configuration sections                       │
│  │  Tree       │                                                         │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Identify   │  Recognize known patterns                             │
│  │  Known      │                                                         │
│  └──────┬──────┘                                                         │
│         │                                                                │
│    ┌────┴────┐                                                           │
│    │         │                                                           │
│  Known    Unknown                                                        │
│    │         │                                                           │
│    │         ↓                                                           │
│    │    ┌─────────────┐                                                  │
│    │    │  Check      │  Look up in knowledge base                     │
│    │    │  KB         │                                                  │
│    │    └──────┬──────┘                                                  │
│    │           │                                                         │
│    │      ┌────┴────┐                                                    │
│    │      │         │                                                    │
│    │    Found     Not Found                                              │
│    │      │         │                                                    │
│    │      │         ↓                                                    │
│    │      │    ┌─────────────┐                                           │
│    │      │    │  AI Query   │  Generate hypothesis                     │
│    │      │    └──────┬──────┘                                           │
│    │      │           │                                                  │
│    │      │           ↓                                                  │
│    │      │    ┌─────────────┐                                           │
│    │      │    │  Generate   │  Create interpretation                   │
│    │      │    │  Hypothesis │                                           │
│    │      │    └──────┬──────┘                                           │
│    │      │           │                                                  │
│    └──────┴───────────┤                                                  │
│                       │                                                  │
│                       ↓                                                  │
│              ┌─────────────┐                                             │
│              │  Semantic   │                                             │
│              │  Result     │                                             │
│              └─────────────┘                                             │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.2 Semantic Analysis Implementation

```python
class SemanticAnalyzer:
    """AI-powered semantic analysis engine"""
    
    def __init__(self, ai_client: AIClient, knowledge_base: KnowledgeBase):
        self.ai_client = ai_client
        self.knowledge_base = knowledge_base
    
    async def analyze(
        self,
        parsed_config: ParsedConfiguration,
        unknown_sections: List[UnknownSection]
    ) -> SemanticInterpretation:
        """Analyze configuration semantics"""
        
        semantic_sections = []
        unknown_meanings = []
        
        # Process each unknown section
        for section in unknown_sections:
            # Check knowledge base first
            kb_mapping = await self.knowledge_base.lookup(
                vendor=parsed_config.vendor,
                platform=parsed_config.platform,
                raw_syntax=section.raw_text
            )
            
            if kb_mapping:
                # Use knowledge base mapping
                semantic_sections.append(SemanticSection(
                    path=section.path,
                    meaning=kb_mapping.semantic_meaning,
                    security_relevance=self._assess_relevance(kb_mapping),
                    confidence=kb_mapping.confidence,
                    explanation=kb_mapping.admin_notes or "From knowledge base",
                    universal_model_path=kb_mapping.universal_model_path
                ))
            else:
                # Query AI for hypothesis
                hypothesis = await self._generate_hypothesis(
                    raw_syntax=section.raw_text,
                    vendor=parsed_config.vendor,
                    platform=parsed_config.platform,
                    context=self._get_context(parsed_config, section)
                )
                
                unknown_meanings.append(UnknownMeaning(
                    raw_syntax=section.raw_text,
                    hypothesis=hypothesis,
                    requires_admin_review=True
                ))
        
        # Calculate confidence scores
        confidence_scores = self._calculate_confidence_scores(
            semantic_sections,
            unknown_meanings
        )
        
        return SemanticInterpretation(
            parsed_configuration_id=parsed_config.id,
            semantic_sections=semantic_sections,
            confidence_scores=confidence_scores,
            unknown_meanings=unknown_meanings
        )
    
    async def _generate_hypothesis(
        self,
        raw_syntax: str,
        vendor: str,
        platform: str,
        context: str
    ) -> AIHypothesis:
        """Generate AI hypothesis for unknown syntax"""
        
        prompt = self._build_hypothesis_prompt(
            raw_syntax=raw_syntax,
            vendor=vendor,
            platform=platform,
            context=context
        )
        
        response = await self.ai_client.query(prompt)
        
        return self._parse_hypothesis_response(response)
    
    def _build_hypothesis_prompt(
        self,
        raw_syntax: str,
        vendor: str,
        platform: str,
        context: str
    ) -> str:
        """Build prompt for hypothesis generation"""
        
        return f"""You are a network security configuration analyst.

Analyze the following unknown network device configuration syntax:

Vendor: {vendor}
Platform: {platform}
Configuration syntax: {raw_syntax}

Context (surrounding configuration):
{context}

Provide your analysis in the following JSON format:
{{
    "meaning": "What this configuration does (semantic interpretation)",
    "security_relevance": "high/medium/low/none",
    "confidence": 0.0-1.0,
    "reasoning": "Why you think this is the meaning",
    "universal_model_path": "Suggested path in universal security model (e.g., management.ssh.enabled)",
    "alternatives": [
        {{
            "meaning": "Alternative interpretation",
            "confidence": 0.0-1.0,
            "reasoning": "Why this could be correct"
        }}
    ],
    "explanation": "Human-readable explanation of what this configuration means"
}}

Be conservative. If uncertain, state uncertainty clearly. Do not guess if you don't know."""
```

### 4.3 Semantic Analysis Output

```python
class SemanticSection(BaseModel):
    """Semantic interpretation of a configuration section"""
    path: List[str]
    meaning: str
    security_relevance: str  # "high", "medium", "low", "none"
    confidence: float
    explanation: str
    universal_model_path: Optional[str]

class UnknownMeaning(BaseModel):
    """Unknown configuration meaning requiring review"""
    raw_syntax: str
    hypothesis: AIHypothesis
    requires_admin_review: bool
    admin_confirmed: Optional[bool] = None
    admin_notes: Optional[str] = None
```

---

## 5. Adaptive Learning Engine

### 5.1 Adaptive Learning Process

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    ADAPTIVE LEARNING WORKFLOW                            │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────┐                                                         │
│  │  Unknown    │  Parser encounters unrecognized syntax                  │
│  │  Detected   │                                                         │
│  └──────┬──────┘                                                         │
│         │                                                                │
│         ↓                                                                │
│  ┌─────────────┐                                                         │
│  │  Check KB   │  Look up in knowledge base                            │
│  └──────┬──────┘                                                         │
│         │                                                                │
│    ┌────┴────┐                                                           │
│    │         │                                                           │
│  Found     Not Found                                                     │
│    │         │                                                           │
│    │         ↓                                                           │
│    │    ┌─────────────┐                                                  │
│    │    │  AI Query   │  Generate hypothesis                            │
│    │    └──────┬──────┘                                                  │
│    │           │                                                         │
│    │           ↓                                                         │
│    │    ┌─────────────┐                                                  │
│    │    │  Present    │  Show to administrator                          │
│    │    │  to Admin   │                                                  │
│    │    └──────┬──────┘                                                  │
│    │           │                                                         │
│    │    ┌──────┴──────┐                                                  │
│    │    │      │      │                                                  │
│    │    ↓      ↓      ↓                                                  │
│    │  Confirm Edit  Reject                                              │
│    │    │      │      │                                                  │
│    │    ↓      ↓      ↓                                                  │
│    │    └──────┼──────┘                                                  │
│    │           │                                                         │
│    │           ↓                                                         │
│    │    ┌─────────────┐                                                  │
│    │    │  Store      │  Save mapping (versioned)                       │
│    │    │  Mapping    │                                                  │
│    │    └──────┬──────┘                                                  │
│    │           │                                                         │
│    └─────┬─────┘                                                         │
│          │                                                               │
│          ↓                                                               │
│    ┌─────────────┐                                                       │
│    │  Re-Analyze │  Re-run normalization with new mapping               │
│    └──────┬──────┘                                                       │
│           │                                                              │
│           ↓                                                              │
│    ┌─────────────┐                                                       │
│    │  Updated    │  Show improved understanding                         │
│    │  Results    │                                                       │
│    └─────────────┘                                                       │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

### 5.2 Adaptive Learning Implementation

```python
class AdaptiveLearningEngine:
    """Human-in-the-loop adaptive learning"""
    
    def __init__(
        self,
        knowledge_base: KnowledgeBase,
        semantic_analyzer: SemanticAnalyzer,
        normalizer: Normalizer
    ):
        self.knowledge_base = knowledge_base
        self.semantic_analyzer = semantic_analyzer
        self.normalizer = normalizer
    
    async def process_unknown(
        self,
        unknown_section: UnknownSection,
        vendor: str,
        platform: str
    ) -> TrainingResult:
        """Process unknown configuration with adaptive learning"""
        
        # 1. Check knowledge base
        existing_mapping = await self.knowledge_base.lookup(
            vendor=vendor,
            platform=platform,
            raw_syntax=unknown_section.raw_text
        )
        
        if existing_mapping:
            return TrainingResult(
                status="found",
                mapping=existing_mapping,
                requires_review=False
            )
        
        # 2. Generate AI hypothesis
        hypothesis = await self.semantic_analyzer._generate_hypothesis(
            raw_syntax=unknown_section.raw_text,
            vendor=vendor,
            platform=platform,
            context=self._get_context(unknown_section)
        )
        
        # 3. Present to administrator
        training_request = TrainingRequest(
            raw_syntax=unknown_section.raw_text,
            vendor=vendor,
            platform=platform,
            hypothesis=hypothesis,
            alternatives=hypothesis.alternatives
        )
        
        return TrainingResult(
            status="requires_review",
            training_request=training_request,
            requires_review=True
        )
    
    async def confirm_mapping(
        self,
        training_request_id: str,
        admin_id: str,
        confirmed_meaning: str,
        universal_model_path: Optional[str],
        admin_notes: Optional[str]
    ) -> TrainingMapping:
        """Admin confirms or edits mapping"""
        
        # 1. Create or update mapping
        mapping = await self.knowledge_base.create_mapping(
            vendor=training_request.vendor,
            platform=training_request.platform,
            raw_syntax=training_request.raw_syntax,
            semantic_meaning=confirmed_meaning,
            universal_model_path=universal_model_path,
            admin_confirmed=True,
            admin_notes=admin_notes,
            created_by=admin_id
        )
        
        # 2. Version the mapping
        await self.knowledge_base.version_mapping(mapping.id)
        
        return mapping
    
    async def reanalyze_with_mapping(
        self,
        audit_id: str,
        mapping: TrainingMapping
    ) -> ComplianceResult:
        """Re-analyze configuration with new mapping"""
        
        # 1. Get original parsed configuration
        parsed_config = await self._get_parsed_config(audit_id)
        
        # 2. Re-run normalization with new mapping
        normalized_config = await self.normalizer.normalize(
            parsed_config=parsed_config,
            additional_mappings=[mapping]
        )
        
        # 3. Re-run compliance evaluation
        compliance_result = await self._reevaluate_compliance(
            audit_id,
            normalized_config
        )
        
        return compliance_result
```

### 5.3 Knowledge Base Structure

```python
class KnowledgeBase:
    """Store of learned vendor-specific mappings"""
    
    async def lookup(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str
    ) -> Optional[TrainingMapping]:
        """Look up existing mapping"""
        
        # Exact match
        mapping = await self.db.query(
            SemanticMapping.vendor == vendor,
            SemanticMapping.platform == platform,
            SemanticMapping.raw_syntax == raw_syntax,
            SemanticMapping.admin_confirmed == True
        ).first()
        
        if mapping:
            return mapping
        
        # Fuzzy match (similar syntax)
        similar = await self._find_similar(
            vendor=vendor,
            platform=platform,
            raw_syntax=raw_syntax
        )
        
        if similar and similar.confidence > 0.8:
            return similar
        
        return None
    
    async def create_mapping(
        self,
        vendor: str,
        platform: str,
        raw_syntax: str,
        semantic_meaning: str,
        universal_model_path: Optional[str],
        admin_confirmed: bool,
        admin_notes: Optional[str],
        created_by: str
    ) -> TrainingMapping:
        """Create new mapping"""
        
        # Check for existing mapping
        existing = await self.lookup(vendor, platform, raw_syntax)
        
        if existing:
            # Update existing mapping
            return await self.update_mapping(
                existing.id,
                semantic_meaning=semantic_meaning,
                universal_model_path=universal_model_path,
                admin_notes=admin_notes,
                changed_by=created_by
            )
        
        # Create new mapping
        mapping = SemanticMapping(
            vendor=vendor,
            platform=platform,
            raw_syntax=raw_syntax,
            semantic_meaning=semantic_meaning,
            universal_model_path=universal_model_path,
            confidence=1.0,  # Admin-confirmed mappings have full confidence
            admin_confirmed=admin_confirmed,
            admin_notes=admin_notes,
            version=1,
            created_by_id=created_by
        )
        
        await self.db.add(mapping)
        await self.db.commit()
        
        return mapping
```

---

## 6. AI Safety Measures

### 6.1 Safety Principles

| Principle | Implementation |
|-----------|---------------|
| **Never Trust AI Directly** | Always validate against deterministic rules |
| **Confidence Thresholds** | Low confidence triggers REVIEW |
| **Human-in-the-loop** | Admin must confirm AI interpretations |
| **Audit Trail** | Log all AI inputs/outputs |
| **Fallback** | System functions without AI (more REVIEWs) |
| **Rate Limiting** | Prevent AI API abuse |
| **Input Sanitization** | Clean inputs before AI queries |
| **Output Validation** | Validate AI responses against schema |

### 6.2 Safety Implementation

```python
class AISafetyValidator:
    """Validate AI outputs for safety"""
    
    def validate_hypothesis(
        self,
        hypothesis: AIHypothesis,
        context: Dict
    ) -> ValidationResult:
        """Validate AI hypothesis for safety"""
        
        errors = []
        warnings = []
        
        # 1. Validate confidence score
        if hypothesis.confidence < 0 or hypothesis.confidence > 1:
            errors.append("Confidence score out of range")
        
        # 2. Validate security relevance
        if hypothesis.security_relevance not in ["high", "medium", "low", "none"]:
            errors.append("Invalid security relevance")
        
        # 3. Check for dangerous patterns
        if self._contains_dangerous_patterns(hypothesis.meaning):
            warnings.append("Potentially dangerous interpretation detected")
        
        # 4. Validate universal model path
        if hypothesis.universal_model_path:
            if not self._is_valid_model_path(hypothesis.universal_model_path):
                warnings.append("Invalid universal model path")
        
        # 5. Check for hallucination indicators
        if self._indicates_hallucination(hypothesis):
            warnings.append("Possible hallucination detected")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            requires_review=len(warnings) > 0 or hypothesis.confidence < 0.7
        )
    
    def _contains_dangerous_patterns(self, text: str) -> bool:
        """Check for dangerous patterns in AI output"""
        dangerous_patterns = [
            "execute",
            "run command",
            "delete",
            "remove",
            "disable firewall",
            "open all ports",
            "allow all traffic"
        ]
        
        text_lower = text.lower()
        return any(pattern in text_lower for pattern in dangerous_patterns)
    
    def _indicates_hallucination(self, hypothesis: AIHypothesis) -> bool:
        """Check for hallucination indicators"""
        # Check if explanation is too vague
        if len(hypothesis.explanation) < 20:
            return True
        
        # Check if reasoning is missing
        if not hypothesis.reasoning:
            return True
        
        # Check if confidence is suspiciously high for unknown syntax
        if hypothesis.confidence > 0.95:
            return True
        
        return False
```

### 6.3 Fallback Strategy

```python
class AIFallbackStrategy:
    """Fallback when AI is unavailable or unreliable"""
    
    async def fallback_analysis(
        self,
        parsed_config: ParsedConfiguration,
        unknown_sections: List[UnknownSection]
    ) -> SemanticInterpretation:
        """Fallback analysis without AI"""
        
        semantic_sections = []
        unknown_meanings = []
        
        for section in unknown_sections:
            # Use pattern matching for common patterns
            pattern_match = self._pattern_match(section.raw_text)
            
            if pattern_match:
                semantic_sections.append(SemanticSection(
                    path=section.path,
                    meaning=pattern_match.meaning,
                    security_relevance=pattern_match.relevance,
                    confidence=pattern_match.confidence,
                    explanation=f"Pattern match: {pattern_match.pattern}",
                    universal_model_path=pattern_match.model_path
                ))
            else:
                # Mark as unknown, requires admin review
                unknown_meanings.append(UnknownMeaning(
                    raw_syntax=section.raw_text,
                    hypothesis=None,
                    requires_admin_review=True
                ))
        
        return SemanticInterpretation(
            parsed_configuration_id=parsed_config.id,
            semantic_sections=semantic_sections,
            confidence_scores=self._calculate_confidence(semantic_sections),
            unknown_meanings=unknown_meanings
        )
```

---

## 7. Prompt Engineering

### 7.1 Prompt Templates

```python
# Hypothesis Generation Prompt
HYPOTHESIS_PROMPT = """You are a network security configuration analyst.

Analyze the following unknown network device configuration syntax:

Vendor: {vendor}
Platform: {platform}
Configuration syntax: {raw_syntax}

Context (surrounding configuration):
{context}

Provide your analysis in the following JSON format:
{{
    "meaning": "What this configuration does (semantic interpretation)",
    "security_relevance": "high/medium/low/none",
    "confidence": 0.0-1.0,
    "reasoning": "Why you think this is the meaning",
    "universal_model_path": "Suggested path in universal security model (e.g., management.ssh.enabled)",
    "alternatives": [
        {{
            "meaning": "Alternative interpretation",
            "confidence": 0.0-1.0,
            "reasoning": "Why this could be correct"
        }}
    ],
    "explanation": "Human-readable explanation of what this configuration means"
}}

Be conservative. If uncertain, state uncertainty clearly. Do not guess if you don't know."""

# Semantic Interpretation Prompt
SEMANTIC_PROMPT = """You are a network security configuration analyst.

Interpret the following network device configuration:

Vendor: {vendor}
Platform: {platform}

Configuration:
{config}

For each security-relevant section, provide:
1. What the configuration does
2. Security relevance (high/medium/low/none)
3. Confidence in interpretation (0.0-1.0)
4. Suggested path in universal security model

Output as JSON array of interpretations."""

# Remediation Explanation Prompt
REMEDIATION_PROMPT = """You are a network security expert.

Explain the following remediation for a security finding:

Finding: {finding_title}
Description: {finding_description}
Vendor: {vendor}
Platform: {platform}
Recommended Configuration: {recommended_config}

Provide:
1. Why this remediation is necessary
2. What risks it mitigates
3. Step-by-step implementation guidance
4. Verification steps
5. Potential side effects

Output as structured JSON."""
```

### 7.2 Prompt Optimization

| Technique | Implementation |
|-----------|---------------|
| **Few-shot Learning** | Include examples in prompts |
| **Chain of Thought** | Ask for reasoning before conclusion |
| **Structured Output** | Request JSON format |
| **Context Window** | Include relevant surrounding config |
| **Temperature Control** | Low temperature for factual queries |
| **Max Tokens** | Limit response length |

### 7.3 Prompt Testing

```python
class PromptTester:
    """Test and validate prompts"""
    
    async def test_hypothesis_prompt(
        self,
        test_cases: List[TestCase]
    ) -> TestResults:
        """Test hypothesis prompt with known cases"""
        
        results = []
        
        for test_case in test_cases:
            response = await self.ai_client.query(
                self._build_hypothesis_prompt(test_case)
            )
            
            # Validate response
            is_correct = self._validate_response(
                response,
                test_case.expected
            )
            
            results.append(TestResult(
                input=test_case.input,
                expected=test_case.expected,
                actual=response,
                is_correct=is_correct
            ))
        
        return TestResults(
            total=len(results),
            correct=sum(1 for r in results if r.is_correct),
            accuracy=sum(1 for r in results if r.is_correct) / len(results)
        )
```

---

## 8. Model Selection

### 8.1 Model Options

| Model | Strengths | Weaknesses | Use Case |
|-------|-----------|------------|----------|
| **GPT-4** | Best reasoning, structured output | Cost, latency | Primary (MVP) |
| **GPT-3.5-Turbo** | Fast, cheap | Lower quality | Fallback, high-volume |
| **Claude-3** | Good reasoning, safety | Availability | Alternative |
| **Local Model** | No API cost, privacy | Lower quality, setup | Future |

### 8.2 Model Selection Strategy

```python
class ModelSelector:
    """Select appropriate AI model"""
    
    def select_model(
        self,
        task_type: str,
        complexity: str,
        cost_sensitivity: str
    ) -> str:
        """Select model based on requirements"""
        
        # High complexity tasks
        if complexity == "high":
            return "gpt-4"
        
        # Medium complexity tasks
        if complexity == "medium":
            if cost_sensitivity == "high":
                return "gpt-3.5-turbo"
            else:
                return "gpt-4"
        
        # Low complexity tasks
        if complexity == "low":
            return "gpt-3.5-turbo"
        
        # Default
        return "gpt-4"
```

### 8.3 Model Configuration

```python
class AIConfig(BaseModel):
    """AI configuration"""
    
    # Primary model
    primary_model: str = "gpt-4"
    primary_temperature: float = 0.3
    primary_max_tokens: int = 2000
    
    # Fallback model
    fallback_model: str = "gpt-3.5-turbo"
    fallback_temperature: float = 0.3
    fallback_max_tokens: int = 2000
    
    # Timeouts
    request_timeout: int = 30
    retry_attempts: int = 3
    retry_delay: int = 1
    
    # Rate limits
    requests_per_minute: int = 60
    tokens_per_minute: int = 90000
    
    # Caching
    cache_ttl: int = 3600
    cache_enabled: bool = True
```

---

## 9. Integration Architecture

### 9.1 API Client

```python
class AIClient:
    """AI API client with retry and rate limiting"""
    
    def __init__(self, config: AIConfig):
        self.config = config
        self.client = openai.AsyncOpenAI()
        self.rate_limiter = RateLimiter(
            max_requests=config.requests_per_minute,
            max_tokens=config.tokens_per_minute
        )
        self.cache = ResponseCache(ttl=config.cache_ttl)
    
    async def query(
        self,
        prompt: str,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None
    ) -> AIResponse:
        """Query AI model"""
        
        # Check cache
        cache_key = self._generate_cache_key(prompt, model)
        cached = await self.cache.get(cache_key)
        if cached:
            return cached
        
        # Apply rate limiting
        await self.rate_limiter.acquire()
        
        # Query with retry
        for attempt in range(self.config.retry_attempts):
            try:
                response = await self._query_model(
                    prompt=prompt,
                    model=model or self.config.primary_model,
                    temperature=temperature or self.config.primary_temperature,
                    max_tokens=max_tokens or self.config.primary_max_tokens
                )
                
                # Cache response
                await self.cache.set(cache_key, response)
                
                return response
                
            except RateLimitError:
                if attempt < self.config.retry_attempts - 1:
                    await asyncio.sleep(self.config.retry_delay * (attempt + 1))
                else:
                    raise
            
            except TimeoutError:
                if attempt < self.config.retry_attempts - 1:
                    continue
                else:
                    # Try fallback model
                    return await self._query_fallback(prompt)
        
        raise AIClientError("All retry attempts failed")
    
    async def _query_model(
        self,
        prompt: str,
        model: str,
        temperature: float,
        max_tokens: int
    ) -> AIResponse:
        """Query specific model"""
        
        response = await self.client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a network security configuration analyst."},
                {"role": "user", "content": prompt}
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"}
        )
        
        return AIResponse(
            content=response.choices[0].message.content,
            model=model,
            tokens_used=response.usage.total_tokens,
            latency_ms=response.response_time
        )
```

### 9.2 Response Parsing

```python
class ResponseParser:
    """Parse AI responses"""
    
    def parse_hypothesis(self, response: AIResponse) -> AIHypothesis:
        """Parse hypothesis response"""
        
        try:
            data = json.loads(response.content)
            
            return AIHypothesis(
                raw_syntax=data.get("raw_syntax", ""),
                suggested_meaning=data.get("meaning", ""),
                confidence=data.get("confidence", 0.5),
                reasoning=data.get("reasoning", ""),
                universal_model_path=data.get("universal_model_path"),
                alternative_interpretations=[
                    AlternativeInterpretation(
                        meaning=alt.get("meaning", ""),
                        confidence=alt.get("confidence", 0.5),
                        reasoning=alt.get("reasoning", "")
                    )
                    for alt in data.get("alternatives", [])
                ],
                security_relevance=data.get("security_relevance", "none"),
                explanation=data.get("explanation", "")
            )
            
        except json.JSONDecodeError:
            raise ResponseParseError("Invalid JSON response")
        
        except KeyError as e:
            raise ResponseParseError(f"Missing field: {e}")
```

---

## 10. Performance Optimization

### 10.1 Caching Strategy

```python
class ResponseCache:
    """Cache AI responses"""
    
    def __init__(self, ttl: int = 3600):
        self.ttl = ttl
        self.redis = Redis()
    
    async def get(self, key: str) -> Optional[AIResponse]:
        """Get cached response"""
        
        cached = await self.redis.get(f"ai_cache:{key}")
        if cached:
            return AIResponse(**json.loads(cached))
        
        return None
    
    async def set(self, key: str, response: AIResponse):
        """Cache response"""
        
        await self.redis.setex(
            f"ai_cache:{key}",
            self.ttl,
            json.dumps(response.dict())
        )
    
    def _generate_cache_key(
        self,
        prompt: str,
        model: str
    ) -> str:
        """Generate cache key"""
        
        # Hash prompt and model
        hash_input = f"{prompt}:{model}"
        return hashlib.sha256(hash_input.encode()).hexdigest()
```

### 10.2 Batch Processing

```python
class BatchProcessor:
    """Batch AI queries for efficiency"""
    
    async def process_batch(
        self,
        queries: List[AIQuery]
    ) -> List[AIResponse]:
        """Process multiple queries in batch"""
        
        # Group similar queries
        grouped = self._group_queries(queries)
        
        results = []
        
        for group in grouped:
            # Process group
            batch_prompt = self._build_batch_prompt(group)
            
            response = await self.ai_client.query(batch_prompt)
            
            # Parse batch response
            batch_results = self._parse_batch_response(response)
            
            results.extend(batch_results)
        
        return results
```

### 10.3 Performance Metrics

| Metric | Target | Measurement |
|--------|--------|-------------|
| Latency (p50) | < 2s | Average response time |
| Latency (p95) | < 5s | 95th percentile |
| Throughput | > 30 req/min | Requests per minute |
| Cache Hit Rate | > 70% | Cached responses / total |
| Error Rate | < 5% | Failed requests / total |

---

## 11. Cost Management

### 11.1 Cost Estimation

| Model | Input Cost | Output Cost | Est. Cost per Audit |
|-------|------------|-------------|---------------------|
| GPT-4 | $0.03/1K tokens | $0.06/1K tokens | $0.50 - $2.00 |
| GPT-3.5-Turbo | $0.001/1K tokens | $0.002/1K tokens | $0.05 - $0.20 |

### 11.2 Cost Optimization

| Strategy | Implementation |
|----------|---------------|
| **Caching** | Cache repeated queries |
| **Batching** | Process multiple queries together |
| **Prompt Optimization** | Minimize token usage |
| **Model Selection** | Use cheaper models for simple tasks |
| **Rate Limiting** | Prevent excessive API calls |

### 11.3 Cost Monitoring

```python
class CostMonitor:
    """Monitor AI API costs"""
    
    def __init__(self):
        self.usage_tracker = UsageTracker()
    
    async def track_usage(
        self,
        model: str,
        tokens_used: int,
        audit_id: str
    ):
        """Track API usage"""
        
        cost = self._calculate_cost(model, tokens_used)
        
        await self.usage_tracker.record(
            model=model,
            tokens=tokens_used,
            cost=cost,
            audit_id=audit_id
        )
        
        # Check budget
        await self._check_budget(cost)
    
    async def _check_budget(self, cost: float):
        """Check if budget is exceeded"""
        
        current_usage = await self.usage_tracker.get_current_usage()
        
        if current_usage + cost > self.config.budget_limit:
            raise BudgetExceededError(
                f"Budget exceeded: {current_usage + cost} > {self.config.budget_limit}"
            )
```

---

## 12. Monitoring and Observability

### 12.1 Metrics

```python
# AI Metrics
AI_METRICS = {
    "ai_requests_total": Counter("ai_requests_total", "Total AI requests"),
    "ai_requests_failed": Counter("ai_requests_failed", "Failed AI requests"),
    "ai_latency_seconds": Histogram("ai_latency_seconds", "AI request latency"),
    "ai_tokens_used": Counter("ai_tokens_used", "Total tokens used"),
    "ai_cost_dollars": Counter("ai_cost_dollars", "Total cost in dollars"),
    "ai_cache_hits": Counter("ai_cache_hits", "Cache hits"),
    "ai_cache_misses": Counter("ai_cache_misses", "Cache misses"),
}
```

### 12.2 Logging

```python
class AILogger:
    """Log AI interactions"""
    
    def log_request(
        self,
        prompt: str,
        model: str,
        response: AIResponse,
        latency_ms: float
    ):
        """Log AI request"""
        
        logger.info("AI request", extra={
            "model": model,
            "prompt_length": len(prompt),
            "response_length": len(response.content),
            "tokens_used": response.tokens_used,
            "latency_ms": latency_ms,
            "cache_hit": response.cache_hit
        })
    
    def log_error(
        self,
        error: Exception,
        prompt: str,
        model: str
    ):
        """Log AI error"""
        
        logger.error("AI error", extra={
            "error_type": type(error).__name__,
            "error_message": str(error),
            "model": model,
            "prompt_length": len(prompt)
        })
```

### 12.3 Alerting

| Alert | Condition | Action |
|-------|-----------|--------|
| High Error Rate | > 10% failures | Investigate |
| High Latency | p95 > 10s | Optimize |
| Budget Exceeded | > 80% budget | Alert team |
| Cache Miss Rate | > 50% misses | Optimize caching |

---

**END OF AI ARCHITECTURE DOCUMENT**
