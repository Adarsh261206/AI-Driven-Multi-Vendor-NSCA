"""
Prompt Templates

Structured prompts for AI semantic analysis.
All prompts request JSON output for deterministic parsing.
"""

from __future__ import annotations


# System prompt for all AI interactions
SYSTEM_PROMPT = """You are a network security configuration analyst. You analyze network device 
configurations and provide structured interpretations. 

IMPORTANT RULES:
1. Always respond with valid JSON only - no markdown, no explanations outside JSON
2. Be conservative - if uncertain, state uncertainty clearly with low confidence
3. Never guess if you don't know - mark as unknown
4. Never suggest security actions - only interpret what the configuration does
5. Focus on factual interpretation, not recommendations

You do NOT make compliance decisions. You only provide semantic interpretations.
The deterministic compliance engine decides PASS/FAIL based on your interpretation."""


# Hypothesis prompt for unknown configuration syntax
HYPOTHESIS_PROMPT = """Analyze this unknown network configuration syntax and provide your interpretation.

Configuration syntax to analyze:
```
{raw_syntax}
```

Context:
- Vendor: {vendor}
- Platform: {platform}
- Section path: {section_path}

Provide your analysis as JSON with this exact structure:
{{
    "meaning": "Clear description of what this configuration does",
    "security_relevance": "high|medium|low|none",
    "confidence": 0.0 to 1.0,
    "reasoning": "Why you interpret it this way",
    "universal_model_path": "suggested.path.in.universal.model or null if unknown",
    "alternatives": [
        {{
            "meaning": "Alternative interpretation",
            "confidence": 0.0 to 1.0,
            "reasoning": "Why this might be correct"
        }}
    ],
    "explanation": "Human-readable explanation of the configuration"
}}

Guidelines:
- confidence 0.9+: You are very certain of the interpretation
- confidence 0.7-0.9: You are reasonably certain
- confidence 0.5-0.7: You are uncertain, provide alternatives
- confidence <0.5: You cannot reliably interpret this
- security_relevance "high": Affects access control, authentication, encryption
- security_relevance "medium": Affects logging, monitoring, availability
- security_relevance "low": Affects naming, cosmetic settings
- security_relevance "none": No security impact
- universal_model_path: Map to our universal model if possible (e.g., management.ssh.enabled)
- Always provide at least one alternative if confidence < 0.9"""


# Semantic analysis prompt for configuration sections
SEMANTIC_PROMPT = """Analyze each section of this network configuration and provide semantic interpretations.

Configuration sections:
{sections}

For each section, provide:
{{
    "path": "section path",
    "meaning": "What this section configures",
    "security_relevance": "high|medium|low|none",
    "confidence": 0.0 to 1.0,
    "universal_model_path": "suggested.path or null"
}}

Respond as a JSON array of section analyses."""


# Remediation explanation prompt
REMEDIATION_PROMPT = """Explain why this security finding matters and how to fix it.

Finding:
- Title: {title}
- Description: {description}
- Vendor: {vendor}
- Platform: {platform}
- Recommended configuration: {recommended_config}

Provide as JSON:
{{
    "why_it_matters": "Plain explanation of the security risk",
    "risks_mitigated": ["risk1", "risk2"],
    "step_by_step": ["step1", "step2"],
    "verification_steps": ["verify1", "verify2"],
    "potential_side_effects": ["effect1", "effect2"]
}}"""


def build_hypothesis_prompt(
    raw_syntax: str,
    vendor: str,
    platform: str,
    section_path: str = "",
) -> str:
    """Build hypothesis prompt"""
    return HYPOTHESIS_PROMPT.format(
        raw_syntax=raw_syntax,
        vendor=vendor,
        platform=platform,
        section_path=section_path or "root",
    )


def build_semantic_prompt(sections: list[dict]) -> str:
    """Build semantic analysis prompt"""
    sections_text = "\n---\n".join(
        f"Path: {s.get('path', 'unknown')}\nContent:\n{s.get('content', '')}"
        for s in sections
    )
    return SEMANTIC_PROMPT.format(sections=sections_text)


def build_remediation_prompt(
    title: str,
    description: str,
    vendor: str,
    platform: str,
    recommended_config: str,
) -> str:
    """Build remediation explanation prompt"""
    return REMEDIATION_PROMPT.format(
        title=title,
        description=description,
        vendor=vendor,
        platform=platform,
        recommended_config=recommended_config,
    )
