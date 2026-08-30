import logging
import time
import os
from core.llm_provider import (
    GeminiProvider, DeepSeekProvider, OpenRouterProvider,
    GroqMultiKeyProvider, OllamaProvider, MistralProvider,
    TogetherAIProvider, NanoRouterProvider
)

logger = logging.getLogger(__name__)

def _is_valid_key_list(keys: list) -> bool:
    if not keys:
        return False
    first = keys[0].lower()
    return not ("your_" in first or "placeholder" in first or "key_here" in first)

class ModelRouter:
    """
    Dynamic Multi-Provider Router with Multi-Key Auto-Rotation & Fallback:
    - NanoRouter (7M Daily Tokens Limit)
    - 3x Groq Keys (Primary Heavy Recon & Reasoning)
    - 3x Mistral Keys (Code Review & Dynamic Tool Builder)
    - 3x Gemini Keys (Knowledge Base & PDF Report Generation)
    - 2x OpenRouter Keys (Fallback Reasoning & Search)
    """
    def __init__(self):
        self._gemini = GeminiProvider()
        self._deepseek = DeepSeekProvider()
        self._nanorouter = NanoRouterProvider() if os.getenv("NANOROUTER_API_KEYS") or os.getenv("NANOROUTER_API_KEY") else None
        self._openrouter = OpenRouterProvider() if os.getenv("OPENROUTER_API_KEYS") or os.getenv("OPENROUTER_API_KEY") else None
        self._groq = GroqMultiKeyProvider() if os.getenv("GROQ_API_KEYS") or os.getenv("GROQ_API_KEY") else None
        self._mistral = MistralProvider() if os.getenv("MISTRAL_API_KEYS") or os.getenv("MISTRAL_API_KEY") else None
        self._together = TogetherAIProvider() if os.getenv("TOGETHER_API_KEYS") or os.getenv("TOGETHER_API_KEY") else None
        self._ollama = OllamaProvider() if os.getenv("USE_OLLAMA", "false").lower() == "true" else None

        self.providers = {
            "gemini": self._gemini,
            "deepseek": self._deepseek,
        }

        has_nano = self._nanorouter and _is_valid_key_list(getattr(self._nanorouter, 'keys', []))
        has_groq = self._groq and _is_valid_key_list(getattr(self._groq, 'keys', []))
        has_mistral = self._mistral and _is_valid_key_list(getattr(self._mistral, 'keys', []))
        has_openrouter = self._openrouter and _is_valid_key_list(getattr(self._openrouter, 'keys', []))

        if has_nano:
            self.providers["nanorouter"] = self._nanorouter
        if has_groq:
            self.providers["groq"] = self._groq
        if has_mistral:
            self.providers["mistral"] = self._mistral
        if has_openrouter:
            self.providers["openrouter"] = self._openrouter

        # Priority: NanoRouter (7M/day) > Groq (300k/day) > OpenRouter > Gemini
        primary_reasoning = (
            "nanorouter" if has_nano else
            "groq"       if has_groq else
            "openrouter" if has_openrouter else
            "gemini"
        )
        code_reasoning = "mistral" if has_mistral else primary_reasoning

        self.routing_table = {
            # ── Orchestration ──────────────────────────────────────────
            "MasterAgent":                  primary_reasoning,
            # ── Recon & Network ────────────────────────────────────────
            "ScopeManagementAgent":         primary_reasoning,
            "PassiveReconAgent":            primary_reasoning,
            "DNSIntelligenceAgent":         primary_reasoning,
            "ReconAnalysisAgent":           primary_reasoning,
            "AliveHostAgent":               primary_reasoning,
            "PortScanAgent":                primary_reasoning,
            # ── Web Enumeration ────────────────────────────────────────
            "WebCrawlingAgent":             primary_reasoning,
            "JSAnalysisAgent":              primary_reasoning,
            "ParamDiscoveryAgent":          primary_reasoning,
            "DirectoryEnumAgent":           primary_reasoning,
            # ── Vulnerability & Attack ─────────────────────────────────
            "VulnerabilityAnalysisAgent":   primary_reasoning,
            "AttackChainAgent":             primary_reasoning,
            # ── Code / Tool Building ───────────────────────────────────
            "GeneralToolBuilderAgent":      code_reasoning,
            "ToolBuilderAgent":             code_reasoning,
            "CodeReviewAgent":              code_reasoning,
            "PatchGeneratorAgent":          code_reasoning,   # ← Mistral Codestral (writes patches)
            # ── Knowledge & Report ─────────────────────────────────────
            "CVEResearchAgent":             "gemini",
            "ReportAgent":                  "gemini",
            "SecurityKnowledgeAgent":       "gemini",
            # ── Support Agents ─────────────────────────────────────────
            "EvidenceAgent":                primary_reasoning,
            "DeduplicationAgent":           primary_reasoning,
            "NotificationAgent":            "gemini",
            "AuditLogAgent":                primary_reasoning,
            "ValidationAgent":              primary_reasoning,
            # ── Default fallback ───────────────────────────────────────
            "default":                      primary_reasoning,
        }

    def get_provider(self, agent_name: str, task: str = None):
        if os.getenv("USE_OLLAMA", "false").lower() == "true" and self._ollama:
            logger.info(f"[ModelRouter] 100% Local Mode Active — Routing {agent_name} -> Ollama Local")
            return self._ollama

        preferred_name = self.routing_table.get(agent_name, self.routing_table["default"])
        provider = self.providers.get(preferred_name, self._gemini)

        logger.info(f"[ModelRouter] Routing {agent_name} -> {preferred_name}")
        return provider
