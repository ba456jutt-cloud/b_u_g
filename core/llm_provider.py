import json
import time
import logging
import os
import re
import threading
from abc import ABC, abstractmethod
import google.generativeai as genai
from pydantic import BaseModel, Field
from openai import OpenAI

from config.settings import settings
from core.llm_cache import get_cached, set_cached

logger = logging.getLogger(__name__)

# ── Global rate-limit windows: track when each provider may resume ─────────
_provider_cooldown: dict = {}  # key: provider_name → float (epoch seconds)

class AgentOutput(BaseModel):
    thought: str = Field(description="The agent's reasoning process")
    action: str = Field(description="The tool to call, or 'none' if no tool is needed")
    result: str = Field(description="The final output to the user, or the parameters for the tool action")

class LLMProvider(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> dict:
        pass

    def _truncate_prompt(self, prompt: str, max_chars: int = 12000) -> str:
        if len(prompt) <= max_chars:
            return prompt
        head = prompt[:4000]
        tail = prompt[-8000:]
        truncation_msg = "\n\n[... PREVIOUS CONTEXT TRUNCATED TO SAVE TOKENS ...]\n\n"
        truncated = head + truncation_msg + tail
        logger.info(f"Prompt truncated from {len(prompt)} to {len(truncated)} chars to save tokens.")
        return truncated

    @staticmethod
    def _parse_retry_after(error_str: str, default: float = 5.0) -> float:
        """Extract seconds to wait from a 429 rate-limit error message."""
        # 'Please try again in 10m7.392s' or 'retry_delay { seconds: 2 }'
        m = re.search(r'(?:retry in|try again in)\s+(\d+)m([\d.]+)s', error_str, re.IGNORECASE)
        if m:
            return int(m.group(1)) * 60 + float(m.group(2))
        m = re.search(r'(?:retry in|try again in)\s+([\d.]+)s', error_str, re.IGNORECASE)
        if m:
            return float(m.group(1))
        m = re.search(r'seconds:\s*(\d+)', error_str)
        if m:
            return float(m.group(1))
        return default


    @staticmethod
    def _extract_last_json_object(text: str) -> str:

        """Use bracket-counting to find ALL top-level JSON objects and return the LAST complete one.
        This fixes the greedy regex bug where reasoning containing JSON examples
        (e.g. 'test {\"id\": 1}') caused wrong extraction.
        """
        candidates = []
        depth = 0
        start = -1
        in_string = False
        escape_next = False

        for i, ch in enumerate(text):
            if escape_next:
                escape_next = False
                continue
            if ch == '\\' and in_string:
                escape_next = True
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch == '{':
                if depth == 0:
                    start = i
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0 and start != -1:
                    candidates.append(text[start:i + 1])
                    start = -1
        return candidates[-1] if candidates else ""

    @staticmethod
    def _clean_and_parse_json(raw_text: str) -> dict:
        """Robustly parse JSON from raw LLM text output, handling markdown fences and surrounding text."""
        if not raw_text:
            return {"thought": "Empty LLM output", "action": "none", "result": ""}

        clean = raw_text.strip()

        # Strip markdown fences if present
        if "```" in clean:
            fence_match = re.search(r'```(?:json)?\s*(.*?)\s*```', clean, re.DOTALL | re.IGNORECASE)
            if fence_match:
                clean = fence_match.group(1).strip()
            else:
                clean = re.sub(r'^```(?:json)?\s*', '', clean, flags=re.IGNORECASE)
                clean = re.sub(r'\s*```$', '', clean).strip()

        # Attempt 1: Direct parse of the entire cleaned string
        try:
            parsed = json.loads(clean)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass

        # Attempt 2: Balanced-bracket extraction — finds the LAST complete JSON object
        # This correctly handles LLM reasoning that contains JSON examples inline
        last_obj = LLMProvider._extract_last_json_object(clean)
        if last_obj:
            try:
                parsed = json.loads(last_obj)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

        # Attempt 3: Simple regex fallback — first JSON block (for simple cases)
        match = re.search(r'\{[^{}]*"action"[^{}]*\}', clean, re.DOTALL)
        if match:
            try:
                parsed = json.loads(match.group(0))
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

        # Attempt 4: If result contains 'action' keyword, try extracting it manually
        if '"action"' in raw_text or "'action'" in raw_text:
            action_match = re.search(r'"action"\s*:\s*"([^"]+)"', raw_text)
            result_match = re.search(r'"result"\s*:\s*"([^"]*)"', raw_text, re.DOTALL)
            thought_match = re.search(r'"thought"\s*:\s*"([^"]*)"', raw_text, re.DOTALL)
            if action_match:
                return {
                    "thought": thought_match.group(1) if thought_match else "Extracted from partial JSON",
                    "action": action_match.group(1),
                    "result": result_match.group(1) if result_match else raw_text[:2000]
                }

        # Final fallback: return raw text as result with action=none
        return {
            "thought": "Analysis generated",
            "action": "none",
            "result": raw_text
        }

    def _cached_generate(self, prompt: str, provider_fn) -> dict:
        """Check cache first; call provider_fn(prompt) on miss; store result."""
        cached = get_cached(prompt)
        if cached is not None:
            return cached
        result = provider_fn(prompt)
        # Only cache successful, non-error responses
        if result.get("action") != "none" or "Error" not in str(result.get("result", "")):
            set_cached(prompt, result)
        return result



class NanoRouterProvider(LLMProvider):
    """
    NanoRouter Provider (7 Million Daily Tokens Limit).
    OpenAI-compatible multi-key provider.
    """
    def __init__(self, model_name: str = "agnes-2.5-flash"):
        raw = os.getenv("NANOROUTER_API_KEYS", os.getenv("NANOROUTER_API_KEY", ""))
        self.keys = [k.strip().strip('"').strip("'") for k in raw.split(",") if k.strip()]
        configured_model = os.getenv("NANOROUTER_MODEL", model_name)
        self.model_name = "gpt-4o-mini" if configured_model == "auto" else configured_model
        base_url = os.getenv("NANOROUTER_BASE_URL", "https://router.bynara.id/v1")
        self.base_url = base_url
        self.current_idx = 0
        self._gemini_fallback = None

    def _get_fallback(self):
        if self._gemini_fallback is None:
            self._gemini_fallback = GeminiProvider()
        return self._gemini_fallback

    def generate(self, prompt: str) -> dict:
        return self._cached_generate(prompt, self._do_generate)

    def _do_generate(self, prompt: str) -> dict:
        if not self.keys or "your_" in self.keys[0]:
            return self._get_fallback().generate(prompt)

        prompt = self._truncate_prompt(prompt)
        attempts = 0
        max_attempts = len(self.keys) * 2

        while attempts < max_attempts:
            key = self.keys[self.current_idx % len(self.keys)]
            self.current_idx += 1
            attempts += 1

            try:
                client = OpenAI(api_key=key, base_url=self.base_url)
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a JSON security agent. Respond strictly with JSON format: {\"thought\": \"...\", \"action\": \"...\", \"result\": \"...\"}"},
                        {"role": "user", "content": prompt}
                    ]
                )
                res_text = response.choices[0].message.content
                return self._clean_and_parse_json(res_text)

            except Exception as e:
                logger.warning(f"[NanoRouterProvider] Key rotation ({key[:10]}...) failed: {e}. Rotating...")
                time.sleep(0.5)

        logger.warning("[NanoRouterProvider] All keys failed. Falling back to Gemini...")
        return self._get_fallback().generate(prompt)


class GroqMultiKeyProvider(LLMProvider):
    """
    Groq Provider with Multi-API Key Auto-Rotation (e.g. 3 keys).
    Eliminates rate limits by rotating to the next key on 429 / quota exhaustion.
    """
    def __init__(self, model_name: str = "llama-3.3-70b-versatile"):
        raw = os.getenv("GROQ_API_KEYS", os.getenv("GROQ_API_KEY", ""))
        self.keys = [k.strip().strip('"').strip("'") for k in raw.split(",") if k.strip()]
        self.model_name = os.getenv("GROQ_MODEL", model_name)
        self.current_idx = 0
        self._fallback_provider = None

    def _get_fallback(self):
        """Priority: OpenRouter (no daily limit) → Gemini"""
        if self._fallback_provider is None:
            openrouter_keys = os.getenv("OPENROUTER_API_KEYS", os.getenv("OPENROUTER_API_KEY", ""))
            if openrouter_keys.strip():
                self._fallback_provider = OpenRouterProvider()
                logger.info("[GroqMultiKeyProvider] Fallback → OpenRouterProvider (no daily limit)")
            else:
                self._fallback_provider = GeminiProvider()
                logger.info("[GroqMultiKeyProvider] Fallback → GeminiProvider")
        return self._fallback_provider

    def generate(self, prompt: str) -> dict:
        return self._cached_generate(prompt, self._do_generate)

    def _do_generate(self, prompt: str) -> dict:
        if not self.keys:
            return self._get_fallback().generate(prompt)

        prompt = self._truncate_prompt(prompt)

        # Track which keys hit daily (TPD) limits - skip them immediately
        daily_exhausted = set()

        for attempt in range(len(self.keys) * 2):
            key = self.keys[self.current_idx % len(self.keys)]
            self.current_idx += 1

            # Skip keys that already hit daily limit this session
            if key in daily_exhausted:
                continue

            try:
                client = OpenAI(api_key=key, base_url="https://api.groq.com/openai/v1")
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a JSON security agent. Respond strictly with JSON format: {\"thought\": \"...\", \"action\": \"...\", \"result\": \"...\"}"},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                return self._clean_and_parse_json(response.choices[0].message.content)

            except Exception as e:
                err_str = str(e)
                is_daily = "tokens per day" in err_str.lower() or "TPD" in err_str or "per day" in err_str.lower()
                if is_daily:
                    # Daily limit hit — mark key as exhausted, skip immediately, no wait
                    logger.warning(f"[GroqMultiKeyProvider] Key ({key[:10]}...) hit DAILY limit. Skipping instantly.")
                    daily_exhausted.add(key)
                else:
                    # Per-minute/token limit — wait the specified time
                    wait = self._parse_retry_after(err_str, default=2.0)
                    wait = min(wait, 8.0)  # max 8s wait for per-minute limits
                    logger.warning(f"[GroqMultiKeyProvider] Key ({key[:10]}...) QPM limited. Waiting {wait:.1f}s...")
                    time.sleep(wait)

            # If all keys are daily-exhausted, break immediately
            if len(daily_exhausted) >= len(self.keys):
                logger.warning("[GroqMultiKeyProvider] All Groq keys hit DAILY limit. Falling back to Gemini immediately.")
                break

        logger.warning("[GroqMultiKeyProvider] All Groq keys exhausted. Falling back to Gemini...")
        return self._get_fallback().generate(prompt)


class GeminiProvider(LLMProvider):
    """
    Gemini Provider with Multi-API Key Auto-Rotation (e.g. 3 keys).
    Rotates through multiple Gemini keys when rate-limit (429) occurs.
    """
    def __init__(self):
        raw = os.getenv("GEMINI_API_KEYS") or os.getenv("GEMINI_API_KEYs") or os.getenv("GEMINI_API_KEY") or getattr(settings, 'GEMINI_API_KEY', '')
        self.keys = [k.strip().strip('"').strip("'") for k in raw.split(",") if k.strip()]
        self.model_name = getattr(settings, 'DEFAULT_MODEL', 'gemini-2.5-flash')
        self.current_idx = 0
        # Thread-safety lock: genai.configure() mutates GLOBAL library state.
        # Without this lock, concurrent threads rotating keys overwrite each other.
        self._genai_lock = threading.Lock()

    def generate(self, prompt: str) -> dict:
        return self._cached_generate(prompt, self._do_generate)

    def _do_generate(self, prompt: str) -> dict:
        if not self.keys:
            return self._cascade_fallback(prompt)

        prompt = self._truncate_prompt(prompt)

        # Track per-key wait times so we pick the key that's available soonest
        key_available_at = {}  # key -> epoch time when it becomes available

        for attempt in range(len(self.keys) * 3):
            now = time.time()
            # Pick the key with the earliest availability
            available_keys = [
                k for k in self.keys
                if key_available_at.get(k, 0) <= now
            ]

            if not available_keys:
                # All keys are in cooldown — wait for the soonest one
                soonest = min(key_available_at.values())
                wait_secs = max(0, soonest - now)
                if wait_secs > 60:
                    # All keys cooling down for > 1 min → cascade to next provider
                    logger.warning(f"[GeminiProvider] All keys cooling down for {wait_secs:.0f}s. Cascading now.")
                    return self._cascade_fallback(prompt)
                logger.warning(f"[GeminiProvider] All keys cooling down. Waiting {wait_secs:.1f}s for earliest key...")
                time.sleep(wait_secs + 0.5)
                continue

            # Use round-robin among available keys
            key = available_keys[self.current_idx % len(available_keys)]
            self.current_idx += 1

            try:
                # FIXED: genai.configure() mutates global library state.
                # Use a lock so only one thread at a time configures+generates.
                with self._genai_lock:
                    genai.configure(api_key=key)
                    model = genai.GenerativeModel(
                        model_name=self.model_name,
                        generation_config={"response_mime_type": "application/json"}
                    )
                    resp = model.generate_content(prompt)
                return self._clean_and_parse_json(resp.text)

            except Exception as e:
                err_str = str(e)
                wait = self._parse_retry_after(err_str, default=5.0)
                logger.warning(f"[GeminiProvider] Key ({key[:10]}...) rate-limited. Available in {wait:.1f}s.")
                key_available_at[key] = time.time() + wait

        logger.warning("[GeminiProvider] All Gemini keys exhausted. Cascading to OpenRouter...")
        return self._cascade_fallback(prompt)

    def _cascade_fallback(self, prompt: str) -> dict:
        """Last-resort: try OpenRouter free tier, then NanoRouter, then local stub."""
        # Try OpenRouter
        openrouter_keys = os.getenv("OPENROUTER_API_KEYS", os.getenv("OPENROUTER_API_KEY", ""))
        if openrouter_keys.strip():
            try:
                from core.llm_provider import OpenRouterProvider
                or_provider = OpenRouterProvider()
                logger.warning("[GeminiProvider] Cascade → OpenRouterProvider")
                result = or_provider._do_generate(prompt)
                if "Error" not in str(result.get("result", "")):
                    return result
            except Exception as e:
                logger.warning(f"[GeminiProvider] OpenRouter cascade failed: {e}")

        # Try NanoRouter
        nano_keys = os.getenv("NANOROUTER_API_KEYS", os.getenv("NANOROUTER_API_KEY", ""))
        if nano_keys.strip():
            try:
                from core.llm_provider import NanoRouterProvider
                nr_provider = NanoRouterProvider()
                logger.warning("[GeminiProvider] Cascade → NanoRouterProvider")
                result = nr_provider._do_generate(prompt)
                if "Error" not in str(result.get("result", "")):
                    return result
            except Exception as e:
                logger.warning(f"[GeminiProvider] NanoRouter cascade failed: {e}")

        # All providers exhausted — return a deterministic stub so agent can still write final report
        logger.error("[GeminiProvider] ALL providers exhausted. Returning graceful stub.")
        return {
            "thought": "All LLM providers are currently rate-limited. Generating best-effort report from collected data.",
            "action": "none",
            "result": "[RATE-LIMIT STUB] All API keys exhausted for this session. Previous tool outputs have been recorded in memory. Please retry in 30-60 minutes or add more API keys to .env (GROQ_API_KEYS / GEMINI_API_KEYS / OPENROUTER_API_KEYS)."
        }


class MistralProvider(LLMProvider):
    """
    Mistral AI Provider with Multi-API Key Auto-Rotation (e.g. 3 keys).
    """
    def __init__(self, model_name: str = "codestral-latest"):
        raw = os.getenv("MISTRAL_API_KEYS", os.getenv("MISTRAL_API_KEY", ""))
        self.keys = [k.strip().strip('"').strip("'") for k in raw.split(",") if k.strip()]
        self.model_name = os.getenv("MISTRAL_MODEL", model_name)
        self.current_idx = 0
        self._gemini_fallback = None

    def _get_fallback(self):
        if self._gemini_fallback is None:
            self._gemini_fallback = GeminiProvider()
        return self._gemini_fallback

    def generate(self, prompt: str) -> dict:
        if not self.keys:
            return self._get_fallback().generate(prompt)

        prompt = self._truncate_prompt(prompt)
        attempts = 0
        max_attempts = len(self.keys) * 2

        while attempts < max_attempts:
            key = self.keys[self.current_idx % len(self.keys)]
            self.current_idx += 1
            attempts += 1

            try:
                client = OpenAI(api_key=key, base_url="https://api.mistral.ai/v1")
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a JSON security agent. Respond strictly with JSON format: {\"thought\": \"...\", \"action\": \"...\", \"result\": \"...\"}"},
                        {"role": "user", "content": prompt}
                    ],
                    response_format={"type": "json_object"}
                )
                return self._clean_and_parse_json(response.choices[0].message.content)

            except Exception as e:
                logger.warning(f"[MistralProvider] Key rotation ({key[:10]}...) failed: {e}. Switching to next key...")
                time.sleep(0.5)

        logger.warning("[MistralProvider] All keys exhausted. Falling back to Gemini...")
        return self._get_fallback().generate(prompt)


class OpenRouterProvider(LLMProvider):
    """
    OpenRouter Provider with Multi-API Key Auto-Rotation (e.g. 2 keys).
    """
    def __init__(self, model_name: str = "openrouter/auto"):
        raw = os.getenv("OPENROUTER_API_KEYS", os.getenv("OPENROUTER_API_KEY", getattr(settings, 'OPENROUTER_API_KEY', '')))
        self.keys = [k.strip().strip('"').strip("'") for k in raw.split(",") if k.strip()]
        self.model_name = os.getenv("OPENROUTER_MODEL", model_name)
        self.current_idx = 0
        self._gemini_fallback = None

    def _get_fallback(self):
        if self._gemini_fallback is None:
            self._gemini_fallback = GeminiProvider()
        return self._gemini_fallback

    def generate(self, prompt: str) -> dict:
        return self._cached_generate(prompt, self._do_generate)

    def _do_generate(self, prompt: str) -> dict:
        if not self.keys:
            return self._get_fallback().generate(prompt)

        prompt = self._truncate_prompt(prompt)
        attempts = 0
        max_attempts = len(self.keys) * 2

        while attempts < max_attempts:
            key = self.keys[self.current_idx % len(self.keys)]
            self.current_idx += 1
            attempts += 1

            try:
                client = OpenAI(api_key=key, base_url="https://openrouter.ai/api/v1")
                response = client.chat.completions.create(
                    model=self.model_name,
                    messages=[
                        {"role": "system", "content": "You are a JSON security agent. Respond strictly with JSON format: {\"thought\": \"...\", \"action\": \"...\", \"result\": \"...\"}"},
                        {"role": "user", "content": prompt}
                    ]
                )
                return self._clean_and_parse_json(response.choices[0].message.content)

            except Exception as e:
                logger.warning(f"[OpenRouterProvider] Key rotation ({key[:10]}...) failed: {e}. Switching to next key...")
                time.sleep(0.5)

        logger.warning("[OpenRouterProvider] All keys exhausted. Falling back to Gemini...")
        return self._get_fallback().generate(prompt)


class TogetherAIProvider(LLMProvider):
    """
    Together AI Provider for Llama-3.3-70B and Qwen-2.5-Coder.
    """
    def __init__(self, model_name: str = "meta-llama/Llama-3.3-70B-Instruct-Turbo"):
        raw = os.getenv("TOGETHER_API_KEYS", os.getenv("TOGETHER_API_KEY", ""))
        self.keys = [k.strip().strip('"').strip("'") for k in raw.split(",") if k.strip()]
        self.model_name = os.getenv("TOGETHER_MODEL", model_name)
        self.current_idx = 0

    def generate(self, prompt: str) -> dict:
        if not self.keys:
            return {"thought": "No Together AI keys configured", "action": "none", "result": "Error: TOGETHER_API_KEYS empty"}

        prompt = self._truncate_prompt(prompt)
        key = self.keys[self.current_idx % len(self.keys)]
        self.current_idx += 1

        try:
            client = OpenAI(api_key=key, base_url="https://api.together.xyz/v1")
            response = client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a JSON security agent. Respond strictly with JSON format: {\"thought\": \"...\", \"action\": \"...\", \"result\": \"...\"}"},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            return self._clean_and_parse_json(response.choices[0].message.content)

        except Exception as e:
            logger.error(f"[TogetherAIProvider] Error: {e}")
            return {"thought": f"Together AI error: {e}", "action": "none", "result": f"Error: {e}"}


class OllamaProvider(LLMProvider):
    """
    100% Local & Private Ollama Provider.
    Connects to http://localhost:11434/v1 — No API Keys, No Rate Limits.
    Models: 'qwen2.5-coder:7b', 'deepseek-r1:8b', 'llama3.1:8b'.
    """
    def __init__(self, model_name: str = "qwen2.5-coder:7b", base_url: str = "http://localhost:11434/v1"):
        self.client = OpenAI(api_key="ollama", base_url=base_url)
        self.model_name = os.getenv("OLLAMA_MODEL", model_name)

    def generate(self, prompt: str) -> dict:
        prompt = self._truncate_prompt(prompt)
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a JSON security agent. Respond strictly in JSON: {\"thought\": \"...\", \"action\": \"...\", \"result\": \"...\"}"},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            return self._clean_and_parse_json(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"[OllamaProvider] Local Ollama Error: {e}")
            return {"thought": f"Ollama local error: {e}", "action": "none", "result": f"Error: Ollama server not responding on localhost:11434. Start with: ollama serve"}


class DeepSeekProvider(LLMProvider):
    def __init__(self):
        self.client = OpenAI(
            api_key=settings.DEEPSEEK_API_KEY,
            base_url="https://api.deepseek.com"
        )
        self.model_name = "deepseek-chat"
        self._failure_count = 0
        self._circuit_open_until = 0
        self._MAX_FAILURES = 2
        self._COOLDOWN_SECONDS = 300
        self._gemini_fallback: GeminiProvider = None

    def _get_gemini_fallback(self) -> GeminiProvider:
        if self._gemini_fallback is None:
            self._gemini_fallback = GeminiProvider()
        return self._gemini_fallback

    def generate(self, prompt: str) -> dict:
        prompt = self._truncate_prompt(prompt)
        try:
            response = self.client.beta.chat.completions.parse(
                model=self.model_name,
                messages=[{"role": "user", "content": prompt}],
                response_format=AgentOutput
            )
            return self._clean_and_parse_json(response.choices[0].message.content)

        except Exception as e:
            err_str = str(e)
            logger.warning(f"[DeepSeekProvider] Error: {err_str[:150]}. Falling back to Gemini...")
            return self._get_gemini_fallback().generate(prompt)
