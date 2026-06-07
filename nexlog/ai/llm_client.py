"""
ai/llm_client.py â€” NexLog AI Layer
LLM client with automatic tier selection.

Five compatibility tiers, auto-selected at runtime in priority order:

  Tier 1 â€” Ollama  (local, private, zero cost)
            REST API at http://localhost:11434 (configurable)
            Models: mistral, llama3.1, gemma3, phi-3, etc.
            Install: https://ollama.com  â†’  ollama pull mistral
            All data stays on-device. Best for air-gapped / private deployments.

  Tier 2 â€” Groq  (free cloud API, very fast inference)
            OpenAI-compatible API. Free tier: 30 RPM, 6 000 TPM.
            Default model: llama-3.3-70b-versatile
            Sign up:  https://console.groq.com  (60 s, no credit card)
            Requires: GROQ_API_KEY environment variable.

  Tier 5 â€” Google Gemini  (free cloud API)
            Free tier: 15 RPM, 1 000 000 tokens per day.
            Default model: gemini-1.5-flash-latest
            Sign up:  https://aistudio.google.com  (Google account only)
            Requires: GEMINI_API_KEY environment variable.

  Tier 4 â€” Anthropic Claude  (paid cloud API)
            Paid API â€” only activates when key is set in env var.
            Default model: claude-3-5-haiku-20241022
            Requires: ANTHROPIC_API_KEY environment variable.
            SECURITY: NEVER hardcode keys â€” env var only.

  Tier 3 â€” Template-based synthesis  (stdlib, always available)
            No LLM required. Deterministic, fast, fully offline.
            Extracts IOCs, rule IDs, MITRE IDs from context via regex.
            Automatic fallback on any API error in tiers 1-4.

Environment variables  (put in .env or export in shell):
    OLLAMA_HOST          Ollama base URL          (default: http://localhost:11434)
    NEXLOG_MODEL   Ollama model name        (default: mistral)
    GROQ_API_KEY         Groq API key             (free: console.groq.com)
    GROQ_MODEL           Groq model override      (default: llama-3.3-70b-versatile)
    GEMINI_API_KEY       Google Gemini API key    (free: aistudio.google.com)
    GEMINI_MODEL         Gemini model override    (default: gemini-1.5-flash-latest)
    ANTHROPIC_API_KEY    Anthropic API key        (paid: console.anthropic.com)

Usage:
    from ai.llm_client import LLMClient

    llm = LLMClient()                  # auto-selects best available tier
    llm = LLMClient(model="llama3.1") # force Ollama with specific model
    llm = LLMClient(force_tier=2)     # force Groq
    llm = LLMClient(force_tier=3)     # template fallback only

    answer = llm.generate(
        query   = "What IPs are attacking the web server?",
        context = "Finding WEB-001 SQL Injection, source_ip=203.0.113.5..."
    )
    for chunk in llm.stream(query, context):
        print(chunk, end="", flush=True)
"""

import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Generator, Optional


# â”€â”€ Configuration  (read from environment â€” never hardcode) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_OLLAMA_BASE          = os.environ.get("OLLAMA_HOST",        "http://localhost:11434")
_DEFAULT_OLLAMA_MODEL = os.environ.get("NEXLOG_MODEL", "mistral")

_GROQ_KEY             = os.environ.get("GROQ_API_KEY",       "")
_GROQ_MODEL           = os.environ.get("GROQ_MODEL",         "llama-3.3-70b-versatile")

_GEMINI_KEY           = os.environ.get("GEMINI_API_KEY",     "")
_GEMINI_MODEL         = os.environ.get("GEMINI_MODEL",       "gemini-1.5-flash-latest")

_ANTHROPIC_KEY        = os.environ.get("ANTHROPIC_API_KEY",  "")
_ANTHROPIC_MODEL      = os.environ.get("ANTHROPIC_MODEL", "claude-3-5-haiku-20241022")

_MANAGED_AI_ENDPOINT  = os.environ.get("NEXLOG_MANAGED_AI_ENDPOINT", "")
_MANAGED_AI_TOKEN     = os.environ.get("NEXLOG_MANAGED_AI_TOKEN", "")
_OPENAI_COMPAT_MODEL  = os.environ.get("NEXLOG_OPENAI_COMPAT_MODEL", "gpt-4o-mini")

_TIMEOUT = 60


# â”€â”€ Shared system prompt â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

_SYSTEM_PROMPT = (
    "You are NexLog AI, an expert cybersecurity analyst assistant embedded in "
    "NexLog, an attacker-aware log analysis platform.\n\n"
    "You have been given security findings retrieved from a forensic investigation. "
    "Each finding includes: rule ID, severity, MITRE ATT&CK technique, source IP, "
    "hostname, trigger line (raw evidence), and risk score.\n\n"
    "Answer the analyst's question using ONLY the provided findings context.\n"
    "  - Lead with the direct answer\n"
    "  - Reference specific rule IDs, IPs, hostnames, and MITRE techniques\n"
    "  - Highlight CRITICAL and HIGH findings first\n"
    "  - If context is insufficient, say so clearly\n"
    "  - Do not speculate beyond the evidence\n\n"
    "Format: plain text paragraphs. No markdown headers. Under 300 words."
)


def _task_system_prompt(task: str = "case_question") -> str:
    """Return task-specific DFIR guidance while preserving safe evidence limits."""
    task_name = (task or "case_question").strip().lower()
    common = (
        "You are NexLog AI, a DFIR analyst assistant. Use only the provided case "
        "evidence. Separate facts from assumptions. Prefer citations such as "
        "finding IDs, rule names, source logs, timestamps, and MITRE IDs. If the "
        "evidence is insufficient, say exactly what is missing."
    )
    prompts = {
        "case_summary": common + " Produce an executive summary, affected assets, highest risks, and response priorities.",
        "finding_explanation": common + " Explain the selected finding, why it matters, likely impact, and validation steps.",
        "attack_story": common + " Build a concise attack narrative from timeline, findings, and graph chains.",
        "timeline_interpretation": common + " Explain event order, suspicious pivots, and gaps in the timeline.",
        "mitre_response_guidance": common + " Explain observed MITRE techniques and provide response guidance.",
        "executive_summary": common + " Write a leadership-ready summary with business impact and next actions.",
        "next_steps_checklist": common + " Produce a practical containment, eradication, and evidence-preservation checklist.",
        "ai_report_narrative": common + " Write a structured report narrative for the PDF report.",
    }
    return prompts.get(task_name, common)


def _build_prompt(query: str, context: str) -> str:
    return (
        f"SECURITY FINDINGS CONTEXT:\n{context}\n\n"
        f"ANALYST QUESTION: {query}\n\n"
        f"ANSWER:"
    )


def _provider_env_slots() -> list[dict[str, str]]:
    slots: list[dict[str, str]] = []
    for idx in (1, 2):
        provider = os.environ.get(f"NEXLOG_AI_PROVIDER_{idx}", "").strip().lower()
        key = os.environ.get(f"NEXLOG_AI_KEY_{idx}", "").strip()
        endpoint = os.environ.get(f"NEXLOG_AI_ENDPOINT_{idx}", "").strip()
        model = os.environ.get(f"NEXLOG_AI_MODEL_{idx}", "").strip()
        if provider or key or endpoint or model:
            slots.append({
                "provider": provider,
                "key": key,
                "endpoint": endpoint,
                "model": model,
            })
    return slots


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TIER 5 â€” Template synthesis  (stdlib, always works)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

def _template_synthesise(query: str, context: str) -> str:
    q = query.lower()

    ips        = list(dict.fromkeys(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', context)))
    rule_ids   = list(dict.fromkeys(re.findall(r'\b[A-Z]+-\d{3,}\b', context)))
    hostnames  = list(dict.fromkeys(re.findall(r'\bhostname[:\s]+(\S+)', context, re.IGNORECASE)))
    severities = list(dict.fromkeys(re.findall(r'\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b', context)))
    mitre_ids  = list(dict.fromkeys(re.findall(r'\bT\d{4}(?:\.\d{3})?\b', context)))
    risk_scores = [float(x) for x in re.findall(r'risk score\s+([\d]+\.?[\d]*)', context, re.IGNORECASE)]

    max_risk   = max(risk_scores, default=0.0)
    n_findings = context.count("Rule ")

    if any(w in q for w in ["ip", "address", "attacker", "source"]):
        if ips:
            answer = (f"The following {len(ips)} source IP"
                      f"{'s' if len(ips) > 1 else ''} "
                      f"{'are' if len(ips) > 1 else 'is'} active: "
                      f"{', '.join(ips[:10])}. ")
            if "CRITICAL" in severities:
                answer += "At least one CRITICAL finding originates from these addresses. "
        else:
            answer = "No specific source IP addresses found in the retrieved context. "

    elif any(w in q for w in ["severity", "critical", "high", "urgent", "worst", "serious"]):
        crit = severities.count("CRITICAL")
        high = severities.count("HIGH")
        answer = (f"The findings contain {crit} CRITICAL and {high} HIGH severity events. "
                  f"Maximum risk score: {max_risk:.1f}/10. ")
        if rule_ids:
            answer += f"Key rules triggered: {', '.join(rule_ids[:5])}. "

    elif any(w in q for w in ["mitre", "att&ck", "technique", "tactic"]):
        if mitre_ids:
            answer = (f"MITRE ATT&CK techniques observed: {', '.join(mitre_ids[:8])}. "
                      f"Total findings in context: {n_findings}. ")
        else:
            answer = "No MITRE technique IDs found in the current context. "

    elif any(w in q for w in ["host", "machine", "server", "target"]):
        if hostnames:
            answer = f"Hosts in the findings: {', '.join(hostnames[:8])}. "
        else:
            answer = "No specific hostnames identified in the retrieved findings. "

    elif any(w in q for w in ["count", "how many", "total", "number"]):
        breakdown = ", ".join(
            f"{s}: {severities.count(s)}"
            for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            if severities.count(s) > 0
        )
        answer = (f"{n_findings} finding record{'s' if n_findings != 1 else ''} retrieved. "
                  f"Severity breakdown: {breakdown}. "
                  f"Max risk score: {max_risk:.1f}/10. ")

    elif any(w in q for w in ["summary", "overview", "what happened", "describe"]):
        answer = f"Based on {n_findings} finding{'s' if n_findings != 1 else ''}: "
        if ips:       answer += f"Attacker IPs: {', '.join(ips[:3])}. "
        if hostnames: answer += f"Targeted hosts: {', '.join(hostnames[:3])}. "
        if "CRITICAL" in severities: answer += "CRITICAL severity events detected. "
        if mitre_ids: answer += f"MITRE techniques: {', '.join(mitre_ids[:4])}. "
        if max_risk >= 8:
            answer += f"Risk score {max_risk:.1f}/10 — immediate response recommended."

    else:
        answer = f"Based on {n_findings} finding{'s' if n_findings != 1 else ''}: "
        if rule_ids:     answer += f"Rules triggered: {', '.join(rule_ids[:5])}. "
        if ips:          answer += f"Source IPs: {', '.join(ips[:5])}. "
        if max_risk > 0: answer += f"Max risk score: {max_risk:.1f}/10. "
        answer += (
            "Tip: configure an AI provider slot, local Ollama, or a managed NexLog AI relay "
            "for deeper evidence-aware analysis."
        )

    return answer.strip()


# Thread-safe global cache for Ollama status
_ollama_cache_lock = threading.Lock()
_ollama_cache = {}  # key: (base_url, model) -> value: (is_available, timestamp)
_ollama_active_checks = set()  # set of (base_url, model) currently being probed in background


def _async_check_ollama(base_url: str, model: str):
    key = (base_url, model)
    try:
        req = urllib.request.Request(f"{base_url.rstrip('/')}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=1.5) as resp:
            data = json.loads(resp.read())
            models = [m["name"].split(":")[0] for m in data.get("models", [])]
            available = model in models or any(model in m for m in models)
    except Exception:
        available = False

    with _ollama_cache_lock:
        _ollama_cache[key] = (available, time.time())
        _ollama_active_checks.discard(key)


# Trigger eager check at module load time to prime the cache
try:
    _ollama_active_checks.add((_OLLAMA_BASE, _DEFAULT_OLLAMA_MODEL))
    _t = threading.Thread(target=_async_check_ollama, args=(_OLLAMA_BASE, _DEFAULT_OLLAMA_MODEL), daemon=True)
    _t.start()
except Exception:
    pass


# =========================================================================
# TIER 1 — Ollama  (local, private, zero cost)
# =========================================================================

class _OllamaClient:
    def __init__(self, base_url: str, model: str):
        self._base  = base_url.rstrip("/")
        self._model = model

    def is_available(self) -> bool:
        key = (self._base, self._model)
        now = time.time()

        with _ollama_cache_lock:
            cached = _ollama_cache.get(key)
            if cached:
                available, timestamp = cached
                if now - timestamp < 30.0:
                    return available
            else:
                available = False

            if key not in _ollama_active_checks:
                _ollama_active_checks.add(key)
                try:
                    t = threading.Thread(target=_async_check_ollama, args=(self._base, self._model), daemon=True)
                    t.start()
                except Exception:
                    _ollama_active_checks.discard(key)

            return available

    def generate(self, query: str, context: str, system: str = _SYSTEM_PROMPT,
                 max_tokens: int = 512, temperature: float = 0.2) -> str:
        payload = json.dumps({
            "model": self._model, "prompt": _build_prompt(query, context),
            "system": system, "stream": False,
            "options": {"num_predict": max_tokens, "temperature": temperature,
                        "top_p": 0.9, "repeat_penalty": 1.1},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self._base}/api/generate", data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read()).get("response", "").strip()

    def stream(self, query: str, context: str, system: str = _SYSTEM_PROMPT,
               max_tokens: int = 512, temperature: float = 0.2) -> Generator[str, None, None]:
        payload = json.dumps({
            "model": self._model, "prompt": _build_prompt(query, context),
            "system": system, "stream": True,
            "options": {"num_predict": max_tokens, "temperature": temperature},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self._base}/api/generate", data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                for line in resp:
                    if not line.strip():
                        continue
                    try:
                        chunk = json.loads(line)
                        token = chunk.get("response", "")
                        if token:
                            yield token
                        if chunk.get("done", False):
                            break
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            yield f"\n[Ollama stream error: {e}]"


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TIER 2 â€” Groq  (free, fast, OpenAI-compatible)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _GroqClient:
    """
    Free tier: 30 RPM, 6 000 TPM.
    Get key at https://console.groq.com (no credit card required).
    """
    _API_URL = "https://api.groq.com/openai/v1/chat/completions"

    def __init__(self, api_key: str, model: str = _GROQ_MODEL):
        self._key   = api_key
        self._model = model

    def generate(self, query: str, context: str, system: str = _SYSTEM_PROMPT,
                 max_tokens: int = 512, temperature: float = 0.2) -> str:
        payload = json.dumps({
            "model": self._model, "max_tokens": max_tokens, "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user",   "content": _build_prompt(query, context)},
            ],
        }).encode("utf-8")
        req = urllib.request.Request(
            self._API_URL, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "Authorization": f"Bearer {self._key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read())["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Groq API error {e.code}: {body[:200]}")

    def stream(self, query: str, context: str, **kwargs) -> Generator[str, None, None]:
        yield self.generate(query, context, **kwargs)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TIER 3 â€” Google Gemini  (free, generous daily quota)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _GeminiClient:
    """
    Free tier: 15 RPM, 1 M tokens/day.
    Get key at https://aistudio.google.com (Google account, no credit card).
    """
    _API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

    def __init__(self, api_key: str, model: str = _GEMINI_MODEL):
        self._key   = api_key
        self._model = model

    def generate(self, query: str, context: str, system: str = _SYSTEM_PROMPT,
                 max_tokens: int = 512, temperature: float = 0.2) -> str:
        url = f"{self._API_BASE}/{self._model}:generateContent?key={self._key}"
        payload = json.dumps({
            "systemInstruction": {"parts": [{"text": system}]},
            "contents": [{"parts": [{"text": _build_prompt(query, context)}]}],
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": temperature},
        }).encode("utf-8")
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                data = json.loads(resp.read())
                return data["candidates"][0]["content"]["parts"][0]["text"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Gemini API error {e.code}: {body[:200]}")

    def stream(self, query: str, context: str, **kwargs) -> Generator[str, None, None]:
        yield self.generate(query, context, **kwargs)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# TIER 4 â€” Anthropic Claude  (paid â€” env var only, NEVER hardcode)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _AnthropicClient:
    _API_URL = "https://api.anthropic.com/v1/messages"

    def __init__(self, api_key: str, model: str = _ANTHROPIC_MODEL):
        self._key = api_key
        self._model = model or _ANTHROPIC_MODEL

    def generate(self, query: str, context: str, system: str = _SYSTEM_PROMPT,
                 max_tokens: int = 512, temperature: float = 0.2) -> str:
        payload = json.dumps({
            "model": self._model, "max_tokens": max_tokens, "system": system,
            "messages": [{"role": "user", "content": _build_prompt(query, context)}],
        }).encode("utf-8")
        req = urllib.request.Request(
            self._API_URL, data=payload, method="POST",
            headers={"Content-Type": "application/json",
                     "x-api-key": self._key, "anthropic-version": "2023-06-01"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read())["content"][0]["text"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Anthropic API error {e.code}: {body[:200]}")

    def stream(self, query: str, context: str, **kwargs) -> Generator[str, None, None]:
        yield self.generate(query, context, **kwargs)


# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
# PUBLIC LLM CLIENT  (Ollama â†’ Groq â†’ Gemini â†’ Anthropic â†’ Template)
# â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

class _OpenAICompatibleClient:
    """Generic chat-completions client for custom/OpenAI-compatible providers."""

    def __init__(self, api_key: str, endpoint: str, model: str):
        self._key = api_key
        self._endpoint = endpoint.rstrip("/")
        self._model = model or _OPENAI_COMPAT_MODEL

    def _api_url(self) -> str:
        if self._endpoint.endswith("/chat/completions"):
            return self._endpoint
        if self._endpoint.endswith("/v1"):
            return f"{self._endpoint}/chat/completions"
        return f"{self._endpoint}/v1/chat/completions"

    def generate(self, query: str, context: str, system: str = _SYSTEM_PROMPT,
                 max_tokens: int = 512, temperature: float = 0.2) -> str:
        payload = json.dumps({
            "model": self._model, "max_tokens": max_tokens, "temperature": temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": _build_prompt(query, context)},
            ],
        }).encode("utf-8")
        req = urllib.request.Request(
            self._api_url(), data=payload, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {self._key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return json.loads(resp.read())["choices"][0]["message"]["content"].strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"OpenAI-compatible API error {e.code}: {body[:200]}")

    def stream(self, query: str, context: str, **kwargs) -> Generator[str, None, None]:
        yield self.generate(query, context, **kwargs)


class _ManagedAIClient:
    """NexLog managed relay client. Raw provider keys stay on the relay server."""

    def __init__(self, endpoint: str, token: str):
        self._endpoint = endpoint.rstrip("/")
        self._token = token

    def generate(self, query: str, context: str, system: str = _SYSTEM_PROMPT,
                 max_tokens: int = 512, temperature: float = 0.2) -> str:
        payload = json.dumps({
            "query": query,
            "context": context,
            "system": system,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "client": "nexlog",
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        req = urllib.request.Request(self._endpoint, data=payload, method="POST", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                data = json.loads(resp.read())
                return str(
                    data.get("answer")
                    or data.get("text")
                    or data.get("content")
                    or data.get("message")
                    or ""
                ).strip()
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Managed NexLog AI error {e.code}: {body[:200]}")

    def stream(self, query: str, context: str, **kwargs) -> Generator[str, None, None]:
        yield self.generate(query, context, **kwargs)


class LLMClient:
    """
    Auto-selecting LLM client for NexLog.

    Compatibility tier numbering (kept for existing API/UI behavior):
      1. Ollama
      2. Groq
      3. Template synthesis (offline fallback)
      4. Anthropic
      5. Gemini

    Args:
        model:         Ollama model (default: NEXLOG_MODEL env var or "mistral")
        ollama_url:    Ollama URL (default: OLLAMA_HOST env var)
        groq_key:      Groq key (overrides GROQ_API_KEY env var)
        gemini_key:    Gemini key (overrides GEMINI_API_KEY env var)
        anthropic_key: Anthropic key (overrides ANTHROPIC_API_KEY env var)
        force_tier:    Force specific tier 1-5 (useful for testing)
        timeout:       HTTP request timeout in seconds
    """

    def __init__(
        self,
        model:          str           = _DEFAULT_OLLAMA_MODEL,
        ollama_url:     str           = _OLLAMA_BASE,
        groq_key:       str           = "",
        gemini_key:     str           = "",
        anthropic_key:  str           = "",
        force_tier:     Optional[int] = None,
        timeout:        int           = _TIMEOUT,
    ):
        global _TIMEOUT
        _TIMEOUT         = timeout
        self._tier       = 0
        self._tier_name  = ""
        self._impl       = None
        self._model_name = model

        def _activate_template() -> None:
            self._impl = None
            self._tier = 3
            self._tier_name = "template-synthesis"

        if force_tier == 3:
            _activate_template()
            return

        groq_model = os.environ.get("GROQ_MODEL", _GROQ_MODEL)
        gemini_model = os.environ.get("GEMINI_MODEL", _GEMINI_MODEL)
        anthropic_model = os.environ.get("ANTHROPIC_MODEL", _ANTHROPIC_MODEL)

        def _activate_provider_slot(slot: dict[str, str]) -> bool:
            provider = (slot.get("provider") or "").strip().lower().replace("_", "-")
            key = slot.get("key") or ""
            endpoint = slot.get("endpoint") or ""
            slot_model = slot.get("model") or ""
            if provider in {"claude", "anthropic", "anthropic-claude"} and key:
                self._impl = _AnthropicClient(key, slot_model or anthropic_model)
                self._tier = 4
                self._tier_name = f"anthropic:{anthropic_model}"
                return True
            if provider == "groq" and key:
                self._impl = _GroqClient(key, slot_model or groq_model)
                self._tier = 2
                self._tier_name = f"groq:{slot_model or groq_model}"
                return True
            if provider == "gemini" and key:
                self._impl = _GeminiClient(key, slot_model or gemini_model)
                self._tier = 5
                self._tier_name = f"gemini:{slot_model or gemini_model}"
                return True
            if provider in {"ollama", "local"}:
                client = _OllamaClient(endpoint or ollama_url, slot_model or model)
                if client.is_available():
                    self._impl = client
                    self._tier = 1
                    self._tier_name = f"ollama:{slot_model or model}"
                    return True
            if provider in {"openai-compatible", "openai", "custom"} and key and endpoint:
                self._impl = _OpenAICompatibleClient(key, endpoint, slot_model)
                self._tier = 6
                self._tier_name = f"{provider}:{slot_model or _OPENAI_COMPAT_MODEL}"
                return True
            return False

        provider_slots = _provider_env_slots()
        if not force_tier and provider_slots:
            for slot in provider_slots:
                if _activate_provider_slot(slot):
                    break

        # Auto-selection keeps compatibility when no provider slots are configured.
        tiers_to_try = [] if self._impl is not None else ([force_tier] if force_tier else [1, 2, 4, 5])
        for tier in tiers_to_try:
            if tier == 1:
                c = _OllamaClient(ollama_url, model)
                if c.is_available():
                    self._impl, self._tier, self._tier_name = c, 1, f"ollama:{model}"
                    break

            elif tier == 2:
                key = groq_key or _GROQ_KEY
                if key:
                    self._impl      = _GroqClient(key, groq_model)
                    self._tier      = 2
                    self._tier_name = f"groq:{groq_model}"
                    break

            elif tier == 4:
                key = anthropic_key or _ANTHROPIC_KEY
                if key:
                    self._impl      = _AnthropicClient(key, anthropic_model)
                    self._tier      = 4
                    self._tier_name = f"anthropic:{anthropic_model}"
                    break

            elif tier == 5:
                key = gemini_key or _GEMINI_KEY
                if key:
                    self._impl      = _GeminiClient(key, gemini_model)
                    self._tier      = 5
                    self._tier_name = f"gemini:{gemini_model}"
                    break

        managed_endpoint = os.environ.get("NEXLOG_MANAGED_AI_ENDPOINT", _MANAGED_AI_ENDPOINT).strip()
        managed_token = os.environ.get("NEXLOG_MANAGED_AI_TOKEN", _MANAGED_AI_TOKEN).strip()
        if self._impl is None and not force_tier and managed_endpoint:
            self._impl = _ManagedAIClient(managed_endpoint, managed_token)
            self._tier = 7
            self._tier_name = "managed-nexlog-ai"
        if self._impl is None:
            _activate_template()

    @property
    def tier(self) -> int:
        return self._tier

    @property
    def tier_name(self) -> str:
        return self._tier_name

    def generate(self, query: str, context: str,
                 max_tokens: int = 512, temperature: float = 0.2,
                 task: str = "case_question") -> str:
        if self._tier == 3 or self._impl is None:
            return _template_synthesise(query, context)
        try:
            return self._impl.generate(query, context,
                                       system=_task_system_prompt(task),
                                       max_tokens=max_tokens, temperature=temperature)
        except Exception as e:
            return (f"[LLM error ({self._tier_name}): {e}. Falling back to template.]\n\n"
                    + _template_synthesise(query, context))

    def stream(self, query: str, context: str,
               max_tokens: int = 512, temperature: float = 0.2,
               task: str = "case_question") -> Generator[str, None, None]:
        if self._tier == 3 or self._impl is None:
            yield _template_synthesise(query, context)
            return
        try:
            yield from self._impl.stream(query, context,
                                         system=_task_system_prompt(task),
                                         max_tokens=max_tokens, temperature=temperature)
        except Exception as e:
            yield f"[LLM error ({self._tier_name}): {e}]\n\n"
            yield _template_synthesise(query, context)

    def __repr__(self) -> str:
        return f"<LLMClient tier={self._tier} ({self._tier_name})>"
