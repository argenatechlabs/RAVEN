"""AI provider abstraction with a pluggable registry.

Supported providers:
    openai, anthropic (Claude), gemini, xai (Grok), openrouter,
    deepseek, mistral, groq, ollama (local), custom (any OpenAI-compatible API)
    local (deterministic offline analysis)

Configuration resolution order for a provider:
    per-scan override -> database (user settings) -> environment -> preset default.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx
from sqlalchemy.orm import Session

from app.config import Settings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ProviderSpec:
    id: str
    label: str
    description: str
    base_url: Optional[str] = None
    default_model: str = ""
    key_env: Optional[str] = None
    requires_key: bool = True
    openai_compatible: bool = True
    docs: str = ""


PROVIDERS: Dict[str, ProviderSpec] = {
    p.id: p
    for p in [
        ProviderSpec(
            id="openai", label="OpenAI (GPT)",
            description="GPT-4o / GPT-4o-mini ve diğer OpenAI modelleri.",
            base_url="https://api.openai.com/v1", default_model="gpt-4o-mini",
            key_env="OPENAI_API_KEY", docs="https://platform.openai.com/api-keys",
        ),
        ProviderSpec(
            id="anthropic", label="Anthropic (Claude)",
            description="Claude model ailesi (native Messages API).",
            base_url="https://api.anthropic.com", default_model="claude-sonnet-4-5",
            key_env="ANTHROPIC_API_KEY", openai_compatible=False,
            docs="https://console.anthropic.com/settings/keys",
        ),
        ProviderSpec(
            id="gemini", label="Google Gemini",
            description="Gemini 2.5 Flash / Pro (OpenAI uyumlu uç nokta).",
            base_url="https://generativelanguage.googleapis.com/v1beta/openai",
            default_model="gemini-2.5-flash", key_env="GEMINI_API_KEY",
            docs="https://aistudio.google.com/app/apikey",
        ),
        ProviderSpec(
            id="xai", label="xAI (Grok)",
            description="Grok modelleri — x.ai OpenAI uyumlu API.",
            base_url="https://api.x.ai/v1", default_model="grok-3",
            key_env="XAI_API_KEY", docs="https://x.ai/api",
        ),
        ProviderSpec(
            id="openrouter", label="OpenRouter",
            description="Yüzlerce modele tek noktadan erişim (opsiyonel anahtar).",
            base_url="https://openrouter.ai/api/v1",
            default_model="anthropic/claude-sonnet-4.5", key_env="OPENROUTER_API_KEY",
            requires_key=False, docs="https://openrouter.ai/keys",
        ),
        ProviderSpec(
            id="deepseek", label="DeepSeek",
            description="DeepSeek-Chat / Reasoner.",
            base_url="https://api.deepseek.com/v1", default_model="deepseek-chat",
            key_env="DEEPSEEK_API_KEY", docs="https://platform.deepseek.com/api_keys",
        ),
        ProviderSpec(
            id="mistral", label="Mistral AI",
            description="Mistral Large / Medium / Small.",
            base_url="https://api.mistral.ai/v1", default_model="mistral-large-latest",
            key_env="MISTRAL_API_KEY", docs="https://console.mistral.ai/api-keys",
        ),
        ProviderSpec(
            id="groq", label="Groq",
            description="Son derece hızlı Llama / Mistral Inference.",
            base_url="https://api.groq.com/openai/v1",
            default_model="llama-3.3-70b-versatile", key_env="GROQ_API_KEY",
            docs="https://console.groq.com/keys",
        ),
        ProviderSpec(
            id="ollama", label="Ollama (Yerel)",
            description="Makinelenizde veya ağda çalışan Ollama modelleri.",
            base_url="http://ollama:11434", default_model="llama3.1",
            key_env=None, requires_key=False, openai_compatible=False,
            docs="https://ollama.com",
        ),
        ProviderSpec(
            id="custom", label="Özel (OpenAI uyumlu)",
            description="Herhangi bir OpenAI uyumlu API (Together, LocalAI, v.s.).",
            base_url=None, default_model="gpt-4o-mini", key_env="CUSTOM_API_KEY",
            docs="",
        ),
    ]
}

# Priority order used by the `auto` selector.
AUTO_PRIORITY = [
    "openai", "anthropic", "gemini", "xai", "openrouter",
    "groq", "deepseek", "mistral", "ollama",
]


# ---------------------------------------------------------------------------
# Provider implementations
# ---------------------------------------------------------------------------
class Provider(ABC):
    name = "abstract"

    def __init__(self, model: str = "") -> None:
        self.model = model

    @abstractmethod
    def complete(self, system: str, user: str, timeout: int = 90) -> str:
        ...


class OpenAICompatibleProvider(Provider):
    """Works for OpenAI, xAI, Gemini, OpenRouter, DeepSeek, Mistral, Groq, custom."""

    def __init__(
        self,
        model: str,
        api_key: str,
        base_url: str,
        provider_id: str = "openai",
        timeout: int = 90,
        extra_headers: Optional[Dict[str, str]] = None,
    ) -> None:
        super().__init__(model)
        from openai import OpenAI

        self.name = provider_id
        kwargs: Dict[str, Any] = {
            "api_key": api_key or "not-needed",
            "base_url": base_url,
            "timeout": float(timeout),
            "max_retries": 1,
        }
        if extra_headers:
            kwargs["default_headers"] = extra_headers
        self.client = OpenAI(**kwargs)

    def complete(self, system: str, user: str, timeout: int = 90) -> str:
        self.client.timeout = float(timeout)
        resp = self.client.chat.completions.create(
            model=self.model,
            temperature=0.2,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""


class AnthropicProvider(Provider):
    """Native Claude Messages API (no extra SDK dependency)."""

    def __init__(
        self, model: str, api_key: str, base_url: str = "https://api.anthropic.com",
        provider_id: str = "anthropic", timeout: int = 90,
    ) -> None:
        super().__init__(model)
        self.name = provider_id
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        try:
            resp = httpx.get(
                f"{self.base_url}/v1/models",
                headers={"x-api-key": self.api_key, "anthropic-version": "2023-06-01"},
                timeout=5.0,
            )
            return resp.status_code in (200, 401, 403)
        except httpx.HTTPError:
            return False

    def complete(self, system: str, user: str, timeout: int = 90) -> str:
        resp = httpx.post(
            f"{self.base_url}/v1/messages",
            headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": self.model,
                "max_tokens": 2048,
                "system": system,
                "messages": [{"role": "user", "content": user}],
            },
            timeout=float(timeout),
        )
        resp.raise_for_status()
        data = resp.json()
        parts = [block.get("text", "") for block in data.get("content", [])
                 if isinstance(block, dict) and block.get("type") == "text"]
        return "".join(parts)


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self, model: str = "llama3.1", base_url: str = "http://ollama:11434") -> None:
        super().__init__(model)
        self.base_url = base_url.rstrip("/")

    def is_available(self) -> bool:
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=4.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def complete(self, system: str, user: str, timeout: int = 90) -> str:
        resp = httpx.post(
            f"{self.base_url}/api/generate",
            json={
                "model": self.model,
                "system": system,
                "prompt": user,
                "stream": False,
                "options": {"temperature": 0.2},
            },
            timeout=float(timeout),
        )
        resp.raise_for_status()
        return resp.json().get("response", "")


class LocalProvider(Provider):
    """Deterministic offline analysis — always available, never calls a model."""

    name = "local"

    def complete(self, system: str, user: str, timeout: int = 90) -> str:  # pragma: no cover
        return ""


# ---------------------------------------------------------------------------
# Persisted user configuration (database)
# ---------------------------------------------------------------------------
def get_stored(db: Optional[Session], key: str, default: Optional[str] = None) -> Optional[str]:
    if db is None:
        return default
    from app.models import Setting

    row = db.get(Setting, key)
    if row is None or row.value is None:
        return default
    return row.value


def set_stored(db: Session, key: str, value: Optional[str], is_secret: bool = False) -> None:
    from app.models import Setting

    row = db.get(Setting, key)
    if row is None:
        row = Setting(key=key)
        db.add(row)
    row.value = value
    row.is_secret = is_secret


def _env_key(settings: Settings, provider_id: str) -> str:
    return getattr(settings, f"{provider_id}_api_key", "") or ""


def _env_model(settings: Settings, provider_id: str) -> str:
    return getattr(settings, f"{provider_id}_model", "") or ""


def _env_base_url(settings: Settings, provider_id: str) -> Optional[str]:
    return getattr(settings, f"{provider_id}_base_url", None) or None


def provider_config(
    db: Optional[Session], settings: Settings, provider_id: str
) -> Dict[str, Any]:
    """Merge env + database into a concrete configuration for one provider."""
    spec = PROVIDERS.get(provider_id)
    if spec is None:
        return {}
    stored_key = get_stored(db, f"ai.providers.{provider_id}.api_key")
    stored_model = get_stored(db, f"ai.providers.{provider_id}.model")
    stored_base = get_stored(db, f"ai.providers.{provider_id}.base_url")

    api_key = stored_key or _env_key(settings, provider_id)
    model = stored_model or _env_model(settings, provider_id) or spec.default_model
    base_url = stored_base or _env_base_url(settings, provider_id) or spec.base_url
    configured = bool(api_key) if spec.requires_key else True
    if provider_id == "ollama":
        configured = True  # availability is checked separately
    if provider_id == "custom":
        configured = bool(api_key) and bool(base_url)
    return {
        "id": provider_id,
        "configured": configured,
        "api_key": api_key,
        "api_key_set": bool(api_key),
        "model": model,
        "base_url": base_url,
    }


def is_configured(db: Optional[Session], settings: Settings, provider_id: str) -> bool:
    return bool(provider_config(db, settings, provider_id).get("configured"))


def build_provider(
    provider_id: str,
    db: Optional[Session],
    settings: Settings,
    model: Optional[str] = None,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
) -> Optional[Provider]:
    """Instantiate a provider, or return None when it is not configured."""
    spec = PROVIDERS.get(provider_id)
    if spec is None:
        return None
    cfg = provider_config(db, settings, provider_id)
    chosen_model = model or cfg.get("model") or spec.default_model
    chosen_base = base_url or cfg.get("base_url") or spec.base_url
    chosen_key = api_key if api_key is not None else cfg.get("api_key")

    if spec.requires_key and not chosen_key:
        return None
    if provider_id == "custom" and not chosen_base:
        return None
    if provider_id == "ollama":
        provider = OllamaProvider(model=chosen_model, base_url=chosen_base or spec.base_url)
        return provider if provider.is_available() else None
    if provider_id == "anthropic":
        if not chosen_key:
            return None
        return AnthropicProvider(
            model=chosen_model, api_key=chosen_key,
            base_url=chosen_base or spec.base_url, provider_id=provider_id,
        )
    headers = None
    if provider_id == "openrouter":
        headers = {"HTTP-Referer": "https://github.com/argenatechlabs/RAVEN",
                   "X-Title": "RAVEN"}
    return OpenAICompatibleProvider(
        model=chosen_model,
        api_key=chosen_key or "",
        base_url=chosen_base or spec.base_url or "https://api.openai.com/v1",
        provider_id=provider_id,
        timeout=settings.ai_timeout,
        extra_headers=headers,
    )


def resolve_provider(
    settings: Settings,
    logger=None,
    db: Optional[Session] = None,
    provider_id: Optional[str] = None,
) -> Provider:
    """Pick the configured provider.

    Order: per-scan override -> saved user selection -> env ``AI_PROVIDER`` ->
    ``auto`` (first configured provider, Ollama if reachable, else local).
    """
    chosen = (
        provider_id
        or get_stored(db, "ai.provider")
        or settings.ai_provider
        or "auto"
    ).lower()

    if chosen == "auto":
        for candidate in AUTO_PRIORITY:
            provider = build_provider(candidate, db, settings)
            if provider is not None:
                if logger:
                    logger.info(f"AI saglayicisi (auto): {candidate}")
                return provider
        if logger:
            logger.info("AI saglayicisi (auto): local")
        return LocalProvider()

    if chosen == "local":
        return LocalProvider()

    provider = build_provider(chosen, db, settings)
    if provider is None:
        if logger:
            logger.warning(
                f"{chosen} AI saglayicasi yapilandirilmamis (API anahtari/Model eksik); "
                "yerel analiz kullanilacak"
            )
        return LocalProvider()
    if logger:
        logger.info(f"AI saglayicisi: {chosen} ({provider.model})")
    return provider


def mask_secret(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    if len(value) <= 8:
        return "••••"
    return f"{value[:4]}••••{value[-4:]}"
