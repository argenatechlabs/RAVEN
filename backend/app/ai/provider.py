"""AI provider abstraction: OpenAI primary, Ollama fallback, local last."""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Optional

import httpx

from app.config import Settings


class Provider(ABC):
    name = "abstract"

    @abstractmethod
    def complete(self, system: str, user: str, timeout: int = 90) -> str:
        ...


class OpenAIProvider(Provider):
    name = "openai"

    def __init__(self, settings: Settings) -> None:
        from openai import OpenAI

        self.model = settings.openai_model
        kwargs = {"api_key": settings.openai_api_key, "timeout": timeout_default(settings.ai_timeout)}
        if settings.openai_base_url:
            kwargs["base_url"] = settings.openai_base_url
        self.client = OpenAI(**kwargs)

    def complete(self, system: str, user: str, timeout: int = 90) -> str:
        self.client.timeout = timeout
        resp = self.client.chat.completions.create(
            model=self.model,
            temperature=0.2,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        return resp.choices[0].message.content or ""


class OllamaProvider(Provider):
    name = "ollama"

    def __init__(self, settings: Settings) -> None:
        self.url = settings.ollama_url.rstrip("/")
        self.model = settings.ollama_model

    def is_available(self) -> bool:
        try:
            resp = httpx.get(f"{self.url}/api/tags", timeout=4.0)
            return resp.status_code == 200
        except httpx.HTTPError:
            return False

    def complete(self, system: str, user: str, timeout: int = 90) -> str:
        resp = httpx.post(
            f"{self.url}/api/generate",
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


def timeout_default(value: int) -> float:
    return float(value)


def resolve_provider(settings: Settings, logger=None) -> Provider:
    """Pick the best configured provider.

    auto: OpenAI key -> Ollama reachable -> local.
    """
    choice = (settings.ai_provider or "auto").lower()
    if choice == "local":
        return LocalProvider()
    if choice in ("openai", "auto") and settings.openai_api_key:
        try:
            return OpenAIProvider(settings)
        except Exception as exc:  # pragma: no cover - misconfiguration
            if logger:
                logger.warning(f"OpenAI başlatılamadı: {exc}")
    if choice in ("ollama", "auto"):
        ollama = OllamaProvider(settings)
        if choice == "ollama" or ollama.is_available():
            return ollama
    return LocalProvider()
