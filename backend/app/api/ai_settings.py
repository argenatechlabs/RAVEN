"""User-configurable AI provider settings.

API keys are accepted here and stored in the database, but are never returned
by the API — only a masked representation.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai.provider import (
    AUTO_PRIORITY,
    PROVIDERS,
    build_provider,
    get_stored,
    mask_secret,
    provider_config,
    set_stored,
)
from app.config import settings
from app.core.security import api_write_limit
from app.database import get_db

router = APIRouter()


class SettingsUpdate(BaseModel):
    provider: Optional[str] = Field(
        None, description="openai | anthropic | gemini | xai | openrouter | "
                          "deepseek | mistral | groq | ollama | custom | local | auto"
    )
    model: Optional[str] = Field(None, description="örn. grok-3, gemini-2.5-flash")
    base_url: Optional[str] = Field(None, description="OpenAI uyumlu özel uç nokta")
    api_key: Optional[str] = Field(None, description="Boş gönderilirse anahtar temizlenir")


@router.get("/api/providers")
def list_providers(db: Session = Depends(get_db)) -> Dict[str, Any]:
    items = []
    for pid, spec in PROVIDERS.items():
        cfg = provider_config(db, settings, pid)
        items.append(
            {
                "id": pid,
                "label": spec.label,
                "description": spec.description,
                "base_url": cfg.get("base_url"),
                "default_model": spec.default_model,
                "key_env": spec.key_env,
                "requires_key": spec.requires_key,
                "openai_compatible": spec.openai_compatible,
                "docs": spec.docs,
                "configured": cfg.get("configured", False),
            }
        )
    return {"items": items, "auto_priority": AUTO_PRIORITY}


@router.get("/api/settings")
def get_settings(db: Session = Depends(get_db)) -> Dict[str, Any]:
    current = get_stored(db, "ai.provider") or settings.ai_provider or "auto"
    providers: Dict[str, Any] = {}
    for pid in PROVIDERS:
        cfg = provider_config(db, settings, pid)
        providers[pid] = {
            "model": cfg.get("model"),
            "base_url": cfg.get("base_url"),
            "api_key": mask_secret(cfg.get("api_key")),
            "api_key_set": cfg.get("api_key_set", False),
            "configured": cfg.get("configured", False),
        }
    return {
        "provider": current,
        "providers": providers,
        "auto_priority": AUTO_PRIORITY,
    }


@router.put("/api/settings", dependencies=[Depends(api_write_limit)])
def update_settings(payload: SettingsUpdate, db: Session = Depends(get_db)) -> Dict[str, Any]:
    if payload.provider is not None:
        provider = payload.provider.strip().lower()
        if provider not in PROVIDERS and provider != "auto":
            raise HTTPException(status_code=400, detail="Bilinmeyen AI saglayicisi")
        set_stored(db, "ai.provider", provider)
        target = provider
    else:
        target = (get_stored(db, "ai.provider") or settings.ai_provider or "auto").lower()

    if target not in ("auto", "local"):
        if payload.model is not None:
            set_stored(db, f"ai.providers.{target}.model", payload.model.strip() or None)
        if payload.base_url is not None:
            set_stored(db, f"ai.providers.{target}.base_url", payload.base_url.strip() or None)
        if payload.api_key is not None:
            set_stored(
                db, f"ai.providers.{target}.api_key",
                payload.api_key.strip() or None, is_secret=True,
            )
    db.commit()
    return get_settings(db)


@router.post("/api/providers/{provider_id}/test", dependencies=[Depends(api_write_limit)])
def test_provider(provider_id: str, db: Session = Depends(get_db)) -> Dict[str, Any]:
    """Send a one-line prompt to a provider to verify the stored API key.

    Uses the configuration already saved for ``provider_id`` (database first,
    then environment); it never accepts a key from the request body so a secret
    cannot be passed through this endpoint.
    """
    pid = provider_id.strip().lower()
    if pid == "local":
        return {
            "ok": True,
            "provider": pid,
            "model": "local",
            "latency_ms": 0,
            "reply": "Yerel analiz motoru her zaman kullanilabilir (API anahtari gerekmez).",
        }

    spec = PROVIDERS.get(pid)
    if spec is None:
        raise HTTPException(status_code=404, detail="Bilinmeyen AI saglayicisi")

    cfg = provider_config(db, settings, pid)
    if spec.requires_key and not cfg.get("api_key"):
        raise HTTPException(
            status_code=400,
            detail=f"{spec.label} icin API anahtari gerekli; once anahtari kaydedin.",
        )

    provider = build_provider(pid, db, settings)
    if provider is None:
        raise HTTPException(
            status_code=400,
            detail=f"{spec.label} yapilandirilamadi (anahtar/model/URL eksik).",
        )

    started = time.perf_counter()
    try:
        reply = provider.complete(
            "Sen RAVEN guvenlik araci icin bir test asistanisin.",
            "Yanit olarak yalnizca su metni yaz: RAVEN-OK",
            timeout=30,
        )
    except Exception as exc:  # noqa: BLE001 - surface any provider/HTTP failure
        raise HTTPException(
            status_code=502, detail=f"{spec.label} baglanti hatasi: {exc}"
        ) from exc

    latency_ms = int((time.perf_counter() - started) * 1000)
    reply = (reply or "").strip()
    if not reply:
        raise HTTPException(status_code=502, detail=f"{spec.label} bos yanit dondurdu.")

    return {
        "ok": True,
        "provider": pid,
        "model": provider.model,
        "base_url": cfg.get("base_url"),
        "latency_ms": latency_ms,
        "reply": reply[:200],
    }
