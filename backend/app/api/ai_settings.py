"""User-configurable AI provider settings.

API keys are accepted here and stored in the database, but are never returned
by the API — only a masked representation.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.ai.provider import (
    AUTO_PRIORITY,
    PROVIDERS,
    get_stored,
    mask_secret,
    provider_config,
    set_stored,
)
from app.config import settings
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


@router.put("/api/settings")
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
