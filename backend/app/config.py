"""Application configuration loaded from environment variables.

All settings are optional so the service can boot with defaults; production
values are injected through docker-compose / .env.
"""
from __future__ import annotations

import json
from functools import lru_cache
from typing import Dict, List, Optional

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    app_name: str = "RAVEN - Autonomous AI Pentester"
    app_env: str = "production"
    api_prefix: str = "/api"

    # --- Database -----------------------------------------------------------
    # Compose overrides this with the postgres service. SQLite keeps local
    # development and the test-suite dependency free.
    database_url: str = "sqlite:///./data/raven.db"

    # --- Queue / cache ------------------------------------------------------
    redis_url: str = "redis://redis:6379/0"
    scan_queue_key: str = "raven:scan-queue"
    worker_poll_interval: float = 1.0
    # When Redis is unreachable scans are executed in-process instead.
    allow_inline_scans: bool = True

    # --- AI providers -------------------------------------------------------
    # auto = first configured provider (OpenAI, Claude, Gemini, Grok, ...),
    # otherwise Ollama if reachable, otherwise the deterministic local engine.
    ai_provider: str = "auto"  # auto | openai | anthropic | gemini | xai | ... | ollama | local
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: Optional[str] = None
    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-5"
    anthropic_base_url: Optional[str] = None
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.5-flash"
    gemini_base_url: Optional[str] = None
    xai_api_key: str = ""
    xai_model: str = "grok-3"
    xai_base_url: Optional[str] = None
    openrouter_api_key: str = ""
    openrouter_model: str = "anthropic/claude-sonnet-4.5"
    openrouter_base_url: Optional[str] = None
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: Optional[str] = None
    mistral_api_key: str = ""
    mistral_model: str = "mistral-large-latest"
    mistral_base_url: Optional[str] = None
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    groq_base_url: Optional[str] = None
    custom_api_key: str = ""
    custom_model: str = "gpt-4o-mini"
    custom_base_url: Optional[str] = None
    ollama_url: str = "http://ollama:11434"
    ollama_model: str = "llama3.1"
    ai_timeout: int = 90
    ai_max_findings_per_request: int = 25

    # --- Scanners -----------------------------------------------------------
    # Directory that holds the embedded scanner binaries (Docker image puts
    # them in /usr/local/bin). PATH is searched as a fallback.
    scanner_bin_dir: str = "/usr/local/bin"
    scanner_timeout: int = 1200
    request_rate_limit: int = 10  # max requests / second against a target
    max_subdomains: int = 500
    max_endpoints: int = 5000
    max_js_files: int = 200
    # The built-in Python engine probes these many alive hosts (kept small so a
    # broad scan never turns into an unbounded HTTP storm).
    builtin_max_hosts: int = 15
    # Requests per host spent on parameter probing (keeps fast scans bounded).
    builtin_param_budget: int = 40
    # How many scan pipelines may run at the same time.
    scan_concurrency: int = 1
    nuclei_severities: str = "critical,high,medium"
    nuclei_templates_dir: Optional[str] = None
    # Optional authenticated scanning: JSON header object and/or a cookie
    # string, e.g. SCAN_HEADERS='{"X-Auth":"abc"}' SCAN_COOKIE='session=xyz'.
    scan_headers: str = ""
    scan_cookie: str = ""

    # --- Demo / offline mode ------------------------------------------------
    # Generates a realistic synthetic target so the UI, AI triage, reporting
    # and the live-log pipeline can be exercised without external tools.
    demo_mode: bool = False

    # --- Storage ------------------------------------------------------------
    data_dir: str = "./data"

    # --- HTTP / API hardening ----------------------------------------------
    cors_origins: List[str] = ["*"]
    host: str = "0.0.0.0"
    port: int = 8000
    # Optional bearer/X-API-Key gate. Empty = open (single-user local mode).
    api_key: str = ""
    # Per-client sliding-window limits (requests, seconds).
    api_rate_limit: bool = True
    api_rate_limit_rpm: int = 120
    scan_rate_limit_rpm: int = 20
    trust_proxy: bool = False
    hsts_header: bool = False

    @property
    def sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def severity_list(self) -> List[str]:
        return [s.strip() for s in self.nuclei_severities.split(",") if s.strip()]

    @property
    def header_map(self) -> Dict[str, str]:
        """Parse ``SCAN_HEADERS`` (JSON object) into a header dict."""
        if not self.scan_headers.strip():
            return {}
        try:
            data = json.loads(self.scan_headers)
        except (ValueError, TypeError):
            return {}
        if not isinstance(data, dict):
            return {}
        headers = {str(k): str(v) for k, v in data.items() if v is not None}
        if self.scan_cookie.strip():
            headers["Cookie"] = self.scan_cookie.strip()
        return headers


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
