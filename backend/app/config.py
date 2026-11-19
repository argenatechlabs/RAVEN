"""Application configuration loaded from environment variables.

All settings are optional so the service can boot with defaults; production
values are injected through docker-compose / .env.
"""
from __future__ import annotations

from functools import lru_cache
from typing import List, Optional

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
    # auto = OpenAI if a key is set, otherwise Ollama if reachable, else the
    # deterministic local analysis engine (never fails, always returns data).
    ai_provider: str = "auto"  # auto | openai | ollama | local
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: Optional[str] = None
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
    nuclei_severities: str = "critical,high,medium"
    nuclei_templates_dir: Optional[str] = None

    # --- Demo / offline mode ------------------------------------------------
    # Generates a realistic synthetic target so the UI, AI triage, reporting
    # and the live-log pipeline can be exercised without external tools.
    demo_mode: bool = False

    # --- Storage ------------------------------------------------------------
    data_dir: str = "./data"

    # --- HTTP ---------------------------------------------------------------
    cors_origins: List[str] = ["*"]
    host: str = "0.0.0.0"
    port: int = 8000

    @property
    def sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def severity_list(self) -> List[str]:
        return [s.strip() for s in self.nuclei_severities.split(",") if s.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
