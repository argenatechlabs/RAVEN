"""SQLAlchemy engine, session factory and declarative base."""
from __future__ import annotations

from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from app.config import settings

_connect_args = (
    {"check_same_thread": False, "timeout": 30} if settings.sqlite else {}
)

engine_kwargs = {
    "url": settings.database_url,
    "future": True,
    "pool_pre_ping": True,
    "connect_args": _connect_args,
}
if settings.sqlite:
    # One connection per thread (unlike StaticPool) plus WAL + busy timeout,
    # which keeps concurrent request/scan sessions from corrupting each other.
    engine_kwargs["poolclass"] = QueuePool
    engine_kwargs["pool_size"] = 5
    engine_kwargs["max_overflow"] = 10
    engine_kwargs["pool_timeout"] = 30

engine = create_engine(**engine_kwargs)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

# SQLite has no native ON DELETE CASCADE unless this pragma is enabled.
if settings.sqlite:

    @event.listens_for(Engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):  # pragma: no cover
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.execute("PRAGMA busy_timeout=30000")
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        cursor.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency that yields a request scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables if they do not exist yet (and the SQLite file's folder)."""
    import os

    if settings.sqlite:
        url = settings.database_url.replace("sqlite:///", "", 1)
        if url and url != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(url)), exist_ok=True)
    os.makedirs(settings.data_dir, exist_ok=True)

    from app.models import Base  # noqa: WPS433 (local import avoids cycles)

    Base.metadata.create_all(bind=engine)
