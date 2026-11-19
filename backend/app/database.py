"""SQLAlchemy engine, session factory and declarative base."""
from __future__ import annotations

from typing import Iterator

from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings

_connect_args = {"check_same_thread": False} if settings.sqlite else {}
_poolclass = StaticPool if settings.sqlite else None

engine_kwargs = {
    "url": settings.database_url,
    "future": True,
    "pool_pre_ping": not settings.sqlite,
    "connect_args": _connect_args,
}
if _poolclass is not None:
    engine_kwargs["poolclass"] = _poolclass

engine = create_engine(**engine_kwargs)

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)

# SQLite has no native ON DELETE CASCADE unless this pragma is enabled.
if settings.sqlite:

    @event.listens_for(Engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):  # pragma: no cover
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
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
