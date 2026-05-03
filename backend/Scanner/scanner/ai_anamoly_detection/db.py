"""
ai_engine/db.py
===============
Synchronous SQLAlchemy engine for the anomaly-detection subsystem.

Reads the same DATABASE_URL that the main WebXGuard asyncpg pool uses,
so no extra credentials are needed.

The ai_engine runs entirely in thread-pool executors (run_in_executor) so
synchronous psycopg2 is fine here — it never blocks the async event loop.
"""
from __future__ import annotations

import logging
import os
import re
from contextlib import contextmanager
from typing import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from .schemas import Base

logger = logging.getLogger("webxguard.ai_engine.db")

_engine: Engine | None = None
_SessionFactory: sessionmaker | None = None


def _dsn() -> str:
    """
    Build a psycopg2 DSN from DATABASE_URL (same env var used by asyncpg).

    asyncpg accepts  postgresql://...
    psycopg2 needs   postgresql+psycopg2://...
    """
    url = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:5353@127.0.0.1:5432/Webxguard",
    )
    # Normalise scheme for SQLAlchemy + psycopg2
    url = re.sub(r"^postgresql(\+psycopg2)?://", "postgresql+psycopg2://", url)
    url = re.sub(r"^postgres://",                "postgresql+psycopg2://", url)
    return url


def get_engine() -> Engine:
    """Return the singleton synchronous Engine (created on first call)."""
    global _engine, _SessionFactory
    if _engine is not None:
        return _engine

    dsn = _dsn()
    logger.info("[AI-DB] Connecting (sync/psycopg2)…")
    _engine = create_engine(
        dsn,
        pool_size=3,
        max_overflow=5,
        pool_pre_ping=True,
        echo=False,
    )
    _SessionFactory = sessionmaker(bind=_engine, expire_on_commit=False)
    logger.info("[AI-DB] Engine ready")
    return _engine


@contextmanager
def get_session() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy Session with auto commit / rollback."""
    if _SessionFactory is None:
        get_engine()
    assert _SessionFactory is not None
    session: Session = _SessionFactory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def ensure_tables() -> None:
    """Create all ORM tables if they don't already exist (idempotent)."""
    engine = get_engine()
    Base.metadata.create_all(engine, checkfirst=True)
    logger.info("[AI-DB] Tables verified / created")


def health_check() -> bool:
    try:
        with get_engine().connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.error("[AI-DB] Health check failed: %s", exc)
        return False