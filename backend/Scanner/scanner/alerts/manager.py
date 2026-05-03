"""
app/scanner/alerts/manager.py
=============================
Low-level CRUD for the `alerts` table.

Two execution paths because the rest of the codebase mixes both:

  SYNC path (psycopg2):
      - posture engine (runs in run_in_executor)
      - ai_anomaly engine (runs in run_in_executor)
    These callers do NOT have an asyncio loop available. They use a tiny
    psycopg2 ThreadedConnectionPool that this module owns internally.

  ASYNC path (asyncpg):
      - FastAPI request handlers
      - scan-completion hook in app/core.py
    These reuse the existing asyncpg pool exposed by scanner.db
    (via fetch / fetchrow / execute helpers).

Dedup: every create_* takes an optional `fingerprint` + `dedup_hours`. If
an identical (user_id, fingerprint) alert was created in the dedup window
we skip insertion — prevents alert spam when the same anomaly fires every
monitoring cycle.
"""
from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from typing import Any, Iterable
from urllib.parse import urlparse

import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

logger = logging.getLogger("webxguard.alerts.manager")


# ─────────────────────────────────────────────────────────────────────────────
# SYNC pool (psycopg2) — for posture engine + ai_anomaly engine
# ─────────────────────────────────────────────────────────────────────────────

_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:5353@127.0.0.1:5432/Webxguard",
)


def _pg_kwargs() -> dict:
    p = urlparse(_DATABASE_URL)
    return {
        "host":     p.hostname or "localhost",
        "port":     p.port     or 5432,
        "database": (p.path or "/Webxguard").lstrip("/"),
        "user":     p.username or "postgres",
        "password": p.password or "",
    }


_sync_pool: ThreadedConnectionPool | None = None


def _get_sync_pool() -> ThreadedConnectionPool:
    global _sync_pool
    if _sync_pool is None or _sync_pool.closed:
        _sync_pool = ThreadedConnectionPool(minconn=1, maxconn=5, **_pg_kwargs())
        logger.debug("[Alerts] sync pool created")
    return _sync_pool


@contextmanager
def _sync_conn():
    pool = _get_sync_pool()
    conn = None
    try:
        conn = pool.getconn()
        yield conn
    except psycopg2.pool.PoolError:
        # Pool exhausted — open a one-off connection so we never block the engine
        conn = psycopg2.connect(**_pg_kwargs())
        yield conn
        try:
            conn.close()
        except Exception:
            pass
        conn = None
    finally:
        if conn is not None:
            try:
                pool.putconn(conn)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass


# ─────────────────────────────────────────────────────────────────────────────
# Validation helpers
# ─────────────────────────────────────────────────────────────────────────────

_VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Info"}


def _normalize_severity(sev: str | None) -> str:
    if not sev:
        return "Info"
    s = str(sev).strip().capitalize()
    return s if s in _VALID_SEVERITIES else "Info"


def _to_jsonb(meta: dict | None) -> str:
    """psycopg2 + asyncpg both accept JSON as a string for JSONB columns."""
    try:
        return json.dumps(meta or {}, default=str)
    except (TypeError, ValueError):
        return "{}"


# ─────────────────────────────────────────────────────────────────────────────
# SYNC API — used by posture engine + ai_anomaly engine
# ─────────────────────────────────────────────────────────────────────────────

def find_users_for_domain_sync(domain: str) -> list[int]:
    """
    Return user_ids who actively monitor this domain via monitored_sites.
    Empty list = no user owns this domain (continuous monitoring of a
    TARGET_URL that nobody added through the UI).
    """
    if not domain:
        return []
    try:
        with _sync_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                """
                SELECT DISTINCT user_id
                FROM   monitored_sites
                WHERE  domain = %s
                  AND  is_active = TRUE
                  AND  user_id IS NOT NULL
                """,
                (domain,),
            )
            rows = cur.fetchall()
            cur.close()
            return [int(r[0]) for r in rows]
    except Exception as e:
        logger.error("[Alerts] find_users_for_domain_sync(%s): %s", domain, e)
        return []


def _check_recent_duplicate_sync(
    cur,
    user_id: int | None,
    fingerprint: str,
    dedup_hours: int,
) -> bool:
    """Return True if a same-fingerprint alert exists within the dedup window."""
    cur.execute(
        """
        SELECT 1
        FROM   alerts
        WHERE  fingerprint = %s
          AND  COALESCE(user_id, -1) = COALESCE(%s, -1)
          AND  created_at >= NOW() - (%s || ' hours')::INTERVAL
        LIMIT 1
        """,
        (fingerprint, user_id, str(dedup_hours)),
    )
    return cur.fetchone() is not None


def create_alert_sync(
    *,
    user_id:             int | None,
    domain:              str,
    severity:            str,
    source:              str,
    title:               str,
    description:         str | None  = None,
    url:                 str | None  = None,
    scan_session:        str | None  = None,
    snapshot_uuid:       str | None  = None,
    posture_snapshot_id: int | None  = None,
    metadata:            dict | None = None,
    fingerprint:         str | None  = None,
    dedup_hours:         int         = 6,
) -> int | None:
    """
    Insert one alert row. Returns the new id, or None when:
      - dedup hit (same fingerprint within window)
      - DB error
    """
    sev = _normalize_severity(severity)
    if not domain or not title:
        logger.warning("[Alerts] sync create skipped — missing domain/title")
        return None

    try:
        with _sync_conn() as conn:
            cur = conn.cursor()

            # Dedup
            if fingerprint and _check_recent_duplicate_sync(
                cur, user_id, fingerprint, dedup_hours
            ):
                cur.close()
                logger.debug(
                    "[Alerts] sync dedup hit  user=%s  fp=%s", user_id, fingerprint,
                )
                return None

            cur.execute(
                """
                INSERT INTO alerts (
                    user_id, domain, severity, source,
                    title, description, url,
                    scan_session, snapshot_uuid, posture_snapshot_id,
                    metadata, fingerprint
                )
                VALUES (
                    %s, %s, %s, %s,
                    %s, %s, %s,
                    %s::uuid, %s::uuid, %s,
                    %s::jsonb, %s
                )
                RETURNING id
                """,
                (
                    user_id, domain, sev, source,
                    title, description, url,
                    scan_session, snapshot_uuid, posture_snapshot_id,
                    _to_jsonb(metadata), fingerprint,
                ),
            )
            new_id = int(cur.fetchone()[0])
            conn.commit()
            cur.close()
            logger.info(
                "[Alerts] sync ✓ id=%s  user=%s  domain=%s  sev=%s  src=%s",
                new_id, user_id, domain, sev, source,
            )
            return new_id
    except Exception as e:
        logger.error("[Alerts] sync create failed: %s", e, exc_info=True)
        return None


def fanout_alert_sync(
    *,
    domain:              str,
    severity:            str,
    source:              str,
    title:               str,
    description:         str | None  = None,
    url:                 str | None  = None,
    scan_session:        str | None  = None,
    snapshot_uuid:       str | None  = None,
    posture_snapshot_id: int | None  = None,
    metadata:            dict | None = None,
    fingerprint:         str | None  = None,
    dedup_hours:         int         = 6,
) -> int:
    """
    Look up every user monitoring `domain` and insert one alert per user.
    If nobody owns the domain we still insert a single user_id=NULL row so
    the alert isn't lost.

    Returns the count of alerts actually inserted (i.e. dedup misses).
    """
    user_ids = find_users_for_domain_sync(domain)
    targets: Iterable[int | None] = user_ids if user_ids else [None]

    inserted = 0
    for uid in targets:
        new_id = create_alert_sync(
            user_id             = uid,
            domain              = domain,
            severity            = severity,
            source              = source,
            title               = title,
            description         = description,
            url                 = url,
            scan_session        = scan_session,
            snapshot_uuid       = snapshot_uuid,
            posture_snapshot_id = posture_snapshot_id,
            metadata            = metadata,
            fingerprint         = fingerprint,
            dedup_hours         = dedup_hours,
        )
        if new_id is not None:
            inserted += 1
    return inserted


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC API — used by FastAPI handlers
# ─────────────────────────────────────────────────────────────────────────────
#
# NOTE: We import lazily to avoid a circular import at module load time
#       (scanner.db imports things that pull in the rest of the scanner).

async def _check_recent_duplicate_async(
    user_id: int | None,
    fingerprint: str,
    dedup_hours: int,
) -> bool:
    from ..db import fetchrow
    row = await fetchrow(
        """
        SELECT 1
        FROM   alerts
        WHERE  fingerprint = $1
          AND  COALESCE(user_id, -1) = COALESCE($2, -1)
          AND  created_at >= NOW() - ($3 || ' hours')::INTERVAL
        LIMIT 1
        """,
        fingerprint, user_id, str(dedup_hours),
    )
    return row is not None


async def create_alert_async(
    *,
    user_id:             int | None,
    domain:              str,
    severity:            str,
    source:              str,
    title:               str,
    description:         str | None  = None,
    url:                 str | None  = None,
    scan_session:        str | None  = None,
    snapshot_uuid:       str | None  = None,
    posture_snapshot_id: int | None  = None,
    metadata:            dict | None = None,
    fingerprint:         str | None  = None,
    dedup_hours:         int         = 6,
) -> int | None:
    from ..db import fetchrow

    sev = _normalize_severity(severity)
    if not domain or not title:
        logger.warning("[Alerts] async create skipped — missing domain/title")
        return None

    try:
        if fingerprint and await _check_recent_duplicate_async(
            user_id, fingerprint, dedup_hours
        ):
            logger.debug(
                "[Alerts] async dedup hit  user=%s  fp=%s", user_id, fingerprint,
            )
            return None

        row = await fetchrow(
            """
            INSERT INTO alerts (
                user_id, domain, severity, source,
                title, description, url,
                scan_session, snapshot_uuid, posture_snapshot_id,
                metadata, fingerprint
            )
            VALUES (
                $1,  $2,  $3,  $4,
                $5,  $6,  $7,
                $8::uuid,  $9::uuid,  $10,
                $11::jsonb,  $12
            )
            RETURNING id
            """,
            user_id, domain, sev, source,
            title, description, url,
            scan_session, snapshot_uuid, posture_snapshot_id,
            _to_jsonb(metadata), fingerprint,
        )
        new_id = int(row["id"]) if row else None
        if new_id:
            logger.info(
                "[Alerts] async ✓ id=%s  user=%s  domain=%s  sev=%s  src=%s",
                new_id, user_id, domain, sev, source,
            )
        return new_id
    except Exception as e:
        logger.error("[Alerts] async create failed: %s", e, exc_info=True)
        return None


# ─────────────────────────────────────────────────────────────────────────────
# Read / update for the dashboard endpoints
# ─────────────────────────────────────────────────────────────────────────────

async def list_user_alerts(
    user_id:  int,
    *,
    limit:    int  = 100,
    severity: str | None = None,
    unread_only: bool = False,
) -> list[dict[str, Any]]:
    """Return alerts for one user, newest first. Filter by severity if given."""
    from ..db import fetch

    sql_parts = [
        "SELECT id, user_id, domain, severity, source,",
        "       title, description, url,",
        "       scan_session::text  AS scan_session,",
        "       snapshot_uuid::text AS snapshot_uuid,",
        "       posture_snapshot_id,",
        "       metadata, is_read, is_dismissed, created_at",
        "FROM   alerts",
        "WHERE  user_id = $1 AND is_dismissed = FALSE",
    ]
    params: list = [user_id]

    if severity:
        sev = _normalize_severity(severity)
        params.append(sev)
        sql_parts.append(f"  AND severity = ${len(params)}")

    if unread_only:
        sql_parts.append("  AND is_read = FALSE")

    params.append(limit)
    sql_parts.append("ORDER BY created_at DESC")
    sql_parts.append(f"LIMIT ${len(params)}")

    rows = await fetch("\n".join(sql_parts), *params)

    out: list[dict[str, Any]] = []
    for r in rows:
        d = dict(r)
        # Frontend expects camelCase-ish naming but the existing pages already
        # use these snake_case keys so leave them alone.
        # `read` (legacy field used by mock data) — provide as alias.
        d["read"] = bool(d.get("is_read"))
        out.append(d)
    return out


async def mark_alert_read(alert_id: int, user_id: int) -> bool:
    """Mark one alert as read. Only succeeds if the alert belongs to user_id."""
    from ..db import execute
    res = await execute(
        """
        UPDATE alerts
        SET    is_read = TRUE
        WHERE  id = $1 AND user_id = $2 AND is_read = FALSE
        """,
        alert_id, user_id,
    )
    # asyncpg returns "UPDATE n" — n>0 means a row matched
    try:
        return int(str(res).split()[-1]) > 0
    except Exception:
        return True   # we don't want false negatives breaking the UI


async def mark_all_read(user_id: int) -> int:
    """Mark every unread alert for the user as read. Returns count updated."""
    from ..db import execute
    res = await execute(
        "UPDATE alerts SET is_read = TRUE WHERE user_id = $1 AND is_read = FALSE",
        user_id,
    )
    try:
        return int(str(res).split()[-1])
    except Exception:
        return 0


async def clear_all_user_alerts(user_id: int) -> int:
    """Soft-delete (dismiss) every alert for this user. Returns count."""
    from ..db import execute
    res = await execute(
        "UPDATE alerts SET is_dismissed = TRUE WHERE user_id = $1 AND is_dismissed = FALSE",
        user_id,
    )
    try:
        return int(str(res).split()[-1])
    except Exception:
        return 0


async def get_unread_count(user_id: int) -> int:
    from ..db import fetchrow
    row = await fetchrow(
        """
        SELECT COUNT(*)::int AS n
        FROM   alerts
        WHERE  user_id = $1 AND is_read = FALSE AND is_dismissed = FALSE
        """,
        user_id,
    )
    return int(row["n"]) if row else 0