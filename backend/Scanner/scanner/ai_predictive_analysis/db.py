"""
posture/db.py
=============
All database operations for the Security Posture Engine.

Key design decisions:
  - ThreadedConnectionPool (min=2, max=10)
  - RealDictCursor for all reads
  - _DecimalEncoder handles Decimal from NUMERIC columns (prevents JSON crash)
  - fetch_monitor_vulns uses DISTINCT ON (page_url, title) to deduplicate —
    same vuln re-inserted every scan cycle gets counted only once
  - All methods return empty list / None on failure — never raise to caller
"""
from __future__ import annotations

import base64
import decimal
import json
import logging
import os
from contextlib import contextmanager
from typing import Generator
from urllib.parse import urlparse

import psycopg2
import psycopg2.pool
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("webxguard.posture.db")


# ── JSON encoder ──────────────────────────────────────────────────────────────

class _DecimalEncoder(json.JSONEncoder):
    """psycopg2 returns NUMERIC columns as Decimal — stdlib json can't handle it."""
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return float(obj)
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode()
        return super().default(obj)


def _dumps(obj) -> str:
    return json.dumps(obj, cls=_DecimalEncoder)


# ── Config ────────────────────────────────────────────────────────────────────

def _cfg(url: str) -> dict:
    p = urlparse(url)
    return {
        "host":     p.hostname or "localhost",
        "port":     p.port     or 5432,
        "database": p.path.lstrip("/"),
        "user":     p.username or "postgres",
        "password": p.password or "",
    }


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:5353@127.0.0.1:5432/Webxguard",
)
DB_CONFIG = _cfg(DATABASE_URL)


# ── Pool ──────────────────────────────────────────────────────────────────────

_pool: psycopg2.pool.ThreadedConnectionPool | None = None


def get_pool() -> psycopg2.pool.ThreadedConnectionPool:
    global _pool
    if _pool is None or _pool.closed:
        _pool = psycopg2.pool.ThreadedConnectionPool(
            minconn=2, maxconn=10, **DB_CONFIG
        )
        logger.debug("[PostureDB] Connection pool created")
    return _pool


@contextmanager
def get_conn() -> Generator:
    conn = None
    try:
        conn = get_pool().getconn()
        yield conn
    except psycopg2.pool.PoolError as e:
        logger.error("[PostureDB] Pool exhausted — direct connect fallback: %s", e)
        conn = psycopg2.connect(**DB_CONFIG)
        yield conn
        conn.close()
        conn = None
    finally:
        if conn is not None:
            try:
                get_pool().putconn(conn)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass


# ── Read helpers ──────────────────────────────────────────────────────────────

def fetch_monitor_vulns(
    domain: str,
    days:   int = 30,
    limit:  int = 2000,
) -> list[dict]:
    """
    Fetch DEDUPLICATED scored vulnerabilities for one domain.

    Bug fixed: the same vuln (same page_url + title) is re-inserted on every
    scan cycle with a new monitor_session_id. Without deduplication N scans
    produce N x unique_vulns rows, inflating the score to 100.

    DISTINCT ON (page_url, title) ORDER BY ... created_at DESC picks the
    most recent version of each unique finding — so you always see exactly
    as many rows as there are unique vulnerabilities.
    """
    try:
        with get_conn() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT DISTINCT ON (page_url, title)
                    id, title, category, confidence,
                    cvss_score, severity, severity_level,
                    likelihood, impact, page_criticality,
                    exploit_available,
                    target_priority, priority_category,
                    created_at
                FROM monitor_vulnerabilities
                WHERE domain           = %s
                  AND target_priority IS NOT NULL
                  AND created_at      >= NOW() - (%s || ' days')::INTERVAL
                ORDER BY page_url, title, created_at DESC
                LIMIT %s
            """, (domain, str(days), limit))
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
            logger.debug(
                "[PostureDB] fetch_monitor_vulns(%s): %d unique findings",
                domain, len(rows),
            )
            return rows
    except Exception as e:
        logger.error("[PostureDB] fetch_monitor_vulns(%s): %s", domain, e)
        return []


def fetch_posture_history(
    domain: str,
    hours:  int = 720,
    limit:  int = 5000,
) -> list[dict]:
    """
    30-day snapshot history ordered oldest→newest.
    Used for: timeline chart, trend, velocity, volatility, anomaly feed.
    """
    try:
        with get_conn() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT id, security_score, risk_level, trend_rate, trend_direction,
                       anomaly_score, is_anomaly, anomaly_reason,
                       vuln_count, critical_count,
                       high_count, medium_count, low_count, captured_at
                FROM posture_snapshots
                WHERE domain      = %s
                  AND captured_at >= NOW() - (%s || ' hours')::INTERVAL
                ORDER BY captured_at ASC
                LIMIT %s
            """, (domain, str(hours), limit))
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
            return rows
    except Exception as e:
        logger.error("[PostureDB] fetch_posture_history(%s): %s", domain, e)
        return []


def fetch_all_posture_history(
    domain: str,
    limit:  int = 5000,
) -> list[dict]:
    """Full history for ML training — no time filter."""
    try:
        with get_conn() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT id, security_score, trend_rate, vuln_count, critical_count,
                       high_count, anomaly_score, is_anomaly, captured_at
                FROM posture_snapshots
                WHERE domain = %s
                ORDER BY captured_at ASC
                LIMIT %s
            """, (domain, limit))
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()
            return rows
    except Exception as e:
        logger.error("[PostureDB] fetch_all_posture_history(%s): %s", domain, e)
        return []


def get_latest_snapshot(domain: str) -> dict | None:
    try:
        with get_conn() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT * FROM posture_snapshots
                WHERE domain = %s
                ORDER BY captured_at DESC
                LIMIT 1
            """, (domain,))
            row = cur.fetchone()
            cur.close()
            return dict(row) if row else None
    except Exception as e:
        logger.error("[PostureDB] get_latest_snapshot(%s): %s", domain, e)
        return None


# ── Write helpers ─────────────────────────────────────────────────────────────

def save_snapshot(
    domain:      str,
    session_id:  str | None,
    score:       float,
    risk_level:  str,
    trend:       dict,
    predictions: dict,
    anomaly:     dict,
    explanation: dict,
    counts:      dict,
    *,
    breach_probability: float | None = None,
    risk_velocity:      float | None = None,
    risk_volatility:    float | None = None,
    volatility_label:   str   | None = None,
    forecast_7d:        list  | None = None,
) -> int | None:
    """
    Upsert one posture snapshot.
    Duplicate within the same UTC minute → UPDATE, not INSERT.
    """
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO posture_snapshots (
                    domain, monitor_session_id,
                    security_score, risk_level,
                    trend_rate, trend_direction, smoothed_score,
                    pred_1h,  pred_6h,  pred_24h,
                    pred_1h_level, pred_6h_level, pred_24h_level,
                    pred_1d, pred_1d_level,
                    pred_model, pred_confidence,
                    anomaly_score, is_anomaly, anomaly_reason,
                    vuln_count, critical_count, high_count, medium_count, low_count,
                    breach_probability, risk_velocity, risk_volatility, volatility_label,
                    forecast_7d,
                    explanation,
                    captured_at
                ) VALUES (
                    %s, %s::uuid,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s, %s,
                    %s, %s,
                    %s, %s,
                    %s, %s, %s,
                    %s, %s, %s, %s, %s,
                    %s, %s, %s, %s,
                    %s::jsonb,
                    %s::jsonb,
                    NOW()
                )
                ON CONFLICT (domain, date_trunc('minute', captured_at AT TIME ZONE 'UTC'))
                DO UPDATE SET
                    security_score     = EXCLUDED.security_score,
                    risk_level         = EXCLUDED.risk_level,
                    trend_rate         = EXCLUDED.trend_rate,
                    trend_direction    = EXCLUDED.trend_direction,
                    smoothed_score     = EXCLUDED.smoothed_score,
                    pred_1h            = EXCLUDED.pred_1h,
                    pred_6h            = EXCLUDED.pred_6h,
                    pred_24h           = EXCLUDED.pred_24h,
                    pred_1d            = EXCLUDED.pred_1d,
                    pred_1d_level      = EXCLUDED.pred_1d_level,
                    anomaly_score      = EXCLUDED.anomaly_score,
                    is_anomaly         = EXCLUDED.is_anomaly,
                    anomaly_reason     = EXCLUDED.anomaly_reason,
                    breach_probability = EXCLUDED.breach_probability,
                    risk_velocity      = EXCLUDED.risk_velocity,
                    risk_volatility    = EXCLUDED.risk_volatility,
                    volatility_label   = EXCLUDED.volatility_label,
                    forecast_7d        = EXCLUDED.forecast_7d,
                    explanation        = EXCLUDED.explanation
                RETURNING id
            """, (
                domain, session_id,
                score, risk_level,
                trend["trend_rate"], trend["trend_direction"], trend["smoothed_score"],
                predictions["pred_1d"], predictions["pred_1d"], predictions["pred_1d"],
                predictions["pred_1d_level"], predictions["pred_1d_level"], predictions["pred_1d_level"],
                predictions["pred_1d"], predictions["pred_1d_level"],
                predictions["model_used"], predictions["confidence"],
                anomaly["anomaly_score"], anomaly["is_anomaly"], anomaly["reason"],
                counts["total"], counts["critical"], counts["high"],
                counts["medium"], counts["low"],
                breach_probability, risk_velocity, risk_volatility, volatility_label,
                _dumps(forecast_7d) if forecast_7d is not None else None,
                _dumps(explanation),
            ))
            row = cur.fetchone()
            conn.commit()
            cur.close()
            return row[0] if row else None
    except Exception as e:
        logger.error("[PostureDB] save_snapshot(%s): %s", domain, e, exc_info=True)
        return None


def save_ml_model(domain: str, kind: str, payload: bytes, meta: dict) -> bool:
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO posture_models (domain, kind, model_bytes, meta, trained_at)
                VALUES (%s, %s, %s, %s::jsonb, NOW())
                ON CONFLICT (domain, kind) DO UPDATE SET
                    model_bytes = EXCLUDED.model_bytes,
                    meta        = EXCLUDED.meta,
                    trained_at  = EXCLUDED.trained_at
            """, (domain, kind, payload, _dumps(meta)))
            conn.commit()
            cur.close()
            return True
    except Exception as e:
        logger.error("[PostureDB] save_ml_model(%s, %s): %s", domain, kind, e)
        return False


def load_ml_model(domain: str, kind: str) -> bytes | None:
    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT model_bytes FROM posture_models WHERE domain=%s AND kind=%s",
                (domain, kind),
            )
            row = cur.fetchone()
            cur.close()
            return bytes(row[0]) if row else None
    except Exception as e:
        logger.error("[PostureDB] load_ml_model(%s, %s): %s", domain, kind, e)
        return None