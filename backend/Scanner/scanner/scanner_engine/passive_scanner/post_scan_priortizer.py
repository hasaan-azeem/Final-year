"""
WebXGuard / post_scan_prioritizer.py

PASSIVE-ONLY VERSION (No active vuln boosting)
"""

import logging
import os
from urllib.parse import urlparse

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("webxguard.post_scan_prioritizer")


# ─────────────────────────────────────────────────────────────────────────────
# DB CONFIG
# ─────────────────────────────────────────────────────────────────────────────

def _db_config_from_url(url: str) -> dict:
    p = urlparse(url)
    return {
        "host":     p.hostname or "localhost",
        "port":     p.port or 5432,
        "database": p.path.lstrip("/"),
        "user":     p.username or "postgres",
        "password": p.password or "",
    }

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:admin123@localhost:5432/WebXGaurd2",
)

DB_CONFIG = _db_config_from_url(DATABASE_URL)


# ─────────────────────────────────────────────────────────────────────────────
# CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

_PAGE_CHANGE_KEYWORDS = (
    "page content change",
    "content change detected",
    "defacement",
    "injected content",
    "new external script",
    "new iframe injected",
    "crypto miner script injected",
)


_CONF_BONUS = {
    "certain": 0.5,
    "firm": 0.0,
    "tentative": -0.3
}


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _safe_float(v, default, lo, hi):
    try:
        v = float(v)
        return max(lo, min(hi, v))
    except:
        return default


def _is_page_change(title: str) -> bool:
    t = (title or "").lower()
    return any(k in t for k in _PAGE_CHANGE_KEYWORDS)


def assign_priority_category(p: float) -> str:
    if p >= 8.5: return "Critical"
    if p >= 6.5: return "High"
    if p >= 4.5: return "Medium"
    return "Low"


# ─────────────────────────────────────────────────────────────────────────────
# CORE SCORING (PASSIVE ONLY)
# ─────────────────────────────────────────────────────────────────────────────

def calculate_priority(row: dict) -> tuple[float, str]:

    title = str(row.get("title") or "")

    # 🚨 HARD OVERRIDE (monitoring-specific)
    if _is_page_change(title):
        return 9.5, "Critical"

    # numeric inputs
    cvss       = _safe_float(row.get("cvss_score"), 5.0, 0, 10)
    severity   = _safe_float(row.get("severity"), 5.0, 0, 10)
    likelihood = _safe_float(row.get("likelihood"), 0.5, 0, 1)
    impact     = _safe_float(row.get("impact"), 5.0, 0, 10)
    page_crit  = _safe_float(row.get("page_criticality"), 5.0, 0, 10)

    exploit    = bool(row.get("exploit_available", False))
    confidence = str(row.get("confidence") or "firm").lower()

    # ── BASE SCORE (pure passive risk weighting)
    base = (
        cvss * 0.40 +
        page_crit * 0.25 +
        impact * 0.15 +
        severity * 0.10 +
        (likelihood * 10) * 0.05
    )

    # ── BONUS (safe for passive findings)
    bonus = 0.0

    if exploit:
        bonus += 2.0   # e.g. known SSL vuln, exposed admin panel exploit exists

    bonus += _CONF_BONUS.get(confidence, 0.0)

    priority = round(max(0, min(10, base + bonus)), 2)

    return priority, assign_priority_category(priority)


# ─────────────────────────────────────────────────────────────────────────────
# PRIORITIZER
# ─────────────────────────────────────────────────────────────────────────────

class MonitorPrioritizer:

    TABLE = "monitor_vulnerabilities"

    def __init__(self, db_config=DB_CONFIG):
        self.db_config = db_config
        self.conn = None

    def connect(self):
        try:
            self.conn = psycopg2.connect(**self.db_config)
            return True
        except Exception as e:
            logger.error("DB connect failed: %s", e)
            return False

    def close(self):
        if self.conn:
            self.conn.close()

    # 🔥 Re-score entire session (NO stale priorities)
    def prioritize_session(self, session_id: str | None):

        cur = self.conn.cursor(cursor_factory=RealDictCursor)

        params = []
        where = ""

        if session_id:
            where = "WHERE monitor_session_id = %s::uuid"
            params.append(session_id)

        cur.execute(f"""
            SELECT id, title, category, confidence,
                   cvss_score, severity, likelihood,
                   impact, page_criticality,
                   exploit_available
            FROM {self.TABLE}
            {where}
        """, params)

        rows = cur.fetchall()

        scored = 0
        critical = 0
        page_change = 0
        errors = 0

        update_cur = self.conn.cursor()

        for row in rows:
            try:
                p, cat = calculate_priority(row)

                if cat == "Critical":
                    critical += 1

                if _is_page_change(row["title"]):
                    page_change += 1

                update_cur.execute(f"""
                    UPDATE {self.TABLE}
                    SET target_priority = %s,
                        priority_category = %s
                    WHERE id = %s
                """, (p, cat, row["id"]))

                scored += 1

            except Exception as e:
                errors += 1
                logger.error("Row %s failed: %s", row.get("id"), e)

        self.conn.commit()

        cur.close()
        update_cur.close()

        logger.info(
            "Prioritized: scored=%d critical=%d page_change=%d errors=%d",
            scored, critical, page_change, errors
        )

        return {
            "scored": scored,
            "critical": critical,
            "page_change_critical": page_change,
            "errors": errors,
        }


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def run_post_scan_prioritization(session_id=None, recover_all=False):

    p = MonitorPrioritizer()

    if not p.connect():
        return {"scored": 0, "errors": 1}

    try:
        return p.prioritize_session(session_id if not recover_all else None)
    finally:
        p.close()