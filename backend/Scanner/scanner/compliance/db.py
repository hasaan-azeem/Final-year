"""
compliance/db.py - SIMPLIFIED VERSION

Database operations for the compliance checker.
Uses existing category and title columns - NO vuln_type column required.

This version avoids the need for database schema changes.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger("webxguard.compliance.db")

from ..db import fetchrow, fetch, execute   # project-level helpers


# ── Load vulnerabilities ──────────────────────────────────────────────────────

async def load_vulnerabilities(session_id: str) -> list[dict]:
    """
    Fetch all vulnerabilities for the session.
    Uses only existing columns: category, title (no vuln_type needed).
    """
    rows = await fetch(
        """
        SELECT
            id,
            domain_id,
            page_url,
            title,
            category,
            confidence,
            severity,
            cvss_score,
            page_criticality,
            severity_level,
            exploit_available
        FROM vulnerabilities
        WHERE session_id = $1
        ORDER BY id
        """,
        session_id,
    )
    return [dict(r) for r in rows] if rows else []


# ── Save violation ────────────────────────────────────────────────────────────

async def save_violation(
    *,
    session_id: str,
    domain_id: int,
    vulnerability_id: int,
    standard: str,
    rule_id: str,
    rule_name: str,
    category: str,
    title: str,
    page_url: str,
    severity: float | None,
    cvss_score: float | None,
    confidence: str | None,
) -> int | None:
    """
    Insert one compliance violation row.
    ON CONFLICT DO NOTHING deduplicates re-runs.
    Returns new row id, or None if duplicate.
    """
    try:
        row = await fetchrow(
            """
            INSERT INTO compliance_violations (
                session_id, domain_id, vulnerability_id,
                standard, rule_id, rule_name,
                category, title, page_url,
                severity, cvss_score, confidence,
                violated_at
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13
            )
            ON CONFLICT (session_id, vulnerability_id, standard, rule_id)
            DO NOTHING
            RETURNING id
            """,
            session_id,
            domain_id,
            vulnerability_id,
            standard,
            rule_id,
            rule_name,
            category or "",
            title or "",
            page_url or "",
            severity,
            cvss_score,
            confidence or "",
            datetime.now(timezone.utc),
        )
        if row:
            logger.debug(
                "[ComplianceDB] Violation saved  vuln_id=%-6d  [%-15s] %s",
                vulnerability_id, standard, rule_id,
            )
            return row["id"]
        return None     # duplicate — silently skip
    except Exception as exc:
        logger.error(
            "[ComplianceDB] save_violation failed: [%s] %s vuln_id=%d — %s",
            standard, rule_id, vulnerability_id, exc,
        )
        return None


# ── Save score ────────────────────────────────────────────────────────────────

async def save_score(
    *,
    session_id: str,
    domain_id: int,
    standard: str,
    total_rules: int,
    violated_rules: int,
    compliant_rules: int,
    score_percent: float,
    status: str,
    violated_rule_ids: list[str],
) -> int | None:
    """
    Upsert the compliance score for one standard in this session.
    Updates in-place if the row already exists (safe for re-runs).
    """
    try:
        row = await fetchrow(
            """
            INSERT INTO compliance_scores (
                session_id, domain_id, standard,
                total_rules, violated_rules, compliant_rules,
                score_percent, status, violated_rule_ids,
                checked_at
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10
            )
            ON CONFLICT (session_id, domain_id, standard)
            DO UPDATE SET
                total_rules       = EXCLUDED.total_rules,
                violated_rules    = EXCLUDED.violated_rules,
                compliant_rules   = EXCLUDED.compliant_rules,
                score_percent     = EXCLUDED.score_percent,
                status            = EXCLUDED.status,
                violated_rule_ids = EXCLUDED.violated_rule_ids,
                checked_at        = EXCLUDED.checked_at
            RETURNING id
            """,
            session_id,
            domain_id,
            standard,
            total_rules,
            violated_rules,
            compliant_rules,
            round(score_percent, 2),
            status,
            violated_rule_ids,
            datetime.now(timezone.utc),
        )
        if row:
            logger.info(
                "[ComplianceDB] Score saved  [%-15s]  %.1f%%  %-4s  "
                "(%d/%d rules compliant)",
                standard, score_percent, status.upper(),
                compliant_rules, total_rules,
            )
            return row["id"]
        return None
    except Exception as exc:
        logger.error("[ComplianceDB] save_score failed: [%s] — %s", standard, exc)
        return None


# ── Read-back helpers ─────────────────────────────────────────────────────────

async def get_scores(
    session_id: str,
    domain_id: int | None = None,
) -> list[dict]:
    """Fetch compliance scores for a session, optionally by domain."""
    if domain_id is not None:
        rows = await fetch(
            """
            SELECT * FROM compliance_scores
            WHERE session_id = $1 AND domain_id = $2
            ORDER BY score_percent DESC
            """,
            session_id, domain_id,
        )
    else:
        rows = await fetch(
            """
            SELECT * FROM compliance_scores
            WHERE session_id = $1
            ORDER BY standard, score_percent DESC
            """,
            session_id,
        )
    return [dict(r) for r in rows] if rows else []


async def get_violations(
    session_id: str,
    standard: str | None = None,
    domain_id: int | None = None,
) -> list[dict]:
    """Fetch violations for a session with optional filters."""
    conditions = ["session_id = $1"]
    params: list = [session_id]

    if standard:
        params.append(standard)
        conditions.append(f"standard = ${len(params)}")
    if domain_id is not None:
        params.append(domain_id)
        conditions.append(f"domain_id = ${len(params)}")

    where = " AND ".join(conditions)
    rows = await fetch(
        f"""
        SELECT * FROM compliance_violations
        WHERE {where}
        ORDER BY standard, rule_id, vulnerability_id
        """,
        *params,
    )
    return [dict(r) for r in rows] if rows else []