"""
backend/Scanner/extras_routes.py

APIRouter exposing all "extras" endpoints. Mounted by Scanner/app.py:

    from .extras_routes import router as extras_router
    app.include_router(extras_router)

Endpoints:

    Alerts:
      GET    /api/alerts                       → list (filter by severity/unread)
      GET    /api/alerts/unread-count          → unread count
      POST   /api/alerts/{alert_id}/read       → mark one as read
      POST   /api/alerts/read-all              → mark all read
      DELETE /api/alerts                       → dismiss all

    Compliance (real DB data):
      GET    /api/compliance/{session_id}      → for a specific scan session
      GET    /api/compliance/latest            → most recent for current user

    Predictive (real DB data from posture_snapshots):
      GET    /api/predictive/{session_id}      → for a specific scan session
      GET    /api/predictive/latest            → most recent for current user

    Crawler (real DB data from pages/endpoints/forms/crawler_queue):
      GET    /api/scan/crawler/{session_id}    → live crawler view

All endpoints require Bearer JWT auth.

NOTE on imports:
  Yeh file backend/Scanner/ ke andar hai, aur Scanner/scanner/ uska child
  package hai. Isliye `.scanner.db` relative import kaam karta hai.
  auth_jwt is in backend/app/ (Flask side) — absolute import 'app.auth_jwt'.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, Query

# JWT helper (sibling app/ package — absolute import)
from app.auth_jwt import get_current_user_id

# Scanner submodules — relative imports inside Scanner/scanner/
from .scanner.db import fetch, fetchrow
from .scanner.repositories.sessions import session_belongs_to_user
from .scanner.alerts.manager import (
    list_user_alerts,
    mark_alert_read,
    mark_all_read,
    clear_all_user_alerts,
    get_unread_count,
)

logger = logging.getLogger("webxguard.extras_routes")

router = APIRouter(tags=["extras"])


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _domain_from_url(url: str | None) -> str:
    if not url:
        return ""
    try:
        return urlparse(url).hostname or url
    except Exception:
        return url


def _severity_label_from_numeric(value: float | None) -> str:
    """Compliance violations have severity as numeric (0-10). Map to label."""
    if value is None:
        return "Medium"
    v = float(value)
    if v >= 9.0: return "Critical"
    if v >= 7.0: return "High"
    if v >= 4.0: return "Medium"
    return "Low"


async def _ensure_session_owned(session_id: str, user_id: int) -> None:
    """Throw 404 if the scan_session doesn't belong to user (info-leak guard)."""
    if not await session_belongs_to_user(session_id, user_id):
        raise HTTPException(status_code=404, detail="Session not found")


async def _resolve_session_domain(session_id: str) -> tuple[str, int | None]:
    """
    Return (domain, domain_id) for a scan_session.
    Falls back to parsing scan_sessions.url if no domain row exists.
    """
    row = await fetchrow(
        """
        SELECT s.url, d.id AS domain_id, d.domain_name
        FROM   scan_sessions s
        LEFT   JOIN vulnerabilities v ON v.session_id = s.id
        LEFT   JOIN domains d         ON d.id = v.domain_id
        WHERE  s.id = $1::uuid
        LIMIT  1
        """,
        session_id,
    )
    if not row:
        return "", None
    domain = row.get("domain_name") or _domain_from_url(row.get("url"))
    return domain or "", row.get("domain_id")


# =============================================================================
# ALERTS ENDPOINTS
# =============================================================================

@router.get("/api/alerts")
async def alerts_list(
    user_id:     int  = Depends(get_current_user_id),
    severity:    str | None = Query(None),
    unread_only: bool = Query(False),
    limit:       int  = Query(100, ge=1, le=500),
):
    return await list_user_alerts(
        user_id     = user_id,
        limit       = limit,
        severity    = severity,
        unread_only = unread_only,
    )


@router.get("/api/alerts/unread-count")
async def alerts_unread_count(user_id: int = Depends(get_current_user_id)):
    return {"unread": await get_unread_count(user_id)}


@router.post("/api/alerts/{alert_id}/read")
async def alerts_mark_read(
    alert_id: int,
    user_id:  int = Depends(get_current_user_id),
):
    ok = await mark_alert_read(alert_id, user_id)
    return {"ok": ok, "id": alert_id}


@router.post("/api/alerts/read-all")
async def alerts_read_all(user_id: int = Depends(get_current_user_id)):
    n = await mark_all_read(user_id)
    return {"ok": True, "updated": n}


@router.delete("/api/alerts")
async def alerts_clear_all(user_id: int = Depends(get_current_user_id)):
    n = await clear_all_user_alerts(user_id)
    return {"ok": True, "dismissed": n}


# =============================================================================
# COMPLIANCE ENDPOINTS
# =============================================================================

async def _build_compliance_payload(session_id: str) -> dict[str, Any] | None:
    """
    Read compliance_scores + compliance_violations for one session_id and
    shape it the way the existing frontend (Compliance.jsx, ScanDetail.jsx,
    ContinuousMonitoring.jsx) already expects.
    """
    domain, _ = await _resolve_session_domain(session_id)

    score_rows = await fetch(
        """
        SELECT standard, total_rules, violated_rules, compliant_rules,
               score_percent, status, violated_rule_ids, checked_at
        FROM   compliance_scores
        WHERE  session_id = $1
        ORDER  BY checked_at DESC, standard ASC
        """,
        session_id,
    )

    if not score_rows:
        return None

    viol_rows = await fetch(
        """
        SELECT standard, rule_id, rule_name,
               severity, cvss_score, page_url, title, category,
               vuln_type, confidence
        FROM   compliance_violations
        WHERE  session_id = $1
        """,
        session_id,
    )

    # Group violations by standard
    by_std: dict[str, list[dict]] = {}
    for v in viol_rows:
        std = str(v.get("standard") or "").strip()
        by_std.setdefault(std, []).append({
            "rule_id":    v.get("rule_id") or "",
            "rule_name":  v.get("rule_name") or "",
            "severity":   _severity_label_from_numeric(v.get("severity")),
            "page_url":   v.get("page_url") or "",
            "title":      v.get("title") or "",
            "category":   v.get("category") or v.get("vuln_type") or "",
            "cvss_score": float(v.get("cvss_score") or 0.0),
        })

    standards: list[dict] = []
    overall_total_pct = 0.0
    for s in score_rows:
        name = str(s.get("standard") or "").strip()
        score_pct = float(s.get("score_percent") or 0.0)
        overall_total_pct += score_pct
        standards.append({
            "name":         name,
            "score":        score_pct,
            "status":       str(s.get("status") or ("PASS" if score_pct >= 80 else "FAIL")).upper(),
            "total_rules":  int(s.get("total_rules") or 0),
            "compliant":    int(s.get("compliant_rules") or 0),
            "violated":     int(s.get("violated_rules") or 0),
            "violations":   by_std.get(name, []),
            "checked_at":   s.get("checked_at").isoformat() if s.get("checked_at") else None,
        })

    overall = round(overall_total_pct / max(len(score_rows), 1), 2)

    return {
        "session_id":    session_id,
        "domain":        domain,
        "overall_score": overall,
        "standards":     standards,
    }


@router.get("/api/compliance/{session_id}")
async def compliance_for_session(
    session_id: str,
    user_id:    int = Depends(get_current_user_id),
):
    await _ensure_session_owned(session_id, user_id)
    data = await _build_compliance_payload(session_id)
    if not data:
        raise HTTPException(
            status_code = 404,
            detail      = "No compliance data for this session yet.",
        )
    return data


@router.get("/api/compliance/latest")
async def compliance_latest(user_id: int = Depends(get_current_user_id)):
    """Most-recent compliance report for any of the current user's scans."""
    row = await fetchrow(
        """
        SELECT cs.session_id::text AS session_id
        FROM   compliance_scores cs
        JOIN   scan_sessions     s  ON s.id::text = cs.session_id
        WHERE  s.user_id = $1
        ORDER  BY cs.checked_at DESC
        LIMIT  1
        """,
        user_id,
    )
    if not row:
        raise HTTPException(404, "No compliance data yet — run a scan first.")
    data = await _build_compliance_payload(row["session_id"])
    if not data:
        raise HTTPException(404, "Compliance data unavailable.")
    return data


# =============================================================================
# PREDICTIVE ENDPOINTS  (real data from posture_snapshots)
# =============================================================================

async def _latest_posture(domain: str) -> dict | None:
    return await fetchrow(
        """
        SELECT id, domain, security_score, risk_level, smoothed_score,
               trend_rate, trend_direction,
               pred_1d, pred_1d_level, pred_confidence, pred_model,
               anomaly_score, is_anomaly, anomaly_reason,
               vuln_count, critical_count, high_count, medium_count, low_count,
               breach_probability, risk_velocity, risk_volatility, volatility_label,
               forecast_7d, explanation, captured_at
        FROM   posture_snapshots
        WHERE  domain = $1
        ORDER  BY captured_at DESC
        LIMIT  1
        """,
        domain,
    )


async def _posture_history(domain: str, days: int = 28) -> list[dict]:
    rows = await fetch(
        """
        SELECT security_score, captured_at
        FROM   posture_snapshots
        WHERE  domain = $1
          AND  captured_at >= NOW() - ($2 || ' days')::INTERVAL
        ORDER  BY captured_at ASC
        """,
        domain, str(days),
    )
    return [dict(r) for r in rows]


async def _at_risk_pages(domain: str, limit: int = 5) -> list[dict]:
    """Top critical/high vulnerabilities → at-risk pages list for the UI."""
    rows = await fetch(
        """
        SELECT DISTINCT ON (page_url)
            page_url, title, cvss_score, priority_category, target_priority
        FROM   monitor_vulnerabilities
        WHERE  domain = $1
          AND  priority_category IN ('Critical', 'High')
        ORDER  BY page_url, COALESCE(target_priority, cvss_score, 0) DESC
        LIMIT  $2
        """,
        domain, limit,
    )
    return [
        {
            "url":    r.get("page_url"),
            "risk":   round(float(r.get("cvss_score") or 0.0), 1),
            "reason": str(r.get("title") or "Vulnerability detected"),
        }
        for r in rows
    ]


async def _build_predictive_payload(session_id: str | None, domain: str) -> dict[str, Any] | None:
    snap = await _latest_posture(domain)
    if not snap:
        return None

    # 7-day forecast — already computed by posture engine, stored as JSONB
    forecast_7d = snap.get("forecast_7d") or []
    forecast_ui = []
    for i, f in enumerate(forecast_7d, start=1):
        if not isinstance(f, dict):
            continue
        forecast_ui.append({
            "day":      f.get("day") or f"Day {i}",
            "expected": float(f.get("score") or 0.0),
            "lower":    float(f.get("lower_bound") or 0.0),
            "upper":    float(f.get("upper_bound") or 0.0),
            "date":     f.get("date"),
            "level":    f.get("level"),
        })

    # 4-week trend from history (collapse to weekly buckets)
    history = await _posture_history(domain, days=28)
    trend: list[dict] = []
    if history:
        buckets: dict[int, list[float]] = {0: [], 1: [], 2: [], 3: []}
        now = datetime.now(timezone.utc)
        for h in history:
            ts = h.get("captured_at")
            if isinstance(ts, str):
                ts = datetime.fromisoformat(ts)
            if ts and ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            if not ts:
                continue
            days_ago = (now - ts).days
            week_idx = min(3, max(0, days_ago // 7))
            buckets[3 - week_idx].append(float(h.get("security_score") or 0.0))
        for i in range(4):
            arr = buckets[i]
            avg = sum(arr) / len(arr) if arr else (
                float(snap.get("security_score") or 0.0)
            )
            trend.append({"day": f"W{i + 1}", "score": round(avg, 1)})

    direction       = str(snap.get("trend_direction") or "stable")
    risk_velocity   = float(snap.get("risk_velocity") or 0.0)
    delta_pct       = abs(round(risk_velocity, 1))
    confidence      = float(snap.get("pred_confidence") or 0.4)
    breach_prob     = float(snap.get("breach_probability") or 0.0)
    next_review_d   = 1 if direction == "increasing" else 7

    at_risk = await _at_risk_pages(domain, limit=5)

    return {
        "session_id": session_id,
        "domain":     domain,
        "forecast":   forecast_ui,
        "trend":      trend,
        "at_risk":    at_risk,
        "summary": {
            "direction":           direction if direction != "stable" else "decreasing",
            "delta_pct":           delta_pct,
            "confidence":          round(confidence, 2),
            "next_review_in_days": next_review_d,
            "breach_probability":  breach_prob,
            "current_score":       float(snap.get("security_score") or 0.0),
            "risk_level":          snap.get("risk_level"),
            "is_anomaly":          bool(snap.get("is_anomaly")),
        },
    }


@router.get("/api/predictive/{session_id}")
async def predictive_for_session(
    session_id: str,
    user_id:    int = Depends(get_current_user_id),
):
    await _ensure_session_owned(session_id, user_id)
    domain, _ = await _resolve_session_domain(session_id)
    if not domain:
        raise HTTPException(404, "Session has no resolvable domain.")
    data = await _build_predictive_payload(session_id, domain)
    if not data:
        raise HTTPException(
            404,
            "No predictive data for this domain yet — posture engine runs in "
            "continuous monitoring only.",
        )
    return data


@router.get("/api/predictive/latest")
async def predictive_latest(user_id: int = Depends(get_current_user_id)):
    """
    Latest posture for any monitored site this user owns.
    Joins on monitored_sites so a user can only see their own domains.
    """
    row = await fetchrow(
        """
        SELECT ps.domain
        FROM   posture_snapshots ps
        JOIN   monitored_sites   ms ON ms.domain = ps.domain
        WHERE  ms.user_id = $1
          AND  ms.is_active = TRUE
        ORDER  BY ps.captured_at DESC
        LIMIT  1
        """,
        user_id,
    )
    if not row:
        raise HTTPException(404, "No predictive data yet — add a site to monitoring.")
    data = await _build_predictive_payload(None, row["domain"])
    if not data:
        raise HTTPException(404, "Predictive data unavailable.")
    return data


# =============================================================================
# CRAWLER ENDPOINT  (live data for the Crawler page)
# =============================================================================

@router.get("/api/scan/crawler/{session_id}")
async def crawler_for_session(
    session_id: str,
    user_id:    int = Depends(get_current_user_id),
):
    await _ensure_session_owned(session_id, user_id)

    sess = await fetchrow(
        "SELECT url, status FROM scan_sessions WHERE id = $1::uuid",
        session_id,
    )
    if not sess:
        raise HTTPException(404, "Session not found")

    domain = _domain_from_url(sess.get("url"))

    # Pages: distinct done URLs from crawler_queue (it's the source of truth
    # for "what the crawler visited in this session").
    page_rows = await fetch(
        """
        SELECT DISTINCT ON (url) url, depth, status
        FROM   crawler_queue
        WHERE  session_id = $1::uuid
          AND  status     = 'done'
        ORDER  BY url, updated_at DESC
        LIMIT  500
        """,
        session_id,
    )
    pages = [
        {"url": r["url"], "depth": int(r.get("depth") or 0), "status": 200}
        for r in page_rows
    ]

    # Endpoints: discovered during this session via page_endpoints
    ep_rows = await fetch(
        """
        SELECT DISTINCT e.url, e.type, e.js_only
        FROM   endpoints       e
        JOIN   page_endpoints  pe ON pe.endpoint_id = e.id
        WHERE  pe.session_id = $1::uuid
        ORDER  BY e.url
        LIMIT  500
        """,
        session_id,
    )
    endpoints = [
        {"url": r["url"], "type": r.get("type") or "api", "js_only": bool(r.get("js_only"))}
        for r in ep_rows
    ]

    # Forms: filtered by session
    form_rows = await fetch(
        """
        SELECT f.action_url, f.method,
               COUNT(fi.id)::int AS input_count
        FROM   forms       f
        LEFT   JOIN form_inputs fi ON fi.form_id = f.id
        WHERE  f.session_id = $1::uuid
        GROUP  BY f.id
        ORDER  BY f.id
        LIMIT  500
        """,
        session_id,
    )
    forms = [
        {
            "action": r["action_url"],
            "method": r.get("method") or "GET",
            "inputs": int(r.get("input_count") or 0),
        }
        for r in form_rows
    ]

    # Recent queue (status timeline) — oldest first so UI scrolls correctly
    q_rows = await fetch(
        """
        SELECT url, status, depth, updated_at
        FROM   crawler_queue
        WHERE  session_id = $1::uuid
        ORDER  BY updated_at DESC
        LIMIT  30
        """,
        session_id,
    )
    queue = [
        {
            "url":    r["url"],
            "status": r.get("status") or "unknown",
            "depth":  int(r.get("depth") or 0),
        }
        for r in reversed(q_rows)
    ]

    return {
        "session_id": session_id,
        "domain":     domain,
        "status":     sess.get("status"),
        "pages":      pages,
        "endpoints":  endpoints,
        "forms":      forms,
        "queue":      queue,
    }

# =============================================================================
# REMEDIATION ENDPOINTS
# =============================================================================

@router.get("/api/remediation/{vulnerability_id}")
async def remediation_for_vuln(
    vulnerability_id: int,
    user_id:          int = Depends(get_current_user_id),
):
    """
    Get the remediation suggestion for ONE vulnerability.
    Looks in cache → static KB → Groq LLM → generic stub.
    """
    from .scanner.ai_remediation import get_remediation_for_vuln

    # Verify the vuln belongs to user
    row = await fetchrow(
        """
        SELECT v.id, v.page_url, v.title, v.category, v.cwe, v.severity,
               v.priority_category, v.session_id::text AS session_id
        FROM   vulnerabilities v
        JOIN   scan_sessions   s ON s.id = v.session_id
        WHERE  v.id = $1 AND s.user_id = $2
        """,
        vulnerability_id, user_id,
    )
    if not row:
        raise HTTPException(404, "Vulnerability not found")

    return await get_remediation_for_vuln(dict(row))


@router.get("/api/remediation/session/{session_id}")
async def remediations_for_session(
    session_id: str,
    user_id:    int = Depends(get_current_user_id),
):
    """
    Bulk: get every vuln in a scan session merged with its remediation.
    Frontend ScanDetail page calls this once.
    """
    await _ensure_session_owned(session_id, user_id)
    from .scanner.ai_remediation import get_remediations_for_session_async
    return await get_remediations_for_session_async(session_id)


# =============================================================================
# USER PREFERENCES (email alerts on/off, severity threshold)
# =============================================================================

from pydantic import BaseModel as _BaseModel


class _PrefsRequest(_BaseModel):
    email_enabled: bool | None = None
    min_severity:  str  | None = None


@router.get("/api/me/notifications")
async def get_my_prefs(user_id: int = Depends(get_current_user_id)):
    row = await fetchrow(
        """
        SELECT email_enabled, min_severity
        FROM   user_notification_preferences
        WHERE  user_id = $1
        """,
        user_id,
    )
    if not row:
        return {"email_enabled": True, "min_severity": "High"}
    return {
        "email_enabled": bool(row["email_enabled"]),
        "min_severity":  row["min_severity"] or "High",
    }


@router.put("/api/me/notifications")
async def update_my_prefs(
    body:    _PrefsRequest,
    user_id: int = Depends(get_current_user_id),
):
    sev = body.min_severity
    if sev and sev not in {"Critical", "High", "Medium", "Low"}:
        raise HTTPException(400, "Invalid min_severity")

    from .scanner.db import execute
    await execute(
        """
        INSERT INTO user_notification_preferences (user_id, email_enabled, min_severity)
        VALUES ($1, $2, $3)
        ON CONFLICT (user_id) DO UPDATE
            SET email_enabled = COALESCE(EXCLUDED.email_enabled, user_notification_preferences.email_enabled),
                min_severity  = COALESCE(EXCLUDED.min_severity,  user_notification_preferences.min_severity),
                updated_at    = NOW()
        """,
        user_id,
        body.email_enabled,
        sev,
    )
    return {"ok": True}