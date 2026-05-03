"""
app/scanner/alerts/triggers.py
==============================
High-level alert trigger functions. Call these from the existing engines —
they wrap the business rules (which findings deserve an alert, what severity,
how to phrase the title) so the engine code stays clean.

Three sources:
  alert_from_posture_sync        ← call from monitoring_main._run_posture_engine
  alert_from_ai_anomaly_sync     ← call from monitoring_main._run_anomaly_detection
  alert_from_scan_completion_async ← call from app.core._run_scan_bg

All sync functions are safe to call from inside run_in_executor threads.
"""
from __future__ import annotations

import logging
from typing import Any

from .manager import (
    create_alert_async,
    fanout_alert_sync,
)

logger = logging.getLogger("webxguard.alerts.triggers")


# ─────────────────────────────────────────────────────────────────────────────
# Posture engine  (sync — runs in executor)
# ─────────────────────────────────────────────────────────────────────────────

def alert_from_posture_sync(domain: str, payload: dict[str, Any]) -> int:
    """
    payload is the dict returned by ai_predictive_analysis.engine.run().
    Creates alerts for any of:
      • is_anomaly = True                     → severity from anomaly score
      • risk_level = "Critical"               → severity Critical
      • breach_probability >= 80              → severity High
      • risk_velocity >= 10 pts/day worsening → severity High

    Returns total alerts inserted (after dedup).
    """
    if not isinstance(payload, dict):
        return 0

    score              = float(payload.get("score") or 0.0)
    risk_level         = str(payload.get("risk_level") or "").strip()
    breach_probability = float(payload.get("breach_probability") or 0.0)
    risk_velocity      = float(payload.get("risk_velocity") or 0.0)
    snapshot_id        = payload.get("snapshot_id")
    session_id         = payload.get("session_id")

    anomaly = payload.get("anomaly") or {}
    is_anom = bool(anomaly.get("is_anomaly"))
    a_score = float(anomaly.get("score") or 0.0)
    a_reason = str(anomaly.get("reason") or "Unknown anomaly")
    a_conf  = float(anomaly.get("confidence") or 0.5)

    inserted = 0

    # 1) Anomaly alert
    if is_anom:
        sev = (
            "Critical" if a_score >= 0.7 or a_conf >= 0.8 else
            "High"     if a_score >= 0.4 else
            "Medium"
        )
        inserted += fanout_alert_sync(
            domain        = domain,
            severity      = sev,
            source        = "posture_anomaly",
            title         = f"Security posture anomaly detected on {domain}",
            description   = a_reason,
            scan_session  = session_id,
            posture_snapshot_id = snapshot_id,
            metadata      = {
                "score":              score,
                "risk_level":         risk_level,
                "anomaly_score":      a_score,
                "anomaly_confidence": a_conf,
                "breach_probability": breach_probability,
                "risk_velocity":      risk_velocity,
                "detector":           anomaly.get("detector"),
            },
            fingerprint   = f"posture_anomaly:{domain}",
            dedup_hours   = 6,
        )

    # 2) Critical posture alert (independent — even non-anomalous data can be Critical)
    if risk_level.lower() == "critical":
        inserted += fanout_alert_sync(
            domain        = domain,
            severity      = "Critical",
            source        = "posture_critical",
            title         = f"{domain} posture is Critical (score {score:.0f}/100)",
            description   = (
                f"Risk level Critical — {payload.get('counts', {}).get('critical', 0)} "
                f"critical findings, breach probability {breach_probability:.0f}%."
            ),
            scan_session  = session_id,
            posture_snapshot_id = snapshot_id,
            metadata      = {
                "score":              score,
                "breach_probability": breach_probability,
                "counts":             payload.get("counts"),
            },
            fingerprint   = f"posture_critical:{domain}",
            dedup_hours   = 12,
        )
    elif breach_probability >= 80.0:
        # High breach prob without Critical risk — separate alert
        inserted += fanout_alert_sync(
            domain        = domain,
            severity      = "High",
            source        = "posture_critical",
            title         = f"High breach probability on {domain} ({breach_probability:.0f}%)",
            description   = "Predictive model estimates an unusually high near-term breach risk.",
            scan_session  = session_id,
            posture_snapshot_id = snapshot_id,
            metadata      = {"breach_probability": breach_probability, "score": score},
            fingerprint   = f"breach_prob:{domain}",
            dedup_hours   = 12,
        )

    # 3) Rapidly worsening trend
    if risk_velocity >= 10.0:
        inserted += fanout_alert_sync(
            domain        = domain,
            severity      = "High",
            source        = "posture_critical",
            title         = f"Security score worsening on {domain} ({risk_velocity:+.1f} pts/day)",
            description   = "Daily security score is degrading faster than the safe threshold.",
            scan_session  = session_id,
            metadata      = {"risk_velocity": risk_velocity, "score": score},
            fingerprint   = f"posture_velocity:{domain}",
            dedup_hours   = 24,
        )

    if inserted:
        logger.info("[Alerts] posture → %d alert(s) for %s", inserted, domain)
    return inserted


# ─────────────────────────────────────────────────────────────────────────────
# AI anomaly engine  (sync — runs in executor)
# ─────────────────────────────────────────────────────────────────────────────

def alert_from_ai_anomaly_sync(domain: str, result: dict[str, Any]) -> int:
    """
    result is the dict returned by ai_anamoly_detection.main.run_anomaly_detection().
    Only fires when is_anomaly is True.
    """
    if not isinstance(result, dict) or not result.get("is_anomaly"):
        return 0

    severity      = str(result.get("severity") or "Medium").capitalize()
    score         = float(result.get("anomaly_score") or 0.0)
    confidence    = float(result.get("confidence") or 0.5)
    method        = str(result.get("detection_method") or "unknown")
    reasons       = result.get("top_reasons") or []
    snapshot_uuid = result.get("snapshot_uuid")

    title = f"Network behaviour anomaly on {domain}"
    if reasons:
        # Use the first reason as the human-readable headline
        title = f"{reasons[0][:120]}"

    description = (
        " | ".join(str(r) for r in reasons[:3]) if reasons
        else f"IsolationForest detected anomalous traffic pattern (method={method})."
    )

    inserted = fanout_alert_sync(
        domain        = domain,
        severity      = severity,
        source        = "ai_anomaly",
        title         = title,
        description   = description,
        snapshot_uuid = snapshot_uuid,
        scan_session  = result.get("session_id"),
        metadata      = {
            "anomaly_score":     score,
            "confidence":        confidence,
            "detection_method":  method,
            "model_version":     result.get("model_version"),
            "reasons":           reasons[:6],
            "feature_deltas":    result.get("feature_deltas"),
        },
        fingerprint   = f"ai_anomaly:{domain}:{severity}",
        dedup_hours   = 4,
    )

    if inserted:
        logger.info("[Alerts] ai_anomaly → %d alert(s) for %s", inserted, domain)
    return inserted


# ─────────────────────────────────────────────────────────────────────────────
# Scan completion  (async — runs inside the FastAPI background task)
# ─────────────────────────────────────────────────────────────────────────────

# How many findings to surface per finished scan (rest are visible on the scan page)
_MAX_PER_SCAN = 5


def _severity_label_from_priority(category: str | None, cvss: float | None) -> str:
    """Map vulnerabilities.priority_category (or cvss) to alert severity."""
    if category:
        c = str(category).strip().capitalize()
        if c in {"Critical", "High", "Medium", "Low"}:
            return c
    cv = float(cvss or 0.0)
    if cv >= 9.0: return "Critical"
    if cv >= 7.0: return "High"
    if cv >= 4.0: return "Medium"
    return "Low"


async def alert_from_scan_completion_async(
    *,
    user_id:    int,
    session_id: str,
    domain:     str | None = None,
) -> int:
    """
    After a one-shot scan finishes, read its top Critical/High findings
    from `vulnerabilities` and create one alert per finding (up to _MAX_PER_SCAN).
    """
    from ..db import fetch, fetchrow

    if not user_id or not session_id:
        return 0

    # Resolve a sensible domain string for the alert (if caller didn't pass one)
    if not domain:
        row = await fetchrow(
            "SELECT url FROM scan_sessions WHERE id = $1::uuid",
            session_id,
        )
        url = (row or {}).get("url") or ""
        try:
            from urllib.parse import urlparse
            domain = urlparse(url).hostname or url
        except Exception:
            domain = url
    domain = domain or "unknown"

    rows = await fetch(
        """
        SELECT id, page_url, title, category, confidence,
               cvss_score, severity, severity_level,
               target_priority, priority_category
        FROM   vulnerabilities
        WHERE  session_id = $1::uuid
          AND  priority_category IN ('Critical', 'High')
        ORDER  BY COALESCE(target_priority, cvss_score, 0) DESC
        LIMIT  $2
        """,
        session_id, _MAX_PER_SCAN,
    )

    inserted = 0
    for r in rows:
        sev = _severity_label_from_priority(
            r.get("priority_category"), r.get("cvss_score"),
        )
        title = str(r.get("title") or "Unknown finding")[:200]
        cvss  = float(r.get("cvss_score") or 0.0)

        new_id = await create_alert_async(
            user_id      = user_id,
            domain       = domain,
            severity     = sev,
            source       = "vuln_scan",
            title        = title,
            description  = (
                f"{r.get('category') or 'Vulnerability'} on "
                f"{r.get('page_url') or domain} — "
                f"CVSS {cvss:.1f}, confidence {r.get('confidence') or 'firm'}"
            ),
            url          = r.get("page_url"),
            scan_session = session_id,
            metadata     = {
                "vulnerability_id": int(r.get("id") or 0),
                "cvss_score":       cvss,
                "category":         r.get("category"),
                "confidence":       r.get("confidence"),
                "target_priority":  float(r.get("target_priority") or 0.0),
            },
            fingerprint  = f"vuln:{user_id}:{r.get('title')}:{r.get('page_url')}",
            dedup_hours  = 24,
        )
        if new_id:
            inserted += 1

    if inserted:
        logger.info(
            "[Alerts] scan_completion → %d alert(s)  user=%s  session=%s  domain=%s",
            inserted, user_id, session_id, domain,
        )
    return inserted