"""
posture/engine.py
=================
Orchestrator — one call to run(domain) drives a complete posture cycle.
"""
from __future__ import annotations

import logging
import math
from collections import defaultdict
from datetime import datetime, timezone, timedelta
from typing import Any

import numpy as np

logger = logging.getLogger("webxguard.posture.engine")

_GRADES: list[tuple[float, str]] = [
    (90.0, "F"), (70.0, "D"), (50.0, "C"),
    (30.0, "B"), (10.0, "A"), (0.0,  "A+"),
]

def _grade(score: float) -> str:
    for threshold, letter in _GRADES:
        if score >= threshold:
            return letter
    return "A+"


def _pred_confidence(n: int) -> float:
    if n >= 500: return 0.90
    if n >= 200: return 0.80
    if n >= 50:  return 0.65
    return 0.40


def _breach_probability(score: float) -> float:
    prob = 100.0 / (1.0 + math.exp(-0.08 * (score - 50.0)))
    return round(prob, 1)


# ── Velocity + volatility ─────────────────────────────────────────────────────

def _velocity_and_volatility(snapshots: list[dict]) -> dict:
    """
    Groups snapshots into calendar days, computes daily deltas.

    Bug fixed: when history spans < 2 calendar days there are no deltas,
    giving std_dev = 0 → flat forecast bands. We now return MIN_VOLATILITY
    as a floor so the forecast always has a realistic uncertainty band.

    Also: velocity is capped at ±MAX_DAILY_RATE to prevent a short (< 2h)
    history window from producing absurd rates.
    """
    from .predictor import MAX_DAILY_RATE, MIN_VOLATILITY

    if len(snapshots) < 2:
        return {
            "risk_velocity":    0.0,
            "risk_volatility":  MIN_VOLATILITY,
            "volatility_label": "STABLE",
        }

    daily: dict[str, float] = {}
    for s in snapshots:
        ts = s.get("captured_at")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if ts and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts:
            daily[ts.strftime("%Y-%m-%d")] = float(s["security_score"])

    sorted_days = sorted(daily.keys())
    if len(sorted_days) < 2:
        return {
            "risk_velocity":    0.0,
            "risk_volatility":  MIN_VOLATILITY,
            "volatility_label": "STABLE",
        }

    deltas = [
        daily[sorted_days[i]] - daily[sorted_days[i - 1]]
        for i in range(1, len(sorted_days))
    ]

    raw_velocity = float(np.mean(deltas[-7:])) if deltas else 0.0
    # Cap velocity — a <2h trend window can give absurd pts/h values
    velocity = round(
        float(np.clip(raw_velocity, -MAX_DAILY_RATE, MAX_DAILY_RATE)), 3
    )

    vol_deltas  = deltas[-14:]
    raw_vol     = float(np.std(vol_deltas)) if len(vol_deltas) > 1 else 0.0
    # Floor volatility so forecast bands are never zero-width
    volatility  = round(max(raw_vol, MIN_VOLATILITY), 3)

    label = "VOLATILE" if volatility > 5.0 else "MODERATE" if volatility > 2.0 else "STABLE"

    return {
        "risk_velocity":    velocity,
        "risk_volatility":  volatility,
        "volatility_label": label,
    }


# ── 30-day daily history ──────────────────────────────────────────────────────

def _build_history_30d(snapshots: list[dict]) -> list[dict]:
    from .scorer import risk_level
    daily: dict[str, float] = {}
    for s in snapshots:
        ts = s.get("captured_at")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if ts and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts:
            daily[ts.strftime("%Y-%m-%d")] = float(s["security_score"])
    return [
        {"date": d, "score": daily[d], "level": risk_level(daily[d])}
        for d in sorted(daily.keys())
    ]


# ── Anomaly type split ────────────────────────────────────────────────────────

def _count_anomaly_types(snapshots: list[dict]) -> dict[str, int]:
    vuln_anom = temporal_anom = 0
    for s in snapshots:
        if not s.get("is_anomaly"):
            continue
        reason = (s.get("anomaly_reason") or "").lower()
        if any(kw in reason for kw in ("vuln", "inject", "spike", "critical")):
            vuln_anom += 1
        else:
            temporal_anom += 1
    return {"vuln_anomalies": vuln_anom, "temporal_anomalies": temporal_anom}


# ── Category distribution ─────────────────────────────────────────────────────

def _category_distribution(vulns: list[dict], anomalous_cats: set[str]) -> list[dict]:
    counts: dict[str, int] = defaultdict(int)
    for v in vulns:
        counts[(v.get("category") or "Unknown").strip()] += 1
    return sorted(
        [{"category": c, "count": n, "is_anomalous": c in anomalous_cats}
         for c, n in counts.items()],
        key=lambda x: x["count"], reverse=True,
    )


# ── Radar chart ───────────────────────────────────────────────────────────────

_RADAR_AXES = {
    "Auth":         ["auth", "session", "csrf", "cookie", "login", "jwt", "token"],
    "Input Val.":   ["xss", "injection", "sqli", "xxe", "traversal", "lfi", "rfi", "ssti"],
    "Data Prot.":   ["ssl", "tls", "crypto", "encrypt", "exposure", "sensitive", "leak"],
    "Config":       ["misconfiguration", "header", "hsts", "cors", "csp", "server"],
    "Access Ctrl":  ["idor", "privilege", "access", "permission", "authoriz", "broken"],
    "Exploit Risk": ["exploit", "rce", "command", "deseri", "upload", "path"],
}

def _build_radar(vulns: list[dict]) -> dict[str, float]:
    axis_scores: dict[str, float] = {ax: 0.0 for ax in _RADAR_AXES}
    for v in vulns:
        text = f"{v.get('category','')} {v.get('title','')}".lower()
        cvss = float(v.get("cvss_score") or 5.0)
        for axis, keywords in _RADAR_AXES.items():
            if any(kw in text for kw in keywords):
                axis_scores[axis] += cvss
    normaliser = max(len(vulns) * 0.3, 1.0)
    return {
        ax: round(min(100.0, val / normaliser * 10.0), 1)
        for ax, val in axis_scores.items()
    }


# ── Stable trend rate for forecasting ─────────────────────────────────────────

def _stable_rate_per_day(
    trend_rate_per_hour: float,
    history_snaps:       list[dict],
) -> float:
    """
    Convert trend_rate (%/h) to a capped, stable pts/day for forecasting.

    Bug fixed: raw conversion (* 24) produces absurd values when history
    spans only minutes. We instead use the actual daily delta from posture
    history if >= 2 calendar days exist, falling back to the capped hourly
    conversion only when history is too short.
    """
    from .predictor import MAX_DAILY_RATE

    # Prefer actual day-over-day delta if we have >= 2 days of history
    daily: dict[str, float] = {}
    for s in history_snaps:
        ts = s.get("captured_at")
        if isinstance(ts, str):
            ts = datetime.fromisoformat(ts)
        if ts and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if ts:
            daily[ts.strftime("%Y-%m-%d")] = float(s["security_score"])

    sorted_days = sorted(daily.keys())
    if len(sorted_days) >= 2:
        # Use last available daily delta — much more stable than intraday rate
        last_delta = daily[sorted_days[-1]] - daily[sorted_days[-2]]
        return round(float(np.clip(last_delta, -MAX_DAILY_RATE, MAX_DAILY_RATE)), 3)

    # Fallback: hourly rate × 24, capped
    raw = trend_rate_per_hour * 24
    return round(float(np.clip(raw, -MAX_DAILY_RATE, MAX_DAILY_RATE)), 3)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN RUN
# ─────────────────────────────────────────────────────────────────────────────

def run(
    domain:     str,
    session_id: str | None = None,
    *,
    vuln_days:  int = 30,
    vuln_limit: int = 2000,
    history_h:  int = 720,
) -> dict[str, Any]:
    from . import db, scorer, trend, predictor, anomaly, xai
    from .scorer import risk_level as rl

    now             = datetime.now(timezone.utc)
    captured_at_str = now.isoformat()

    # 1. Fetch vulns (deduplicated)
    vulns = db.fetch_monitor_vulns(domain, days=vuln_days, limit=vuln_limit)
    logger.info("[Engine] %s — %d vulns fetched", domain, len(vulns))

    # 2. Score
    score, counts, contributions = scorer.compute_score(vulns, now=now)
    current_risk = rl(score)
    logger.info("[Engine] %s — score=%.2f  risk=%s  counts=%s",
                domain, score, current_risk, counts)

    # 3. History
    history_snaps = db.fetch_posture_history(domain, hours=history_h)
    all_history   = db.fetch_all_posture_history(domain)

    # 4. Trend
    trend_data = trend.compute_trend(history_snaps)

    # Stable rate for forecasting — avoids noise from short history windows
    rate_per_day = _stable_rate_per_day(trend_data["trend_rate"], history_snaps)

    # 5. Velocity + volatility (with MIN_VOLATILITY floor)
    vel_vol = _velocity_and_volatility(history_snaps)

    # 6. Breach probability
    breach_prob = _breach_probability(score)

    # 7. ML predictor
    pred_model    = predictor.get_predictor(domain, all_history)
    pred_features = None

    if pred_model and all_history:
        synthetic = list(all_history) + [{
            "security_score": score,
            "smoothed_score": trend_data["smoothed_score"],
            "trend_rate":     trend_data["trend_rate"],
            "vuln_count":     counts["total"],
            "critical_count": counts["critical"],
            "high_count":     counts["high"],
            "anomaly_score":  0.0,
            "is_anomaly":     False,
            "captured_at":    now,
        }]
        pred_features = predictor._build_row(synthetic, len(synthetic) - 1)

    if pred_model and pred_features is not None:
        raw_preds  = pred_model.predict(pred_features)
        pred_1d    = raw_preds["1d"]
        model_used = "gbr_trained"
        confidence = _pred_confidence(len(all_history))
    else:
        raw_preds  = predictor.linear_predict(score, rate_per_day)
        pred_1d    = raw_preds["1d"]
        model_used = "linear_fallback"
        confidence = _pred_confidence(0)

    # 8. 7-day forecast (rate + volatility both capped/floored)
    forecast_7d = predictor.build_7day_forecast(
        current_score = score,
        trend_rate    = rate_per_day,
        volatility    = vel_vol["risk_volatility"],
        pred_1d       = pred_1d,
        now           = now,
    )

    # 9. Anomaly detection
    detector   = anomaly.get_detector(domain, all_history)
    prev_score = (
        float(history_snaps[-2]["security_score"])
        if len(history_snaps) >= 2 else score
    )

    if detector:
        anomaly_data  = detector.detect(
            score, trend_data["trend_rate"],
            counts["total"], counts["critical"], prev_score,
        )
        detector_kind = "isolation_forest"
    else:
        anomaly_data  = anomaly.rule_based_anomaly(score, prev_score, trend_data["trend_rate"])
        detector_kind = "rule_based"

    if anomaly_data["is_anomaly"]:
        logger.warning("[Engine] %s — ANOMALY: %s", domain, anomaly_data["reason"])

    recent_30     = history_snaps[-30:] if history_snaps else []
    anom_types    = _count_anomaly_types(recent_30)
    anomaly_count = sum(1 for s in recent_30 if s.get("is_anomaly"))

    # 10. Category distribution
    cat_counts: dict[str, int] = defaultdict(int)
    for v in vulns:
        cat_counts[(v.get("category") or "Unknown").strip()] += 1
    cat_values = list(cat_counts.values())
    cat_mean   = float(np.mean(cat_values)) if cat_values else 0.0
    cat_std    = float(np.std(cat_values))  if len(cat_values) > 1 else 1.0
    anomalous_cats = {
        c for c, n in cat_counts.items()
        if cat_std > 0 and (n - cat_mean) / cat_std > 1.5
    }
    category_dist = _category_distribution(vulns, anomalous_cats)

    # 11. XAI
    explanation = xai.build_explanation(vulns, contributions, pred_model, pred_features)

    # 12. 30-day history chart
    history_30d = _build_history_30d(history_snaps)

    # 13. Persist
    snapshot_id = db.save_snapshot(
        domain     = domain,
        session_id = session_id,
        score      = score,
        risk_level = current_risk,
        trend = {
            "trend_rate":      trend_data["trend_rate"],
            "trend_direction": trend_data["trend_direction"],
            "smoothed_score":  trend_data["smoothed_score"],
        },
        predictions = {
            "pred_1d":       pred_1d,
            "pred_1d_level": rl(pred_1d),
            "model_used":    model_used,
            "confidence":    confidence,
        },
        anomaly = {
            "anomaly_score": anomaly_data["anomaly_score"],
            "is_anomaly":    anomaly_data["is_anomaly"],
            "reason":        anomaly_data["reason"],
        },
        explanation        = explanation,
        counts             = counts,
        breach_probability = breach_prob,
        risk_velocity      = vel_vol["risk_velocity"],
        risk_volatility    = vel_vol["risk_volatility"],
        volatility_label   = vel_vol["volatility_label"],
        forecast_7d        = forecast_7d,
    )

    if snapshot_id:
        logger.info("[Engine] %s — snapshot saved id=%s", domain, snapshot_id)
    else:
        logger.error("[Engine] %s — snapshot FAILED to save", domain)

    return {
        "domain":      domain,
        "session_id":  session_id,
        "snapshot_id": snapshot_id,
        "captured_at": captured_at_str,

        "score":              score,
        "risk_level":         current_risk,
        "grade":              _grade(score),
        "breach_probability": breach_prob,
        "risk_velocity":      vel_vol["risk_velocity"],
        "risk_volatility":    vel_vol["risk_volatility"],
        "volatility_label":   vel_vol["volatility_label"],
        "anomaly_count":      anomaly_count,

        "trend": {
            "rate_per_day":  rate_per_day,
            "rate_per_hour": trend_data["trend_rate"],
            "direction":     trend_data["trend_direction"],
            "smoothed":      trend_data["smoothed_score"],
        },

        "forecast_7d":  forecast_7d,
        "history_30d":  history_30d,

        "anomaly": {
            "score":              anomaly_data["anomaly_score"],
            "is_anomaly":         anomaly_data["is_anomaly"],
            "reason":             anomaly_data["reason"],
            "confidence":         anomaly_data.get("confidence", 0.5),
            "detector":           detector_kind,
            "vuln_anomalies":     anom_types["vuln_anomalies"],
            "temporal_anomalies": anom_types["temporal_anomalies"],
        },

        "counts":        counts,
        "category_dist": category_dist,
        "radar":         _build_radar(vulns),

        "predictions": {
            "pred_1d":    pred_1d,
            "model":      model_used,
            "confidence": confidence,
        },

        "explanation": explanation,
    }


def get_latest(domain: str) -> dict[str, Any] | None:
    from . import db
    return db.get_latest_snapshot(domain)