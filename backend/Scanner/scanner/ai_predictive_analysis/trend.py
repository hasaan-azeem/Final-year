"""
posture/trend.py
================
EMA smoothing + rate-of-change direction from posture snapshots.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

logger = logging.getLogger("webxguard.posture.trend")

EMA_ALPHA     = 0.30   # 0 = no smoothing, 1 = no memory
STABLE_BAND   = 2.0    # ±%/h within which trend is "stable"
MIN_SNAPSHOTS = 2


def compute_trend(snapshots: list[dict]) -> dict:
    """
    Args:
        snapshots: list of dicts with 'security_score' and 'captured_at',
                   ordered oldest → newest.
    Returns:
        {
          "trend_rate":      float  — % change per hour (+ve = worsening)
          "trend_direction": str    — "increasing" | "decreasing" | "stable"
          "smoothed_score":  float  — EMA-smoothed current score
        }
    """
    if not snapshots:
        return {"trend_rate": 0.0, "trend_direction": "stable", "smoothed_score": 0.0}

    scores = [float(s["security_score"]) for s in snapshots]

    ema = scores[0]
    for s in scores[1:]:
        ema = EMA_ALPHA * s + (1.0 - EMA_ALPHA) * ema
    smoothed = round(ema, 2)

    if len(snapshots) < MIN_SNAPSHOTS:
        return {"trend_rate": 0.0, "trend_direction": "stable", "smoothed_score": smoothed}

    def _ts(row: dict) -> datetime:
        t = row.get("captured_at")
        if isinstance(t, str):
            t = datetime.fromisoformat(t)
        if t and t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return t or datetime.now(timezone.utc)

    oldest = snapshots[0]
    newest = snapshots[-1]
    elapsed_hours = max(
        (_ts(newest) - _ts(oldest)).total_seconds() / 3600,
        0.001,
    )

    delta     = float(newest["security_score"]) - float(oldest["security_score"])
    rate      = round(delta / elapsed_hours, 3)
    direction = (
        "stable"     if abs(rate) <= STABLE_BAND else
        "increasing" if rate > 0                 else
        "decreasing"
    )

    return {
        "trend_rate":      rate,
        "trend_direction": direction,
        "smoothed_score":  smoothed,
    }