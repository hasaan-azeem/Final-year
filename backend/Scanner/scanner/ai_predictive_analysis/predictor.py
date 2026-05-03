"""
posture/predictor.py
====================
GradientBoostingRegressor predicting security score at +1 day.
Engine extrapolates to a full 7-day daily forecast series.

Minimum rows: 50 snapshots to train; falls back to linear extrapolation.
Retrain:      every RETRAIN_EVERY cycles per domain.
Cache:        in-memory per domain; DB load on cold start.
"""
from __future__ import annotations

import logging
import math
import pickle
from datetime import datetime, timezone, timedelta

import numpy as np

logger = logging.getLogger("webxguard.posture.predictor")

MIN_TRAIN_ROWS = 50
RETRAIN_EVERY  = 50

HORIZONS = {
    "1d": timedelta(days=1)
}  # 1 day at 5-min intervals

# Maximum credible daily rate change for linear fallback.
# Prevents wild extrapolation when trend is computed from < 2h of history.
MAX_DAILY_RATE = 15.0   # pts/day cap — site can't realistically change 15+ pts/day

# Minimum volatility when not enough history exists for std-dev calculation.
# Gives the forecast a realistic uncertainty band even on day 1.
MIN_VOLATILITY = 2.5    # pts — roughly ±2.5 pts base uncertainty

FEATURE_COLS = [
    "current_score", "smoothed_score", "trend_rate",
    "vuln_count", "critical_count", "high_count",
    "rolling_mean", "rolling_std", "rolling_max",
    "delta_1h", "delta_6h",
    "hour_sin", "hour_cos", "dow_sin", "dow_cos",
]

FEATURE_LABELS = {
    "current_score":  "Current Security Score",
    "smoothed_score": "EMA-Smoothed Score",
    "trend_rate":     "Trend Rate (pts/day)",
    "vuln_count":     "Total Vulnerabilities",
    "critical_count": "Critical Vulns",
    "high_count":     "High Vulns",
    "rolling_mean":   "Rolling Mean (12 pts)",
    "rolling_std":    "Rolling Std Dev (12 pts)",
    "rolling_max":    "Rolling Max (12 pts)",
    "delta_1h":       "Score Delta vs 1h Ago",
    "delta_6h":       "Score Delta vs 6h Ago",
    "hour_sin":       "Hour of Day (sin)",
    "hour_cos":       "Hour of Day (cos)",
    "dow_sin":        "Day of Week (sin)",
    "dow_cos":        "Day of Week (cos)",
}

_cache:    dict[str, "PosturePredictor"] = {}
_counters: dict[str, int]               = {}


# ── Feature engineering ───────────────────────────────────────────────────────

def _cyclic(value: float, period: float) -> tuple[float, float]:
    a = 2 * math.pi * value / period
    return math.sin(a), math.cos(a)


def _build_row(snapshots: list[dict], idx: int) -> list[float] | None:
    if idx < 6:
        return None
    current = snapshots[idx]
    window  = [float(s["security_score"]) for s in snapshots[max(0, idx - 12): idx]]

    ts = current.get("captured_at")
    if isinstance(ts, str):
        ts = datetime.fromisoformat(ts)
    if ts and ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)

    hour_sin, hour_cos = _cyclic(ts.hour      if ts else 12, 24)
    dow_sin,  dow_cos  = _cyclic(ts.weekday() if ts else 0,  7)

    score    = float(current["security_score"])
    delta_1h = score - float(snapshots[max(0, idx - 12)]["security_score"]) if idx >= 12 else 0.0
    delta_6h = score - float(snapshots[max(0, idx - 72)]["security_score"]) if idx >= 72 else 0.0

    return [
        score,
        float(current.get("smoothed_score") or score),
        float(current.get("trend_rate")     or 0.0),
        float(current.get("vuln_count")     or 0),
        float(current.get("critical_count") or 0),
        float(current.get("high_count")     or 0),
        float(np.mean(window)) if window else score,
        float(np.std(window))  if window else 0.0,
        float(np.max(window))  if window else score,
        delta_1h, delta_6h,
        hour_sin, hour_cos,
        dow_sin,  dow_cos,
    ]


# ── Model ─────────────────────────────────────────────────────────────────────

class PosturePredictor:
    def __init__(self, models: dict, scaler, X_train: np.ndarray):
        self.models  = models
        self.scaler  = scaler
        self.X_train = X_train

    def predict(self, features: list[float]) -> dict[str, float]:
        X = self.scaler.transform([features])
        return {
            label: float(np.clip(gbr.predict(X)[0], 0.0, 100.0))
            for label, gbr in self.models.items()
        }

    def to_bytes(self) -> bytes:
        return pickle.dumps({"models": self.models, "scaler": self.scaler})

    @classmethod
    def from_bytes(cls, data: bytes) -> "PosturePredictor":
        d = pickle.loads(data)
        return cls(d["models"], d["scaler"], X_train=np.zeros((1, len(FEATURE_COLS))))


# ── Trainer ───────────────────────────────────────────────────────────────────

def train_predictor(snapshots: list[dict], domain: str) -> "PosturePredictor | None":
    if len(snapshots) < MIN_TRAIN_ROWS:
        logger.info("[Predictor] %s: %d snapshots (need %d) — skipping",
                    domain, len(snapshots), MIN_TRAIN_ROWS)
        return None

    try:
        from sklearn.ensemble import GradientBoostingRegressor
        from sklearn.preprocessing import StandardScaler
        from sklearn.metrics import r2_score, mean_absolute_error

        def _parse_ts(x):
            if isinstance(x, str):
                x = datetime.fromisoformat(x)
            return x.replace(tzinfo=timezone.utc) if x.tzinfo is None else x

        X_rows: list[list[float]] = []
        targets: dict[str, list[float]] = {h: [] for h in HORIZONS}

        snapshots = [
            {**s, "captured_at": _parse_ts(s["captured_at"])}
            for s in snapshots
        ]

        for i in range(len(snapshots)):
            row = _build_row(snapshots, i)
            if row is None:
                continue

            current_time = snapshots[i]["captured_at"]

            valid = True
            t: dict[str, float] = {}

            for label, horizon in HORIZONS.items():

                # 🔥 TIME-BASED TARGET LOOKUP (GENERALIZED)
                target_time = current_time + horizon

                future = None
                for j in range(i + 1, len(snapshots)):
                    if snapshots[j]["captured_at"] >= target_time:
                        future = snapshots[j]
                        break

                if future is None:
                    valid = False
                    break

                t[label] = float(future["security_score"])

            if not valid:
                continue

            X_rows.append(row)
            for label in HORIZONS:
                targets[label].append(t[label])

        if len(X_rows) < 20:
            logger.warning("[Predictor] %s: only %d usable rows", domain, len(X_rows))
            return None

        X = np.array(X_rows, dtype=np.float64)

        scaler = StandardScaler()
        X_s = scaler.fit_transform(X)

        models: dict = {}

        for label in HORIZONS:
            y = np.array(targets[label], dtype=np.float64)

            gbr = GradientBoostingRegressor(
                n_estimators=150,
                max_depth=4,
                learning_rate=0.08,
                subsample=0.8,
                random_state=42,
            )

            gbr.fit(X_s, y)
            y_pred = gbr.predict(X_s)

            logger.info(
                "[Predictor] %s  %s  R2=%.4f  MAE=%.3f",
                domain, label,
                r2_score(y, y_pred),
                mean_absolute_error(y, y_pred),
            )

            models[label] = gbr

        logger.info("[Predictor] %s — trained on %d rows", domain, len(X_rows))

        return PosturePredictor(models, scaler, X_train=X)

    except ImportError:
        logger.warning("[Predictor] scikit-learn not installed")
        return None

    except Exception as e:
        logger.error("[Predictor] Training failed for %s: %s", domain, e, exc_info=True)
        return None

# ── Cache + load ──────────────────────────────────────────────────────────────

def get_predictor(domain: str, snapshots: list[dict]) -> "PosturePredictor | None":
    from .db import load_ml_model, save_ml_model

    _counters[domain] = _counters.get(domain, 0) + 1
    due = _counters[domain] % RETRAIN_EVERY == 0

    if due:
        model = train_predictor(snapshots, domain)
        if model:
            _cache[domain] = model
            save_ml_model(domain, "predictor", model.to_bytes(), {"rows": len(snapshots)})
            return model

    if domain in _cache:
        return _cache[domain]

    raw = load_ml_model(domain, "predictor")
    if raw:
        try:
            model = PosturePredictor.from_bytes(raw)
            _cache[domain] = model
            return model
        except Exception as e:
            logger.warning("[Predictor] DB model corrupt for %s: %s", domain, e)

    model = train_predictor(snapshots, domain)
    if model:
        _cache[domain] = model
        save_ml_model(domain, "predictor", model.to_bytes(), {"rows": len(snapshots)})
    return model


# ── 7-day daily forecast ──────────────────────────────────────────────────────

def build_7day_forecast(
    current_score: float,
    trend_rate:    float,        # pts/day — will be capped internally
    volatility:    float,        # historical std dev for uncertainty band
    pred_1d:       float | None = None,
    now:           datetime | None = None,
) -> list[dict]:
    """
    Build a 7-element daily forecast.

    Caps:
      - effective_rate is clamped to ±MAX_DAILY_RATE (15 pts/day) to prevent
        wild extrapolation when trend is computed from only minutes of history.
      - volatility is floored at MIN_VOLATILITY (2.5) so bands are never flat.

    Day 1  → ML pred_1d if available, else capped linear.
    Day 2+ → weighted blend: ML-implied rate (60%) + trend_rate (40%), capped.
    Band   → ±(volatility × sqrt(day)).
    """
    from .scorer import risk_level

    if now is None:
        now = datetime.now(timezone.utc)

    # Floor volatility so uncertainty bands are never zero-width
    effective_vol = max(float(volatility), MIN_VOLATILITY)

    if pred_1d is not None:
        ml_daily_rate  = pred_1d - current_score
        raw_rate       = ml_daily_rate * 0.60 + trend_rate * 0.40
    else:
        raw_rate = trend_rate

    # Cap rate to prevent noise-driven runaway forecasts
    effective_rate = float(np.clip(raw_rate, -MAX_DAILY_RATE, MAX_DAILY_RATE))

    if abs(raw_rate) > MAX_DAILY_RATE:
        logger.debug(
            "[Predictor] forecast rate capped %.2f → %.2f pts/day",
            raw_rate, effective_rate,
        )

    forecast = []
    for day in range(1, 8):
        date_str = (now + timedelta(days=day)).strftime("%Y-%m-%d")

        if day == 1 and pred_1d is not None:
            score = pred_1d
        else:
            score = current_score + effective_rate * day

        score = round(float(np.clip(score, 0.0, 100.0)), 2)
        band  = round(effective_vol * math.sqrt(day), 2)

        forecast.append({
            "day":         day,
            "date":        date_str,
            "score":       score,
            "level":       risk_level(score),
            "lower_bound": round(max(0.0,   score - band), 2),
            "upper_bound": round(min(100.0, score + band), 2),
        })

    return forecast


def linear_predict(current_score: float, trend_rate: float) -> dict[str, float]:
    """
    Fallback 1-day prediction when no ML model is available.
    trend_rate is capped at ±MAX_DAILY_RATE before use.
    """
    capped = float(np.clip(trend_rate, -MAX_DAILY_RATE, MAX_DAILY_RATE))
    return {
        "1d": round(float(np.clip(current_score + capped, 0.0, 100.0)), 2),
    }