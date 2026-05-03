"""
posture/anomaly.py
==================
IsolationForest anomaly detector for security posture scores.

Feature vector per snapshot:
  [security_score, trend_rate, vuln_count, critical_count, delta_vs_prev]

Two modes:
  - rule_based_anomaly()  : cold start (<30 snapshots)
  - AnomalyDetector.detect(): IsolationForest once enough history exists
"""
from __future__ import annotations

import logging
import pickle

import numpy as np

logger = logging.getLogger("webxguard.posture.anomaly")

MIN_TRAIN_ROWS = 30
RETRAIN_EVERY  = 50
CONTAMINATION  = 0.05   # expected ~5% anomalies

_cache:    dict[str, "AnomalyDetector"] = {}
_counters: dict[str, int]               = {}


def _build_features(snapshots: list[dict], idx: int) -> list[float] | None:
    if idx < 1:
        return None
    cur   = snapshots[idx]
    prev  = snapshots[idx - 1]
    score = float(cur.get("security_score") or 0.0)
    delta = score - float(prev.get("security_score") or 0.0)
    return [
        score,
        float(cur.get("trend_rate")     or 0.0),
        float(cur.get("vuln_count")     or 0),
        float(cur.get("critical_count") or 0),
        delta,
    ]


def _single_features(
    score: float, trend_rate: float,
    vuln_count: int, critical_count: int, prev_score: float,
) -> list[float]:
    return [score, trend_rate, float(vuln_count), float(critical_count), score - prev_score]


class AnomalyDetector:
    def __init__(self, model, scaler, threshold: float):
        self.model     = model
        self.scaler    = scaler
        self.threshold = threshold

    def detect(
        self, score: float, trend_rate: float,
        vuln_count: int, critical_count: int, prev_score: float,
    ) -> dict:
        try:
            feats = _single_features(score, trend_rate, vuln_count, critical_count, prev_score)
            X     = self.scaler.transform([feats])
            raw   = float(self.model.decision_function(X)[0])

            is_anomaly = raw < self.threshold
            confidence = round(
                min(1.0, abs(raw - self.threshold) / (abs(self.threshold) + 1e-6)), 3
            )

            delta = score - prev_score
            if is_anomaly:
                if delta > 15:
                    reason = f"Score spiked +{delta:.1f} pts in one cycle — likely mass vulnerability injection."
                elif delta < -15:
                    reason = f"Score dropped {delta:.1f} pts — unexpected remediation or data loss."
                elif critical_count > 5:
                    reason = f"{critical_count} Critical vulnerabilities detected simultaneously."
                elif abs(trend_rate) > 20:
                    reason = f"Extreme trend rate {trend_rate:+.1f}%/h detected."
                else:
                    reason = "Statistical anomaly vs historical baseline (IsolationForest)."
            else:
                reason = "Score within normal range for this domain."

            return {
                "anomaly_score": round(raw, 4),
                "is_anomaly":    is_anomaly,
                "reason":        reason,
                "confidence":    confidence,
            }
        except Exception as e:
            logger.error("[Anomaly] detect failed: %s", e)
            return {
                "anomaly_score": 0.0, "is_anomaly": False,
                "reason": "Detection unavailable.", "confidence": 0.0,
            }

    def to_bytes(self) -> bytes:
        return pickle.dumps({
            "model": self.model, "scaler": self.scaler, "threshold": self.threshold,
        })

    @classmethod
    def from_bytes(cls, data: bytes) -> "AnomalyDetector":
        d = pickle.loads(data)
        return cls(d["model"], d["scaler"], d["threshold"])


def train_anomaly(snapshots: list[dict], domain: str) -> "AnomalyDetector | None":
    if len(snapshots) < MIN_TRAIN_ROWS:
        logger.info("[Anomaly] %s: %d snapshots (need %d) — skipping",
                    domain, len(snapshots), MIN_TRAIN_ROWS)
        return None
    try:
        from sklearn.ensemble import IsolationForest
        from sklearn.preprocessing import StandardScaler

        rows = [
            f for i in range(1, len(snapshots))
            if (f := _build_features(snapshots, i)) is not None
        ]

        if len(rows) < 20:
            return None

        X      = np.array(rows, dtype=np.float64)
        scaler = StandardScaler()
        X_s    = scaler.fit_transform(X)

        model = IsolationForest(
            n_estimators=200, contamination=CONTAMINATION,
            random_state=42, n_jobs=-1,
        )
        model.fit(X_s)

        scores    = model.decision_function(X_s)
        threshold = float(np.percentile(scores, 5))
        flagged   = int(np.sum(scores < threshold))

        logger.info(
            "[Anomaly] %s — trained on %d rows  threshold=%.4f  flagged=%d (%.1f%%)",
            domain, len(rows), threshold, flagged, 100 * flagged / len(rows),
        )
        return AnomalyDetector(model, scaler, threshold)

    except ImportError:
        logger.warning("[Anomaly] scikit-learn not installed")
        return None
    except Exception as e:
        logger.error("[Anomaly] Training failed for %s: %s", domain, e, exc_info=True)
        return None


def get_detector(domain: str, snapshots: list[dict]) -> "AnomalyDetector | None":
    from .db import load_ml_model, save_ml_model

    _counters[domain] = _counters.get(domain, 0) + 1
    due = _counters[domain] % RETRAIN_EVERY == 0

    if due:
        detector = train_anomaly(snapshots, domain)
        if detector:
            _cache[domain] = detector
            save_ml_model(domain, "anomaly", detector.to_bytes(), {"rows": len(snapshots)})
            return detector

    if domain in _cache:
        return _cache[domain]

    raw = load_ml_model(domain, "anomaly")
    if raw:
        try:
            detector = AnomalyDetector.from_bytes(raw)
            _cache[domain] = detector
            return detector
        except Exception as e:
            logger.warning("[Anomaly] DB model corrupt for %s: %s", domain, e)

    detector = train_anomaly(snapshots, domain)
    if detector:
        _cache[domain] = detector
        save_ml_model(domain, "anomaly", detector.to_bytes(), {"rows": len(snapshots)})
    return detector


def rule_based_anomaly(score: float, prev_score: float, trend_rate: float) -> dict:
    """Simple threshold fallback when no IF model is available yet."""
    delta      = score - prev_score
    is_anomaly = abs(delta) > 20 or abs(trend_rate) > 25
    return {
        "anomaly_score": round(-abs(delta) / 100.0, 4),
        "is_anomaly":    is_anomaly,
        "reason": (
            f"Score changed {delta:+.1f} pts in one cycle." if is_anomaly
            else "Score within normal range (rule-based check)."
        ),
        "confidence": 0.5,
    }