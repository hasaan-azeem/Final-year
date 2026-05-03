"""
ai_engine/detector.py
=====================
Core anomaly detection logic.

Two detection paths
-------------------
1. IsolationForest  — when domain has ≥ 20 normal snapshots and a trained model.
2. Cold-start rules — heuristic fallback before the model is ready.

Reason-building policy  (KEY FIX)
-----------------------------------
top_reasons and feature_deltas are ALWAYS populated, regardless of is_anomaly:

  anomaly=True  → features with z ≥ 1.5 (significant deviations), up to 6.
  anomaly=False → top-5 features by absolute deviation for context, even if
                  z-scores are all near 0 (homogeneous data).

Additionally, features that are persistently at a security-concerning level
(e.g. missing_csp_ratio=1.0 every scan) are surfaced as [Security] notes
regardless of z-score.  Attack-signal hits are always included.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

import numpy as np

from .baseline import compute_baseline_stats, load_normal_features
from .extractor import FEATURE_NAMES, SnapshotFeatures
from .trainer import load_model

logger = logging.getLogger("webxguard.ai_engine.detector")

# ---------------------------------------------------------------------------
# Cold-start threshold rules
# ---------------------------------------------------------------------------

COLD_START_RULES: dict[str, tuple[str, float]] = {
    "error_rate":             ("gt", 0.30),
    "rate_500":               ("gt", 0.10),
    "rate_403":               ("gt", 0.20),
    "sqli_pattern_count":     ("gt", 2),
    "xss_pattern_count":      ("gt", 2),
    "suspicious_path_count":  ("gt", 5),
    "missing_csp_ratio":      ("gt", 0.90),
    "post_ratio":             ("gt", 0.70),
    "request_burstiness":     ("gt", 3.0),
}

_SEVERITY_MAP = [
    (0.80, "critical"),
    (0.60, "high"),
    (0.40, "medium"),
    (0.0,  "low"),
]

# Features that deserve a note when their current value is security-concerning,
# even if the site always looks this way (z ≈ 0).
# Format string receives pct = value * 100.
_SECURITY_CONCERN_THRESHOLDS: dict[str, tuple[str, float, str]] = {
    "missing_csp_ratio":  ("gt", 0.80,
        "Content-Security-Policy absent on {pct:.0f}% of requests (persistent)"),
    "missing_hsts_ratio": ("gt", 0.80,
        "Strict-Transport-Security absent on {pct:.0f}% of requests (persistent)"),
    "missing_xfo_ratio":  ("gt", 0.80,
        "X-Frame-Options absent on {pct:.0f}% of requests (persistent)"),
    "error_rate":         ("gt", 0.20,
        "Error rate elevated at {pct:.0f}% of requests"),
    "rate_500":           ("gt", 0.05,
        "Server errors (5xx) on {pct:.0f}% of requests"),
}

_ANOMALY_REASON_Z = 1.5   # z-score threshold for anomaly reasons
_CONTEXT_TOP_N    = 5      # always emit this many features in feature_deltas


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------

@dataclass
class DetectionResult:
    domain:               str
    snapshot_uuid:        str
    anomaly_score:        float
    is_anomaly:           bool
    confidence:           float
    severity:             str
    top_reasons:          list[str]      = field(default_factory=list)
    feature_deltas:       dict[str, Any] = field(default_factory=dict)
    compared_to_baseline: bool           = False
    detection_method:     str            = "cold_start"
    model_version:        int | None     = None
    timestamp:            str            = field(
        default_factory=lambda: datetime.now(tz=timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain":               self.domain,
            "snapshot_uuid":        self.snapshot_uuid,
            "anomaly_score":        round(self.anomaly_score, 4),
            "is_anomaly":           self.is_anomaly,
            "confidence":           round(self.confidence, 4),
            "severity":             self.severity,
            "top_reasons":          self.top_reasons,
            "feature_deltas":       self.feature_deltas,
            "compared_to_baseline": self.compared_to_baseline,
            "detection_method":     self.detection_method,
            "model_version":        self.model_version,
            "timestamp":            self.timestamp,
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _map_severity(score: float) -> str:
    for threshold, label in _SEVERITY_MAP:
        if score >= threshold:
            return label
    return "low"


def _pct_change(current: float, baseline_mean: float) -> float | None:
    if abs(baseline_mean) < 1e-9:
        return None
    return round((current - baseline_mean) / abs(baseline_mean) * 100, 1)


def _build_reasons(
    features:       SnapshotFeatures,
    baseline_stats: dict[str, dict[str, float]],
    is_anomaly:     bool,
) -> tuple[list[str], dict[str, Any]]:
    """
    Build top_reasons and feature_deltas, always non-empty.

    1. Compute z-scores for every feature.
    2. Select reasons:
         anomaly=True  → features with z ≥ 1.5
         anomaly=False → top-5 by z (any score) for context
    3. Append persistent security concern notes.
    4. Append attack-signal hits.
    """
    fdict = features.to_dict()

    # ── Step 1: score every feature ───────────────────────────────────────
    scored: list[tuple[float, str, str, dict]] = []  # (z, reason_text, feat, delta)

    for feat in FEATURE_NAMES:
        current = float(fdict.get(feat, 0.0))
        if feat not in baseline_stats:
            continue
        stat = baseline_stats[feat]
        mean = stat["mean"]
        std  = stat["std"]
        z    = abs(current - mean) / (std + 1e-9)

        pct       = _pct_change(current, mean)
        direction = "above" if current > mean else "below"
        label     = feat.replace("_", " ").title()

        if pct is not None:
            reason = f"{label} is {abs(pct):.0f}% {direction} baseline (z={z:.1f})"
        else:
            reason = f"{label} = {current:.4f}  (baseline ≈ {mean:.4f}, z={z:.1f})"

        delta = {
            "current":       round(current, 4),
            "baseline_mean": round(mean,    4),
            "baseline_std":  round(std,     4),
            "z_score":       round(z,       2),
            "pct_change":    pct,
        }
        scored.append((z, reason, feat, delta))

    scored.sort(key=lambda x: x[0], reverse=True)

    # ── Step 2: select reasons and deltas ─────────────────────────────────
    reasons:     list[str]      = []
    deltas_dict: dict[str, Any] = {}

    if is_anomaly:
        # High-z deviations for anomaly explanation
        for z, reason, feat, delta in scored:
            if z >= _ANOMALY_REASON_Z and len(reasons) < 6:
                reasons.append(reason)
                deltas_dict[feat] = delta
        # Always include at least 1 feature in deltas for context
        for _, _, feat, delta in scored[:1]:
            if feat not in deltas_dict:
                deltas_dict[feat] = delta
    else:
        # Top-N context features regardless of z threshold
        for z, reason, feat, delta in scored[:_CONTEXT_TOP_N]:
            deltas_dict[feat] = delta
            if z >= 0.8:          # only add to readable reasons if notable
                reasons.append(reason)

    # ── Step 3: persistent security concerns ─────────────────────────────
    for feat, (op, threshold, template) in _SECURITY_CONCERN_THRESHOLDS.items():
        value = float(fdict.get(feat, 0.0))
        if op == "gt" and value > threshold:
            note = "[Security] " + template.format(pct=value * 100)
            if note not in reasons:
                reasons.append(note)
            # Also ensure it appears in deltas
            if feat not in deltas_dict and feat in baseline_stats:
                stat = baseline_stats[feat]
                deltas_dict[feat] = {
                    "current":       round(value, 4),
                    "baseline_mean": round(stat["mean"], 4),
                    "baseline_std":  round(stat["std"],  4),
                    "z_score":       round(
                        abs(value - stat["mean"]) / (stat["std"] + 1e-9), 2
                    ),
                    "pct_change":    _pct_change(value, stat["mean"]),
                }

    # ── Step 4: attack signals ────────────────────────────────────────────
    if features.sqli_pattern_count > 0:
        reasons.append(
            f"[Attack] SQL injection patterns ({features.sqli_pattern_count} occurrences)"
        )
    if features.xss_pattern_count > 0:
        reasons.append(
            f"[Attack] XSS patterns ({features.xss_pattern_count} occurrences)"
        )
    if features.suspicious_path_count > 0:
        reasons.append(
            f"[Attack] Suspicious admin/debug paths ({features.suspicious_path_count})"
        )

    # Fallback when truly nothing noteworthy at all
    if not reasons:
        reasons.append("No significant deviations from baseline detected")

    return reasons, deltas_dict


# ---------------------------------------------------------------------------
# Detection paths
# ---------------------------------------------------------------------------

def _cold_start_detect(
    domain:        str,
    snapshot_uuid: str,
    features:      SnapshotFeatures,
) -> DetectionResult:
    fdict     = features.to_dict()
    triggered: list[str] = []

    for feat, (op, threshold) in COLD_START_RULES.items():
        value = float(fdict.get(feat, 0.0))
        if (op == "gt" and value > threshold) or (op == "lt" and value < threshold):
            label = feat.replace("_", " ").title()
            triggered.append(
                f"[Cold-start] {label} = {value:.3f} exceeds threshold {threshold}"
            )

    # Persistent security concerns
    for feat, (op, threshold, template) in _SECURITY_CONCERN_THRESHOLDS.items():
        value = float(fdict.get(feat, 0.0))
        if op == "gt" and value > threshold:
            note = "[Security] " + template.format(pct=value * 100)
            if note not in triggered:
                triggered.append(note)

    # Attack signals
    if features.sqli_pattern_count > 0:
        triggered.append(f"[Attack] SQLi patterns ({features.sqli_pattern_count})")
    if features.xss_pattern_count > 0:
        triggered.append(f"[Attack] XSS patterns ({features.xss_pattern_count})")
    if features.suspicious_path_count > 0:
        triggered.append(f"[Attack] Suspicious paths ({features.suspicious_path_count})")

    if not triggered:
        triggered.append("No suspicious signals detected (cold-start baseline period)")

    # Only cold-start RULE hits count toward anomaly (not security/attack notes)
    rule_hits  = sum(1 for r in triggered if r.startswith("[Cold-start]"))
    is_anomaly = rule_hits >= 2
    score      = min(rule_hits / 6.0, 1.0)

    return DetectionResult(
        domain               = domain,
        snapshot_uuid        = snapshot_uuid,
        anomaly_score        = score,
        is_anomaly           = is_anomaly,
        confidence           = 0.50 if is_anomaly else 0.70,
        severity             = _map_severity(score),
        top_reasons          = triggered[:8],
        compared_to_baseline = False,
        detection_method     = "cold_start",
    )


def _isolation_forest_detect(
    domain:        str,
    snapshot_uuid: str,
    features:      SnapshotFeatures,
    model_version: int | None,
) -> DetectionResult:
    loaded = load_model(domain)
    if loaded is None:
        logger.warning("[Detector] No model for %s — cold-start fallback", domain)
        return _cold_start_detect(domain, snapshot_uuid, features)

    model, scaler = loaded

    vec          = np.array([features.to_vector()], dtype=float)
    vec_s        = scaler.transform(vec)
    raw_decision = float(model.decision_function(vec_s)[0])
    prediction   = int(model.predict(vec_s)[0])   # -1 anomaly, 1 normal

    anomaly_score = float(np.clip(0.5 - raw_decision, 0.0, 1.0))
    is_anomaly    = prediction == -1
    confidence    = min(abs(raw_decision) * 2.0, 1.0)

    normal_features = load_normal_features(domain)
    baseline_stats  = compute_baseline_stats(normal_features)
    reasons, deltas = _build_reasons(features, baseline_stats, is_anomaly)

    return DetectionResult(
        domain               = domain,
        snapshot_uuid        = snapshot_uuid,
        anomaly_score        = round(anomaly_score, 4),
        is_anomaly           = is_anomaly,
        confidence           = round(confidence, 4),
        severity             = _map_severity(anomaly_score),
        top_reasons          = reasons,
        feature_deltas       = deltas,
        compared_to_baseline = True,
        detection_method     = "isolation_forest",
        model_version        = model_version,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect(
    domain:        str,
    snapshot_uuid: str,
    features:      SnapshotFeatures,
    model_version: int | None = None,
) -> DetectionResult:
    """
    Run anomaly detection on one snapshot.
    Automatically selects IsolationForest vs cold-start path.
    """
    loaded = load_model(domain)

    if loaded is None:
        logger.info("[Detector] Cold-start path for %s (no model yet)", domain)
        result = _cold_start_detect(domain, snapshot_uuid, features)
    else:
        logger.info("[Detector] IsolationForest path for %s", domain)
        result = _isolation_forest_detect(domain, snapshot_uuid, features, model_version)

    logger.info(
        "[Detector] %s → score=%.3f  is_anomaly=%s  severity=%s  "
        "method=%s  reasons=%d",
        domain, result.anomaly_score, result.is_anomaly,
        result.severity, result.detection_method, len(result.top_reasons),
    )
    return result