"""
ai_engine/baseline.py
=====================
Per-domain historical baseline management.

Responsibilities
----------------
* Persist SnapshotFeatures rows to ai_snapshot_features.
* Load normal (non-anomalous) history for a domain.
* Gate training / retraining decisions.
* Compute mean/std baseline statistics used for explainability.

Minimum-sample policy
---------------------
MIN_SAMPLES_FOR_TRAINING   = 20   — first real model
MIN_NEW_NORMAL_FOR_RETRAIN = 20   — incremental retrain trigger (raised from 10
                                    to avoid score oscillation on homogeneous data)
RETRAIN_ANOMALY_GUARD      = 0.30 — skip retrain if >30% recent are anomalous
LOW_VARIANCE_GUARD         = 0.02 — skip retrain if mean feature std < this
                                    (data is too homogeneous to improve model)
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

import numpy as np
from sqlalchemy import desc, func, select, update

from .db import get_session
from .extractor import FEATURE_NAMES, SnapshotFeatures
from .schemas import AISnapshotFeatures

logger = logging.getLogger("webxguard.ai_engine.baseline")

MIN_SAMPLES_FOR_TRAINING:   int   = 20
MIN_NEW_NORMAL_FOR_RETRAIN: int   = 20   # raised from 10 → less oscillation
RETRAIN_ANOMALY_GUARD:      float = 0.30
LOW_VARIANCE_GUARD:         float = 0.02  # mean std across features
BASELINE_WINDOW_DAYS:       int   = 90
MAX_BASELINE_ROWS:          int   = 500


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_snapshot_features(
    domain:        str,
    snapshot_uuid: str,
    features:      SnapshotFeatures,
    session_id:    str | None = None,
) -> None:
    """Upsert the feature row for (domain, snapshot_uuid)."""
    import uuid as _u

    fdict = features.to_dict()

    sid = None
    if session_id:
        try:
            sid = _u.UUID(session_id)
        except ValueError:
            sid = None

    snap_uuid = _u.UUID(snapshot_uuid) if isinstance(snapshot_uuid, str) else snapshot_uuid

    with get_session() as session:
        existing = session.execute(
            select(AISnapshotFeatures).where(
                AISnapshotFeatures.domain        == domain,
                AISnapshotFeatures.snapshot_uuid == snap_uuid,
            )
        ).scalar_one_or_none()

        if existing:
            for col, val in fdict.items():
                setattr(existing, col, val)
            existing.feature_vector = fdict
        else:
            row = AISnapshotFeatures(
                domain          = domain,
                snapshot_uuid   = snap_uuid,
                session_id      = sid,
                feature_vector  = fdict,
                **fdict,
            )
            session.add(row)

    logger.debug("[Baseline] Saved features  domain=%s  uuid=%s", domain, snapshot_uuid)


def mark_anomaly_label(
    domain:        str,
    snapshot_uuid: str,
    is_anomaly:    bool,
    anomaly_score: float,
) -> None:
    """Back-fill is_anomaly / anomaly_score after detection."""
    import uuid as _u
    snap_uuid = _u.UUID(snapshot_uuid) if isinstance(snapshot_uuid, str) else snapshot_uuid

    with get_session() as session:
        session.execute(
            update(AISnapshotFeatures)
            .where(
                AISnapshotFeatures.domain        == domain,
                AISnapshotFeatures.snapshot_uuid == snap_uuid,
            )
            .values(is_anomaly=is_anomaly, anomaly_score=anomaly_score)
        )


# ---------------------------------------------------------------------------
# Loading history
# ---------------------------------------------------------------------------

def load_normal_features(
    domain:      str,
    max_rows:    int = MAX_BASELINE_ROWS,
    window_days: int = BASELINE_WINDOW_DAYS,
) -> list[dict[str, float]]:
    """
    Return feature dicts for the most recent normal snapshots within the
    rolling window.  Rows with is_anomaly=TRUE are excluded so the model
    never trains on known bad data.
    """
    cutoff = datetime.now(tz=timezone.utc) - timedelta(days=window_days)

    with get_session() as session:
        rows = session.execute(
            select(AISnapshotFeatures)
            .where(
                AISnapshotFeatures.domain     == domain,
                AISnapshotFeatures.created_at >= cutoff,
                (AISnapshotFeatures.is_anomaly == False)
                | (AISnapshotFeatures.is_anomaly == None),
            )
            .order_by(desc(AISnapshotFeatures.created_at))
            .limit(max_rows)
        ).scalars().all()

    result = []
    for row in rows:
        if row.feature_vector and isinstance(row.feature_vector, dict):
            result.append({k: float(row.feature_vector.get(k, 0)) for k in FEATURE_NAMES})
        else:
            result.append(row.to_feature_dict())

    logger.debug("[Baseline] Loaded %d normal rows for %s", len(result), domain)
    return result


def count_recent_anomalies(domain: str, last_n: int = 50) -> tuple[int, int]:
    """Return (anomaly_count, total) among the last *last_n* snapshots."""
    with get_session() as session:
        rows = session.execute(
            select(AISnapshotFeatures.is_anomaly)
            .where(AISnapshotFeatures.domain == domain)
            .order_by(desc(AISnapshotFeatures.created_at))
            .limit(last_n)
        ).scalars().all()

    total     = len(rows)
    anomalies = sum(1 for r in rows if r is True)
    return anomalies, total


def _mean_feature_variance(normal_features: list[dict[str, float]]) -> float:
    """
    Return the mean standard deviation across all features.
    Used to detect near-zero-variance (homogeneous) training data.
    """
    if len(normal_features) < 5:
        return 1.0   # too few samples to judge — allow training
    matrix = np.array(
        [[r.get(f, 0.0) for f in FEATURE_NAMES] for r in normal_features],
        dtype=float,
    )
    return float(np.mean(np.std(matrix, axis=0)))


# ---------------------------------------------------------------------------
# Training gate
# ---------------------------------------------------------------------------

def has_enough_for_training(domain: str) -> bool:
    normal = load_normal_features(domain, max_rows=MIN_SAMPLES_FOR_TRAINING)
    return len(normal) >= MIN_SAMPLES_FOR_TRAINING


def should_retrain(domain: str, last_trained_at: datetime | None) -> bool:
    """
    True when ALL of the following:
      1. Enough NEW normal rows exist since last training.
      2. Recent anomaly fraction is below RETRAIN_ANOMALY_GUARD.
      3. Training data has sufficient variance (not all-identical snapshots).
         Low-variance data produces an unstable model that oscillates on
         retrain — better to keep the existing model.
    """
    if last_trained_at is None:
        return has_enough_for_training(domain)

    cutoff = last_trained_at.replace(tzinfo=timezone.utc) \
        if last_trained_at.tzinfo is None else last_trained_at

    with get_session() as session:
        new_count = session.execute(
            select(func.count())
            .where(
                AISnapshotFeatures.domain     == domain,
                AISnapshotFeatures.created_at > cutoff,
                (AISnapshotFeatures.is_anomaly == False)
                | (AISnapshotFeatures.is_anomaly == None),
            )
        ).scalar_one()

    if int(new_count or 0) < MIN_NEW_NORMAL_FOR_RETRAIN:
        logger.debug(
            "[Baseline] Retrain skipped — %d new normal rows (need %d)",
            new_count, MIN_NEW_NORMAL_FOR_RETRAIN,
        )
        return False

    # Check recent anomaly rate
    anomalies, total = count_recent_anomalies(domain, last_n=50)
    if total > 0 and (anomalies / total) > RETRAIN_ANOMALY_GUARD:
        logger.warning(
            "[Baseline] Retrain blocked — %.0f%% recent anomalies exceed %.0f%% guard",
            anomalies / total * 100, RETRAIN_ANOMALY_GUARD * 100,
        )
        return False

    # Check data variance — skip retrain if data is too homogeneous
    normal_features = load_normal_features(domain)
    mean_std = _mean_feature_variance(normal_features)
    if mean_std < LOW_VARIANCE_GUARD:
        logger.info(
            "[Baseline] Retrain skipped — mean feature std=%.4f < %.4f "
            "(homogeneous data, existing model is stable)",
            mean_std, LOW_VARIANCE_GUARD,
        )
        return False

    return True


# ---------------------------------------------------------------------------
# Baseline statistics for explainability
# ---------------------------------------------------------------------------

def compute_baseline_stats(
    normal_features: list[dict[str, float]],
) -> dict[str, dict[str, float]]:
    """Return per-feature {mean, std, min, max} from normal history."""
    if not normal_features:
        return {}

    stats: dict[str, dict[str, float]] = {}
    for feat in FEATURE_NAMES:
        values = np.array([r.get(feat, 0.0) for r in normal_features], dtype=float)
        stats[feat] = {
            "mean": float(np.mean(values)),
            "std":  float(np.std(values)),
            "min":  float(np.min(values)),
            "max":  float(np.max(values)),
        }
    return stats


def build_feature_matrix(
    normal_features: list[dict[str, float]],
) -> np.ndarray:
    """Convert feature dict list to (N × 21) numpy array."""
    return np.array(
        [[r.get(f, 0.0) for f in FEATURE_NAMES] for r in normal_features],
        dtype=float,
    )