"""
ai_engine/trainer.py
====================
Trains and persists per-domain IsolationForest + StandardScaler models.

Artefacts
---------
    models/<domain>.pkl         ← IsolationForest
    models/<domain>_scaler.pkl  ← StandardScaler

The ai_domain_models table tracks metadata (path, version, training count).
"""
from __future__ import annotations

import logging
import pickle
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sqlalchemy import select

from .baseline import MIN_SAMPLES_FOR_TRAINING, build_feature_matrix, load_normal_features
from .db import get_session
from .extractor import FEATURE_NAMES
from .schemas import AIDomainModel

logger = logging.getLogger("webxguard.ai_engine.trainer")

MODELS_DIR         = "models"
CONTAMINATION      = 0.05
N_ESTIMATORS       = 150
RETRAIN_INTERVAL_H = 24


# ---------------------------------------------------------------------------
# Artefact helpers
# ---------------------------------------------------------------------------

def _safe_name(domain: str) -> str:
    return domain.replace("/", "_").replace(":", "_")


def _model_path(domain: str)  -> Path:
    return Path(MODELS_DIR) / f"{_safe_name(domain)}.pkl"


def _scaler_path(domain: str) -> Path:
    return Path(MODELS_DIR) / f"{_safe_name(domain)}_scaler.pkl"


def _save(obj: Any, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as fh:
        pickle.dump(obj, fh, protocol=pickle.HIGHEST_PROTOCOL)


def _load(path: Path) -> Any:
    with path.open("rb") as fh:
        return pickle.load(fh)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def load_model(domain: str) -> tuple[IsolationForest, StandardScaler] | None:
    """Load persisted (model, scaler) for *domain*. Returns None if absent."""
    mp = _model_path(domain)
    sp = _scaler_path(domain)
    if not mp.exists() or not sp.exists():
        return None
    try:
        return _load(mp), _load(sp)
    except Exception as exc:
        logger.error("[Trainer] Failed to load model for %s: %s", domain, exc)
        return None


def train_domain_model(domain: str, force: bool = False) -> bool:
    """
    Train (or retrain) IsolationForest for *domain*.

    Returns True on success, False if skipped or failed.
    """
    logger.info("[Trainer] Training  domain=%s", domain)

    normal = load_normal_features(domain)
    n      = len(normal)

    if n < MIN_SAMPLES_FOR_TRAINING and not force:
        logger.info("[Trainer] Skipped — %d samples (need %d)", n, MIN_SAMPLES_FOR_TRAINING)
        return False

    X = build_feature_matrix(normal)
    logger.info("[Trainer] Fitting on %d × %d matrix", X.shape[0], X.shape[1])

    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    model = IsolationForest(
        n_estimators = N_ESTIMATORS,
        contamination = CONTAMINATION,
        max_samples  = "auto",
        bootstrap    = False,
        random_state = 42,
        n_jobs       = -1,
    )
    model.fit(X_scaled)

    mp = _model_path(domain)
    sp = _scaler_path(domain)
    _save(model,  mp)
    _save(scaler, sp)
    logger.info("[Trainer] Saved  model=%s  scaler=%s", mp, sp)

    _upsert_record(domain, str(mp), str(sp), n)
    return True


def _upsert_record(domain: str, mp: str, sp: str, n_samples: int) -> None:
    now          = datetime.now(tz=timezone.utc)
    next_retrain = now + timedelta(hours=RETRAIN_INTERVAL_H)

    with get_session() as session:
        existing = session.execute(
            select(AIDomainModel).where(AIDomainModel.domain == domain)
        ).scalar_one_or_none()

        if existing:
            existing.model_path       = mp
            existing.scaler_path      = sp
            existing.training_samples = n_samples
            existing.last_trained_at  = now
            existing.next_retrain_at  = next_retrain
            existing.feature_names    = FEATURE_NAMES
            existing.model_version    = (existing.model_version or 1) + 1
            existing.updated_at       = now
        else:
            session.add(AIDomainModel(
                domain           = domain,
                model_path       = mp,
                scaler_path      = sp,
                training_samples = n_samples,
                last_trained_at  = now,
                next_retrain_at  = next_retrain,
                feature_names    = FEATURE_NAMES,
                model_version    = 1,
            ))

    logger.info("[Trainer] DB record updated  domain=%s  samples=%d", domain, n_samples)


def get_model_record(domain: str) -> AIDomainModel | None:
    with get_session() as session:
        return session.execute(
            select(AIDomainModel).where(AIDomainModel.domain == domain)
        ).scalar_one_or_none()