"""
ai_engine/main.py
=================
Top-level orchestration for the WebXGuard anomaly-detection subsystem.

Public entry point
------------------
    run_anomaly_detection(domain, network_log_file=None, session_id=None)

Pipeline
--------
1. Resolve network_log_file (passed directly or read from monitor_snapshots).
2. Extract feature vector from the JSONL file.
3. Persist features to ai_snapshot_features.
4. Train / retrain the domain model if conditions are met.
5. Detect anomaly (IsolationForest or cold-start).
6. Back-fill anomaly label on the feature row.
7. Persist result to ai_anomaly_results.
8. Return full result dict.

Designed to run synchronously inside asyncio.run_in_executor() — never
awaits anything and never touches the main asyncpg pool.
"""
from __future__ import annotations

import logging
import os
import re
import uuid as _uuid
from datetime import datetime, timezone
from typing import Any

import psycopg2
import psycopg2.extras
from sqlalchemy import select

from .baseline import (
    has_enough_for_training,
    mark_anomaly_label,
    save_snapshot_features,
    should_retrain,
)
from .db import ensure_tables, get_session
from .detector import detect
from .extractor import extract_features
from .schemas import AIAnomalyResult
from .trainer import get_model_record, train_domain_model

logger = logging.getLogger("webxguard.ai_engine.main")


# ---------------------------------------------------------------------------
# Snapshot DB fallback  (only used when network_log_file is not passed in)
# ---------------------------------------------------------------------------

def _build_psycopg2_dsn() -> str:
    url = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:admin123@localhost:5432/WebXGaurd2",
    )
    m = re.match(
        r"postgres(?:ql)?(?:\+\w+)?://([^:]*):([^@]*)@([^:/]+):?(\d+)?/(.+)",
        url,
    )
    if m:
        user, pwd, host, port, db = m.groups()
        return (
            f"host={host} port={port or 5432} "
            f"dbname={db} user={user} password={pwd}"
        )
    return url   # already a keyword DSN


def _fetch_snapshot_from_db(domain: str) -> dict | None:
    """
    Fallback: read network_log_file and session_id from monitor_snapshots.
    Only called when the caller did not pass network_log_file directly.
    """
    try:
        conn = psycopg2.connect(_build_psycopg2_dsn())
        with conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                cur.execute(
                    """
                    SELECT domain, network_log_file, session_id
                    FROM   monitor_snapshots
                    WHERE  domain = %s
                    LIMIT  1
                    """,
                    (domain,),
                )
                row = cur.fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception as exc:
        logger.error("[Main] DB fallback fetch failed for %s: %s", domain, exc)
        return None


# ---------------------------------------------------------------------------
# Result persistence
# ---------------------------------------------------------------------------

def _save_result(result_dict: dict[str, Any], session_id_str: str | None) -> None:
    sid = None
    if session_id_str:
        try:
            sid = _uuid.UUID(session_id_str)
        except ValueError:
            pass

    snap_uuid = result_dict["snapshot_uuid"]
    if isinstance(snap_uuid, str):
        try:
            snap_uuid = _uuid.UUID(snap_uuid)
        except ValueError:
            pass

    with get_session() as session:
        existing = session.execute(
            select(AIAnomalyResult).where(
                AIAnomalyResult.domain        == result_dict["domain"],
                AIAnomalyResult.snapshot_uuid == snap_uuid,
            )
        ).scalar_one_or_none()

        cols = (
            "anomaly_score", "is_anomaly", "confidence", "severity",
            "top_reasons", "feature_deltas", "compared_to_baseline",
            "detection_method", "model_version",
        )
        if existing:
            for col in cols:
                setattr(existing, col, result_dict.get(col))
        else:
            session.add(AIAnomalyResult(
                domain        = result_dict["domain"],
                snapshot_uuid = snap_uuid,
                session_id    = sid,
                **{col: result_dict.get(col) for col in cols},
            ))


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_anomaly_detection(
    domain:           str,
    network_log_file: str | None = None,
    session_id:       str | None = None,
) -> dict[str, Any]:
    """
    Run the full anomaly-detection pipeline for *domain*.

    Called from monitoring_main.py via run_in_executor::

        result = await loop.run_in_executor(
            None,
            partial(_anomaly_run, domain, network_log, str(session_id)),
        )

    Parameters
    ----------
    domain           : hostname being monitored
    network_log_file : JSONL path — if None, read from monitor_snapshots
    session_id       : UUID string from the crawl session

    Returns
    -------
    dict matching DetectionResult.to_dict()
    """
    logger.info("[Main] ── Detection start  domain=%s ──", domain)

    # ── 0. Ensure tables exist ─────────────────────────────────────────────
    try:
        ensure_tables()
    except Exception as exc:
        logger.error("[Main] Table check failed: %s", exc)

    # ── 1. Resolve log file ────────────────────────────────────────────────
    if not network_log_file:
        row = _fetch_snapshot_from_db(domain)
        if not row:
            logger.warning("[Main] No snapshot row for %s", domain)
            return _error_result(domain, "no_snapshot")
        network_log_file = row.get("network_log_file")
        if not session_id:
            session_id = str(row.get("session_id") or "")

    if not network_log_file:
        logger.warning("[Main] No network_log_file for %s", domain)
        return _error_result(domain, "no_log_file")

    # Stable per-cycle identifier
    snapshot_uuid = session_id or str(_uuid.uuid4())

    # ── 2. Extract features ────────────────────────────────────────────────
    logger.info("[Main] Extracting features from %s", network_log_file)
    try:
        features = extract_features(network_log_file)
    except Exception as exc:
        logger.error("[Main] Extraction failed: %s", exc)
        return _error_result(domain, "extraction_error", snapshot_uuid)

    if features.request_count == 0:
        logger.warning("[Main] Empty feature vector for %s", domain)
        return _error_result(domain, "empty_log", snapshot_uuid)

    # ── 3. Persist features ────────────────────────────────────────────────
    try:
        save_snapshot_features(
            domain        = domain,
            snapshot_uuid = snapshot_uuid,
            features      = features,
            session_id    = session_id or None,
        )
    except Exception as exc:
        logger.error("[Main] Feature save failed (non-fatal): %s", exc)

    # ── 4. Train / retrain ─────────────────────────────────────────────────
    model_record    = get_model_record(domain)
    last_trained_at = getattr(model_record, "last_trained_at", None)
    model_version   = getattr(model_record, "model_version",   None)

    try:
        if should_retrain(domain, last_trained_at):
            logger.info("[Main] Retraining model for %s", domain)
            if train_domain_model(domain):
                model_record  = get_model_record(domain)
                model_version = getattr(model_record, "model_version", model_version)
        elif not model_record and has_enough_for_training(domain):
            logger.info("[Main] First training for %s", domain)
            if train_domain_model(domain):
                model_record  = get_model_record(domain)
                model_version = getattr(model_record, "model_version", 1)
    except Exception as exc:
        logger.error("[Main] Training step failed (non-fatal): %s", exc)

    # ── 5. Detect ──────────────────────────────────────────────────────────
    try:
        detection = detect(
            domain        = domain,
            snapshot_uuid = snapshot_uuid,
            features      = features,
            model_version = model_version,
        )
    except Exception as exc:
        logger.error("[Main] Detection failed: %s", exc)
        return _error_result(domain, "detection_error", snapshot_uuid)

    # ── 6. Back-fill label ─────────────────────────────────────────────────
    try:
        mark_anomaly_label(
            domain        = domain,
            snapshot_uuid = snapshot_uuid,
            is_anomaly    = detection.is_anomaly,
            anomaly_score = detection.anomaly_score,
        )
    except Exception as exc:
        logger.warning("[Main] Label back-fill failed (non-fatal): %s", exc)

    # ── 7. Persist result ──────────────────────────────────────────────────
    result_dict = detection.to_dict()
    try:
        _save_result(result_dict, session_id_str=session_id or None)
    except Exception as exc:
        logger.error("[Main] Result save failed (non-fatal): %s", exc)

    logger.info(
        "[Main] ── Done  domain=%s  score=%.3f  is_anomaly=%s  "
        "severity=%s  method=%s ──",
        domain,
        detection.anomaly_score,
        detection.is_anomaly,
        detection.severity,
        detection.detection_method,
    )
    return result_dict


# ---------------------------------------------------------------------------
# Error sentinel
# ---------------------------------------------------------------------------

def _error_result(
    domain:        str,
    reason:        str        = "error",
    snapshot_uuid: str | None = None,
) -> dict[str, Any]:
    return {
        "domain":               domain,
        "snapshot_uuid":        snapshot_uuid or str(_uuid.uuid4()),
        "anomaly_score":        0.0,
        "is_anomaly":           False,
        "confidence":           0.0,
        "severity":             "low",
        "top_reasons":          [f"Pipeline error: {reason}"],
        "feature_deltas":       {},
        "compared_to_baseline": False,
        "detection_method":     "error",
        "model_version":        None,
        "timestamp":            datetime.now(tz=timezone.utc).isoformat(),
    }