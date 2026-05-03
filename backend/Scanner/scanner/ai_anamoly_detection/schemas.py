"""
ai_engine/schemas.py
====================
SQLAlchemy ORM models for the anomaly-detection subsystem.
Uses synchronous psycopg2 engine (ai_engine/db.py) — runs in executor.

FIX — "Foreign key … could not find table 'monitor_sessions'":
  SQLAlchemy resolves ForeignKey() targets by looking up the table name in
  the current MetaData object at mapper-configuration time.  monitor_sessions
  is created by a different migration and is not declared in this Base, so
  resolution fails with the error you saw.

  Fix applied in two layers:
    1.  A minimal MonitorSessions stub is added to this Base so the mapper
        can locate the target table.  It uses extend_existing=True so it
        never conflicts if the table was already reflected elsewhere.
    2.  Both FK columns keep use_alter=True so SQLAlchemy emits
        ALTER TABLE … ADD CONSTRAINT after all CREATE TABLE statements
        — safe for circular or cross-schema dependencies.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy import (
    BigInteger, Boolean, Column, DateTime,
    ForeignKey, Integer, Numeric, String,
    Text, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# 0. MonitorSessions stub
#    Declares the table in this Base's MetaData so FK references resolve.
#    The actual table is owned by the monitoring migration — extend_existing=True
#    means SQLAlchemy won't try to re-create it; it just registers the name.
# ---------------------------------------------------------------------------

class MonitorSessions(Base):
    __tablename__  = "monitor_sessions"
    __table_args__ = {"extend_existing": True}   # ← never drops/recreates

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
    )
    # Only the PK is needed here — SQLAlchemy only needs to know the
    # target column exists so it can wire the FK relationship.


# ---------------------------------------------------------------------------
# 1. ai_snapshot_features
# ---------------------------------------------------------------------------

class AISnapshotFeatures(Base):
    __tablename__ = "ai_snapshot_features"
    __table_args__ = (
        UniqueConstraint("domain", "snapshot_uuid", name="uq_asf_domain_snapshot"),
    )

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    domain        = Column(Text, nullable=False, index=True)
    snapshot_uuid = Column(UUID(as_uuid=True), nullable=False)
    session_id    = Column(
        UUID(as_uuid=True),
        # use_alter=True: emit ALTER TABLE … ADD CONSTRAINT after all
        # CREATE TABLE statements so cross-migration FKs never fail.
        ForeignKey(
            "monitor_sessions.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_asf_session_id",
        ),
        nullable=True,
        index=True,
    )

    # Core counts
    request_count         = Column(Integer)
    unique_urls           = Column(Integer)

    # Method ratios
    get_ratio             = Column(Numeric(6, 4))
    post_ratio            = Column(Numeric(6, 4))

    # Error ratios
    error_rate            = Column(Numeric(6, 4))
    rate_403              = Column(Numeric(6, 4))
    rate_500              = Column(Numeric(6, 4))

    # Size
    avg_response_size     = Column(Numeric(12, 2))

    # Distribution entropies
    content_type_entropy  = Column(Numeric(8, 4))
    resource_type_entropy = Column(Numeric(8, 4))

    # Cookies
    cookie_count          = Column(Integer)
    unique_cookie_names   = Column(Integer)

    # Security header absence ratios
    missing_csp_ratio     = Column(Numeric(6, 4))
    missing_hsts_ratio    = Column(Numeric(6, 4))
    missing_xfo_ratio     = Column(Numeric(6, 4))

    # Attack signals
    suspicious_path_count = Column(Integer)
    sqli_pattern_count    = Column(Integer)
    xss_pattern_count     = Column(Integer)

    # Behaviour
    request_burstiness    = Column(Numeric(10, 4))
    user_agent_count      = Column(Integer)
    url_entropy           = Column(Numeric(8, 4))

    # Full vector (for retraining without re-reading JSONL)
    feature_vector        = Column(JSONB)

    # Labels — back-filled after detection
    is_anomaly            = Column(Boolean, default=False)
    anomaly_score         = Column(Numeric(8, 4))

    created_at            = Column(DateTime(timezone=True), server_default=func.now())

    def to_feature_dict(self) -> dict[str, Any]:
        from .extractor import FEATURE_NAMES
        return {name: float(getattr(self, name) or 0) for name in FEATURE_NAMES}


# ---------------------------------------------------------------------------
# 2. ai_domain_models
# ---------------------------------------------------------------------------

class AIDomainModel(Base):
    __tablename__ = "ai_domain_models"

    id     = Column(BigInteger, primary_key=True, autoincrement=True)
    domain = Column(Text, unique=True, nullable=False, index=True)

    model_path  = Column(Text, nullable=False)
    scaler_path = Column(Text, nullable=False)

    training_samples  = Column(Integer, nullable=False, default=0)
    last_trained_at   = Column(DateTime(timezone=True), nullable=True)
    next_retrain_at   = Column(DateTime(timezone=True), nullable=True)

    mean_anomaly_rate = Column(Numeric(6, 4))
    threshold         = Column(Numeric(8, 4))
    feature_names     = Column(JSONB)
    model_version     = Column(Integer, nullable=False, default=1)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
    )


# ---------------------------------------------------------------------------
# 3. ai_anomaly_results
# ---------------------------------------------------------------------------

class AIAnomalyResult(Base):
    __tablename__ = "ai_anomaly_results"
    __table_args__ = (
        UniqueConstraint("domain", "snapshot_uuid", name="uq_aar_domain_snapshot"),
    )

    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    domain        = Column(Text, nullable=False, index=True)
    snapshot_uuid = Column(UUID(as_uuid=True), nullable=False)
    session_id    = Column(
        UUID(as_uuid=True),
        ForeignKey(
            "monitor_sessions.id",
            ondelete="SET NULL",
            use_alter=True,
            name="fk_aar_session_id",
        ),
        nullable=True,
        index=True,
    )

    anomaly_score        = Column(Numeric(8, 4), nullable=False)
    is_anomaly           = Column(Boolean, nullable=False, default=False)
    confidence           = Column(Numeric(6, 4))
    severity             = Column(String(20))    # low | medium | high | critical
    top_reasons          = Column(JSONB)          # list[str]
    feature_deltas       = Column(JSONB)          # {feature: {current, baseline_mean, pct_change}}
    compared_to_baseline = Column(Boolean, default=False)
    detection_method     = Column(String(40))     # isolation_forest | cold_start | error
    model_version        = Column(Integer)

    created_at = Column(DateTime(timezone=True), server_default=func.now())