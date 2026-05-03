"""
scanner/ai_risk_analysis/database_sync.py

BUG FIX — "No module named 'webxgaurd'" / "No module named 'ai_risk_analysis'":
  The original file used bare absolute imports:
      from ai_risk_analysis.priority_model import DB_CONFIG, DATASET_PATH

  When the file runs as part of `scanner.ai_risk_analysis` (via `python -m
  scanner.api`), Python resolves absolute imports from the project root.
  The package is `scanner.ai_risk_analysis`, not `ai_risk_analysis`, so
  the bare import fails with ModuleNotFoundError.

  Fix: all cross-file imports within ai_risk_analysis are now relative
  (`from .priority_model import ...`).  This works correctly whether the
  package is imported as `scanner.ai_risk_analysis` or `ai_risk_analysis`.
"""
from __future__ import annotations

import logging
from pathlib import Path

import pandas as pd
import psycopg2

# ── BUG FIX: relative import — works regardless of how the package is invoked ──
from .priority_model import DB_CONFIG, DATASET_PATH
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

_FETCH_SQL = """
    SELECT
        id,
        session_id::text   AS session_id,
        domain_id,
        page_url,
        title,
        category,
        confidence,
        parameter_name,
        cwe,
        wasc,
        reference,
        page_id,
        endpoint_id,
        form_id,
        created_at,
        severity,
        likelihood,
        impact,
        cvss_score,
        exploit_available,
        page_criticality,
        severity_level,
        target_priority,
        priority_category,
        COALESCE(raw_data::json->>'vuln_type', 'unknown') AS vuln_type
    FROM vulnerabilities
    {where}
    ORDER BY id ASC
"""


class DatasetSynchronizer:
    def __init__(self, db_config: dict = DB_CONFIG, dataset_path: str | None = None):
        self.db_config    = db_config
        self.dataset_path = Path(dataset_path) if dataset_path else Path(DATASET_PATH)
        self.conn         = None

    def connect(self) -> bool:
        try:
            self.conn = psycopg2.connect(**self.db_config)
            logger.info("Sync: DB connected")
            return True
        except Exception as e:
            logger.error("Sync: DB connect failed — %s", e)
            return False

    def close(self):
        if self.conn:
            self.conn.close()
            self.conn = None

    def _load_csv(self) -> pd.DataFrame:
        try:
            df = pd.read_csv(self.dataset_path, low_memory=False)
            logger.info("CSV loaded: %d rows from %s", len(df), self.dataset_path)
            return df
        except FileNotFoundError:
            logger.info("CSV not found at %s — will create fresh", self.dataset_path)
            return pd.DataFrame()
        except Exception as e:
            logger.error("CSV load error: %s", e)
            return pd.DataFrame()

    def _save_csv(self, df: pd.DataFrame):
        self.dataset_path.parent.mkdir(parents=True, exist_ok=True)
        df.to_csv(self.dataset_path, index=False)
        logger.info("CSV saved → %s (%d rows)", self.dataset_path, len(df))

    def _fetch_from_db(
        self,
        only_scored: bool      = True,
        since_id:    int | None = None,
        session_id:  str | None = None,
    ) -> pd.DataFrame:
        conditions: list[str] = []
        params:     list      = []

        if only_scored:
            conditions.append("target_priority IS NOT NULL")
        if since_id is not None:
            conditions.append("id > %s")
            params.append(since_id)
        if session_id:
            conditions.append("session_id = %s::uuid")
            params.append(session_id)

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        sql   = _FETCH_SQL.format(where=where)

        try:
            df = pd.read_sql(sql, self.conn, params=params or None)
            logger.info("DB fetch: %d rows (only_scored=%s)", len(df), only_scored)
            return df
        except Exception as e:
            logger.error("DB fetch failed: %s", e)
            return pd.DataFrame()

    def sync(
        self,
        only_scored: bool      = True,
        session_id:  str | None = None,
    ) -> dict:
        logger.info("─" * 50)
        logger.info("DATASET SYNC START")

        local_df = self._load_csv()
        initial  = len(local_df)

        max_local_id = (
            int(local_df["id"].max())
            if not local_df.empty and "id" in local_df.columns
            else None
        )

        db_df = self._fetch_from_db(
            only_scored=only_scored,
            since_id=max_local_id,
            session_id=session_id,
        )

        if db_df.empty:
            logger.info("No new rows in DB (max local id=%s)", max_local_id)
            return {"before": initial, "added": 0, "after": initial}

        if not local_df.empty and "id" in local_df.columns:
            existing_ids = set(local_df["id"].astype(int))
            db_df = db_df[~db_df["id"].isin(existing_ids)]

        if db_df.empty:
            logger.info("All fetched rows already in CSV")
            return {"before": initial, "added": 0, "after": initial}

        updated_df = (
            pd.concat([local_df, db_df], ignore_index=True)
            .sort_values("id")
            .reset_index(drop=True)
        )
        self._save_csv(updated_df)

        added = len(db_df)
        after = len(updated_df)
        logger.info("Sync done — before=%d  added=%d  after=%d", initial, added, after)
        return {"before": initial, "added": added, "after": after}

    def info(self) -> dict | None:
        df = self._load_csv()
        if df.empty:
            return None

        out: dict = {
            "total_records": len(df),
            "path":          str(self.dataset_path),
            "columns":       list(df.columns),
        }
        if "created_at" in df.columns:
            out["date_range"] = {
                "earliest": str(df["created_at"].min()),
                "latest":   str(df["created_at"].max()),
            }
        if "target_priority" in df.columns:
            tp = df["target_priority"].dropna()
            out["priority_stats"] = {
                "count": int(len(tp)),
                "min":   round(float(tp.min()),  2) if len(tp) else 0.0,
                "max":   round(float(tp.max()),  2) if len(tp) else 0.0,
                "mean":  round(float(tp.mean()), 2) if len(tp) else 0.0,
            }
        if "priority_category" in df.columns:
            out["priority_distribution"] = df["priority_category"].value_counts().to_dict()
        if "confidence" in df.columns:
            out["confidence_distribution"] = df["confidence"].value_counts().to_dict()
        if "category" in df.columns:
            out["top_categories"] = df["category"].value_counts().head(10).to_dict()
        if "vuln_type" in df.columns:
            out["vuln_type_distribution"] = df["vuln_type"].value_counts().head(10).to_dict()
        return out


def sync_database_to_dataset(
    db_config:    dict       = DB_CONFIG,
    dataset_path: str | None = None,
    only_scored:  bool       = True,
    session_id:   str | None = None,
) -> dict:
    syncer = DatasetSynchronizer(db_config, dataset_path)
    if not syncer.connect():
        return {"before": 0, "added": 0, "after": 0}

    result = syncer.sync(only_scored=only_scored, session_id=session_id)

    stats = syncer.info()
    if stats:
        logger.info(
            "Dataset info — total=%d  priority_scored=%d",
            stats["total_records"],
            stats.get("priority_stats", {}).get("count", 0),
        )
        if "priority_distribution" in stats:
            logger.info("Distribution: %s", stats["priority_distribution"])

    syncer.close()
    return result