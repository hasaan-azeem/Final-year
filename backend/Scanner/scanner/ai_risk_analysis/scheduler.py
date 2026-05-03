"""
AI Risk Analysis / scheduler.py

Continuous-learning pipeline:

  Every cycle:
    1. Fetch unprioritized vulns from DB
    2. Score each with the current model
    3. Write scores back to DB
    4. Append newly scored rows to dataset.csv
    5. If RETRAIN_THRESHOLD new rows have accumulated → retrain on FULL CSV
       (not just new rows — full CSV = true continuous learning)

The model always retrains on the entire accumulated CSV so older knowledge
is never forgotten while new patterns are incorporated.

ERROR HANDLING (added):
  If the ML model fails to load, train, or predict for any reason, a
  rule-based fallback scorer (_fallback_priority) is used instead.
  This guarantees every vulnerability in the DB always receives a
  target_priority value — even when the ML pipeline is completely broken.

  Fallback formula:
    priority = (cvss_score × 0.6 + page_criticality × 0.4) × exploit_boost
  where exploit_boost = 1.2 if exploit_available else 1.0, clamped to [0, 10].

CLI:
  python -m ai_risk_analysis.scheduler              # continuous (every 60 s)
  python -m ai_risk_analysis.scheduler once         # one cycle then exit
  python -m ai_risk_analysis.scheduler once <uuid>  # one session only
  python -m ai_risk_analysis.scheduler train        # force retrain from CSV
  python -m ai_risk_analysis.scheduler sync         # CSV sync only
  python -m ai_risk_analysis.scheduler sync --all   # sync unscored rows too
  python -m ai_risk_analysis.scheduler info         # print CSV stats
"""

import logging
import sys
import time
from datetime import datetime
from pathlib import Path

from .priority_model import (
    DB_CONFIG,
    MODEL_PATH,
    DATASET_PATH,
    DatabaseManager,
    PriorityPredictor,
    assign_priority_category,
)
from .database_sync import DatasetSynchronizer, sync_database_to_dataset

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
logger = logging.getLogger(__name__)


# ── Constants ─────────────────────────────────────────────────────────────────

POLL_INTERVAL_SECONDS = 60    # seconds between DB polls
RETRAIN_THRESHOLD     = 50    # retrain after this many NEW rows added to CSV


# ── Fallback priority scorer ──────────────────────────────────────────────────

def _fallback_priority(vuln: dict) -> float:
    """
    Rule-based fallback used when the ML model is unavailable for any reason
    (missing .pkl, training failure, predict() exception, etc.).

    Formula:
        priority = (cvss_score × 0.6 + page_criticality × 0.4) × exploit_boost
    where exploit_boost = 1.2 if exploit_available else 1.0.

    All inputs are read safely with defaults so this never raises.
    Result is clamped to [0.0, 10.0] and rounded to 2 decimal places.
    """
    try:
        cvss             = float(vuln.get("cvss_score")        or 5.0)
        page_criticality = float(vuln.get("page_criticality")  or 5.0)
        exploit_boost    = 1.2 if vuln.get("exploit_available") else 1.0
        raw              = (cvss * 0.6 + page_criticality * 0.4) * exploit_boost
        return round(min(max(raw, 0.0), 10.0), 2)
    except Exception:
        return 5.0   # absolute last resort


def _score_vuln(model: PriorityPredictor | None, vuln: dict) -> tuple[float, bool]:
    """
    Attempt ML scoring; fall back to rule-based on any failure.
    Returns (priority_float, used_fallback_bool).
    """
    if model is not None and model._fitted:
        try:
            return model.predict(vuln), False
        except Exception as exc:
            logger.warning(
                "[Scheduler] ML predict failed for id=%s (%s) — using fallback",
                vuln.get("id"), exc,
            )
    return _fallback_priority(vuln), True


# ── Scheduler ─────────────────────────────────────────────────────────────────

class VulnerabilityScheduler:
    """
    Polls DB → scores vulns → updates DB → syncs CSV → retrains when needed.

    Retraining always uses the FULL dataset.csv (not just new rows) so the
    model continuously improves without forgetting earlier patterns.
    """

    def __init__(
        self,
        db_config:         dict = DB_CONFIG,
        model_path:        str  = MODEL_PATH,
        dataset_path:      str  = DATASET_PATH,
        interval:          int  = POLL_INTERVAL_SECONDS,
        retrain_threshold: int  = RETRAIN_THRESHOLD,
    ):
        self.db_config          = db_config
        self.model_path         = model_path
        self.dataset_path       = dataset_path
        self.interval           = interval
        self.retrain_threshold  = retrain_threshold

        self.model              = PriorityPredictor()
        self.running            = False
        self.cycle              = 0
        self.total_scored       = 0
        self.new_rows_since_retrain = 0

        self._bootstrap_model()

    # ── Bootstrap ─────────────────────────────────────────────────────────────

    def _bootstrap_model(self) -> bool:
        """Load .pkl if it exists, otherwise train from CSV, otherwise from DB."""
        if Path(self.model_path).exists():
            ok = self.model.load_model(self.model_path)
            if ok:
                return True

        if Path(self.dataset_path).exists():
            logger.info("No saved model — training from CSV: %s", self.dataset_path)
            ok = self.model.train_from_csv(self.dataset_path)
            if ok:
                self.model.save_model(self.model_path)
                return True

        logger.warning("No CSV found — attempting to train from DB labelled rows…")
        return self._retrain_from_db()

    # ── Retrain ───────────────────────────────────────────────────────────────

    def _retrain_from_csv(self) -> bool:
        logger.info("=" * 55)
        logger.info("RETRAINING — full CSV  (%s)", self.dataset_path)
        logger.info("=" * 55)

        ok = self.model.train_from_csv(self.dataset_path)
        if ok:
            self.model.save_model(self.model_path)
            self.new_rows_since_retrain = 0
            logger.info("Retrain complete — model updated → %s", self.model_path)
        else:
            logger.error("Retrain failed — keeping current model")
        return ok

    def _retrain_from_db(self) -> bool:
        db = DatabaseManager(self.db_config)
        if not db.connect():
            logger.error("Cannot connect to DB for retraining")
            return False
        df = db.fetch_training_data()
        db.close()

        if len(df) < 20:
            logger.warning(
                "Only %d labelled DB rows — need >= 20. "
                "Place dataset.csv at %s first.",
                len(df), self.dataset_path,
            )
            return False

        ok = self.model.train_model(df)
        if ok:
            self.model.save_model(self.model_path)
            self.new_rows_since_retrain = 0
        return ok

    # ── Main loop ─────────────────────────────────────────────────────────────

    def start(self):
        # ── ERROR HANDLING: proceed even without a trained model ──────────────
        # If no model is available the scheduler still runs and applies
        # rule-based fallback scoring every cycle so no vuln is left unscored.
        if not self.model._fitted:
            logger.warning(
                "[Scheduler] No trained model available — will use rule-based "
                "fallback scoring until a model is trained."
            )

        logger.info("=" * 60)
        logger.info("VULNERABILITY SCHEDULER STARTED")
        logger.info("  Poll interval   : %ds", self.interval)
        logger.info("  Model           : %s", self.model_path)
        logger.info("  Dataset         : %s", self.dataset_path)
        logger.info("  Retrain every   : %d new CSV rows", self.retrain_threshold)
        logger.info("=" * 60)

        self.running = True
        try:
            while self.running:
                self.cycle += 1
                logger.info(
                    "── Cycle %d  %s ──",
                    self.cycle,
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                )
                self._run_cycle()
                time.sleep(self.interval)

        except KeyboardInterrupt:
            logger.info("Stopped by user (Ctrl-C)")
        except Exception as e:
            logger.error("Unhandled error: %s", e, exc_info=True)
        finally:
            self.running = False
            logger.info(
                "Scheduler stopped — cycles=%d  total_scored=%d",
                self.cycle, self.total_scored,
            )

    def stop(self):
        self.running = False

    # ── One cycle ─────────────────────────────────────────────────────────────

    def _run_cycle(self):
        scored = self._score_and_update_db()

        if scored > 0:
            added = self._sync_csv()
            self.new_rows_since_retrain += added

        if self.new_rows_since_retrain >= self.retrain_threshold:
            logger.info(
                "%d new rows since last retrain — retraining on full CSV…",
                self.new_rows_since_retrain,
            )
            self._retrain_from_csv()

    # ── Score & update DB ─────────────────────────────────────────────────────

    def _score_and_update_db(self) -> int:
        try:
            db = DatabaseManager(self.db_config)
            if not db.connect():
                return 0

            rows = db.fetch_unprioritized()
            if not rows:
                logger.info("No unprioritized vulnerabilities")
                db.close()
                return 0

            logger.info("Scoring %d vulnerabilities…", len(rows))

            # ── ERROR HANDLING: per-vuln fallback ────────────────────────────
            # If model.predict() raises for any individual vuln (e.g. bad
            # feature values, encoder mismatch after a partial retrain),
            # _score_vuln catches it and applies the rule-based fallback so
            # that vuln is still written to the DB with a valid priority.
            updates     = []
            fallback_n  = 0
            model_arg   = self.model if self.model._fitted else None

            for r in rows:
                priority, used_fallback = _score_vuln(model_arg, dict(r))
                if used_fallback:
                    fallback_n += 1
                updates.append((r["id"], priority, assign_priority_category(priority)))

            if fallback_n:
                logger.warning(
                    "[Scheduler] %d/%d vulns scored via rule-based fallback",
                    fallback_n, len(rows),
                )

            db.batch_update_priorities(updates)

            risk = db.get_site_risk_score()
            if risk:
                logger.info(
                    "Site risk %.2f/10 (%s) | C=%d H=%d M=%d L=%d",
                    risk["site_risk_score"], risk["site_risk_level"],
                    risk["critical"], risk["high"], risk["medium"], risk["low"],
                )

            db.close()
            n = len(updates)
            self.total_scored += n
            return n

        except Exception as e:
            logger.error("Score/update error: %s", e, exc_info=True)
            return 0

    # ── Sync CSV and return count of rows added ───────────────────────────────

    def _sync_csv(self, session_id: str | None = None) -> int:
        try:
            result = sync_database_to_dataset(
                db_config=self.db_config,
                dataset_path=self.dataset_path,
                only_scored=True,
                session_id=session_id,
            )
            added = result["added"]
            if added > 0:
                logger.info(
                    "CSV updated — added=%d  total=%d",
                    added, result["after"],
                )
            return added
        except Exception as e:
            logger.error("CSV sync error: %s", e)
            return 0


# ── run_once ──────────────────────────────────────────────────────────────────

def run_once(session_id: str | None = None) -> bool:
    """
    Score all unprioritized rows once, sync CSV, retrain if threshold met.
    Runs synchronously — called from main.py inside a ThreadPoolExecutor.

    ERROR HANDLING:
      If the ML model cannot be loaded or trained, rule-based fallback scoring
      is applied to every unprioritized vuln so none are left with NULL priority.
    """
    logger.info("RUN-ONCE  session=%s", session_id or "all")

    # ── Try to get a working ML model ─────────────────────────────────────────
    model: PriorityPredictor | None = None
    try:
        _model = PriorityPredictor()
        loaded = _model.load_model(MODEL_PATH)

        if not loaded:
            logger.warning("No saved model — attempting to train from CSV…")
            loaded = _model.train_from_csv(DATASET_PATH)
            if loaded:
                _model.save_model(MODEL_PATH)

        if loaded and _model._fitted:
            model = _model
        else:
            logger.warning(
                "[run_once] ML model unavailable — "
                "all vulns will be scored via rule-based fallback."
            )
    except Exception as exc:
        logger.error(
            "[run_once] Model init failed (%s) — "
            "falling back to rule-based scoring.", exc,
        )

    # ── Score unprioritized DB rows ───────────────────────────────────────────
    try:
        db = DatabaseManager(DB_CONFIG)
        if not db.connect():
            logger.error("[run_once] Cannot connect to DB — aborting")
            return False

        rows = db.fetch_unprioritized()
        if rows:
            updates    = []
            fallback_n = 0
            for r in rows:
                priority, used_fallback = _score_vuln(model, dict(r))
                if used_fallback:
                    fallback_n += 1
                updates.append((r["id"], priority, assign_priority_category(priority)))

            if fallback_n:
                logger.warning(
                    "[run_once] %d/%d vulns scored via rule-based fallback",
                    fallback_n, len(rows),
                )

            db.batch_update_priorities(updates)
            logger.info("[run_once] Scored %d vulnerabilities", len(updates))

        risk = db.get_site_risk_score()
        if risk:
            logger.info(
                "[run_once] Site risk: %.2f/10 (%s)",
                risk["site_risk_score"], risk["site_risk_level"],
            )
        db.close()

    except Exception as exc:
        logger.error("[run_once] DB scoring phase failed: %s", exc, exc_info=True)
        # Do NOT return False here — CSV sync and retrain can still proceed.

    # ── Sync CSV ──────────────────────────────────────────────────────────────
    added = 0
    try:
        result = sync_database_to_dataset(
            db_config=DB_CONFIG,
            dataset_path=DATASET_PATH,
            only_scored=True,
            session_id=session_id,
        )
        added = result["added"]
        logger.info(
            "[run_once] CSV sync — before=%d  added=%d  after=%d",
            result["before"], added, result["after"],
        )
    except Exception as exc:
        logger.error("[run_once] CSV sync failed: %s", exc)

    # ── Retrain on full CSV if threshold met ──────────────────────────────────
    if added >= RETRAIN_THRESHOLD:
        try:
            logger.info(
                "[run_once] %d new rows — retraining on full CSV…", added,
            )
            model2 = PriorityPredictor()
            if model2.train_from_csv(DATASET_PATH):
                model2.save_model(MODEL_PATH)
                logger.info("[run_once] Model retrained → %s", MODEL_PATH)
            else:
                logger.warning("[run_once] Retrain skipped — not enough data yet")
        except Exception as exc:
            logger.error("[run_once] Retrain failed: %s", exc)

    return True


# ── run_fallback_scoring_only ─────────────────────────────────────────────────

def run_fallback_scoring_only(session_id: str | None = None) -> bool:
    """
    Pure rule-based priority assignment — no ML involved.
    Called by main.py when run_once() itself raises an unhandled exception,
    ensuring every vuln still gets a priority no matter what.
    """
    logger.warning(
        "[Fallback] ML pipeline failed entirely — "
        "applying rule-based scoring to all unscored vulns."
    )
    try:
        db = DatabaseManager(DB_CONFIG)
        if not db.connect():
            logger.error("[Fallback] Cannot connect to DB")
            return False

        rows = db.fetch_unprioritized()
        if not rows:
            logger.info("[Fallback] No unscored vulns found")
            db.close()
            return True

        updates = [
            (r["id"], _fallback_priority(r), assign_priority_category(_fallback_priority(r)))
            for r in rows
        ]
        db.batch_update_priorities(updates)
        logger.info("[Fallback] Rule-based scores written for %d vulns", len(updates))
        db.close()
        return True

    except Exception as exc:
        logger.error("[Fallback] Fallback scoring also failed: %s", exc, exc_info=True)
        return False


# ── print_info ────────────────────────────────────────────────────────────────

def print_info():
    syncer = DatasetSynchronizer(DB_CONFIG, DATASET_PATH)
    stats  = syncer.info()
    if not stats:
        print("No dataset found at", DATASET_PATH)
        return

    print("\n" + "=" * 55)
    print("DATASET INFO")
    print("=" * 55)
    print(f"  Path            : {stats['path']}")
    print(f"  Total rows      : {stats['total_records']}")
    if "date_range" in stats:
        print(
            f"  Date range      : "
            f"{stats['date_range']['earliest']}  →  {stats['date_range']['latest']}"
        )
    if "priority_stats" in stats:
        ps = stats["priority_stats"]
        print(f"  Scored rows     : {ps['count']}")
        print(f"  Priority range  : {ps['min']} – {ps['max']}  (mean {ps['mean']})")
    if "priority_distribution" in stats:
        print(f"  Distribution    : {stats['priority_distribution']}")
    if "vuln_type_distribution" in stats:
        print(f"  Top vuln types  : {stats['vuln_type_distribution']}")
    if "top_categories" in stats:
        print("  Top categories  :")
        for cat, n in list(stats["top_categories"].items())[:5]:
            print(f"    {cat:<30} {n}")
    print()


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cmd     = sys.argv[1] if len(sys.argv) > 1 else "start"
    session = sys.argv[2] if len(sys.argv) > 2 else None

    if cmd == "once":
        run_once(session_id=session)

    elif cmd == "train":
        logger.info("Force retrain from CSV: %s", DATASET_PATH)
        p = PriorityPredictor()
        if p.train_from_csv(DATASET_PATH):
            p.save_model(MODEL_PATH)
            logger.info("Training complete → %s", MODEL_PATH)
        else:
            logger.error("Training failed")

    elif cmd == "sync":
        all_rows = "--all" in sys.argv
        result = sync_database_to_dataset(
            db_config=DB_CONFIG,
            dataset_path=DATASET_PATH,
            only_scored=not all_rows,
            session_id=session,
        )
        print(
            f"Sync done: before={result['before']}  "
            f"added={result['added']}  after={result['after']}"
        )

    elif cmd == "info":
        print_info()

    else:
        scheduler = VulnerabilityScheduler(
            db_config=DB_CONFIG,
            model_path=MODEL_PATH,
            dataset_path=DATASET_PATH,
            interval=POLL_INTERVAL_SECONDS,
            retrain_threshold=RETRAIN_THRESHOLD,
        )
        scheduler.start()