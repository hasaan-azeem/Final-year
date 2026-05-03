"""
backend/Scanner/scanner/monitoring_main.py

Continuous monitoring loop. Har MONITOR_INTERVAL_MINUTES baad:
  1. Crawl each TARGET_URL
  2. Passive scan
  3. Prioritize vulnerabilities
  4. Run posture engine (security score, forecast, anomaly)
  5. Run AI anomaly detection (network log IsolationForest)
  6. ★ Fan-out alerts for any anomalies / Critical posture
  7. Archive network log

All steps non-fatal — if any step fails, loop continues.
"""
import asyncio
import logging
import os
import shutil
from functools import partial

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .db import init_db, close_db
from .scrapper.monitoring_core import MonitoringCrawler
from .repositories.monitor_snapshot import get_monitor_snapshot
from .repositories.domains import get_or_create_domain
from .scanner_engine.passive_scanner.monitor_scanner import passive_scan_snapshot
from .scanner_engine.passive_scanner.post_scan_priortizer import run_post_scan_prioritization
from .monitoring_config import TARGET_URLS, MONITOR_INTERVAL_MINUTES

# ── Posture Engine ────────────────────────────────────────────────────────────
try:
    from .ai_predictive_analysis.engine import run as _posture_run
    _POSTURE_AVAILABLE = True
except ImportError:
    _POSTURE_AVAILABLE = False

# ── Anomaly Detection Engine ──────────────────────────────────────────────────
try:
    from .ai_anamoly_detection.main import run_anomaly_detection as _anomaly_run
    _ANOMALY_AVAILABLE = True
    print("✅ Anomaly engine import SUCCESS")
except Exception as e:
    _ANOMALY_AVAILABLE = False

    import traceback
    print("\n========== ANOMALY IMPORT ERROR ==========")
    print(f"ERROR TYPE: {type(e).__name__}")
    print(f"ERROR MESSAGE: {e}")
    print("FULL TRACEBACK:")
    traceback.print_exc()
    print("=========================================\n")

# ★ NEW — Alert triggers (sync — both run inside run_in_executor)
try:
    from .alerts.triggers import (
        alert_from_posture_sync,
        alert_from_ai_anomaly_sync,
    )
    _ALERTS_AVAILABLE = True
    print("✅ Alerts module import SUCCESS")
except Exception as e:
    _ALERTS_AVAILABLE = False

    import traceback
    print("\n========== ALERTS IMPORT ERROR ==========")
    print(f"ERROR TYPE: {type(e).__name__}")
    print(f"ERROR MESSAGE: {e}")
    print("FULL TRACEBACK:")
    traceback.print_exc()
    print("=========================================\n")


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logger = logging.getLogger("webxguard.monitoring_main")

NETWORK_LOG_DIR = "network_logs"
ARCHIVE_LOG_DIR = "network_logs/archive"
_crawlers: list = []


# ─────────────────────────────────────────────────────────────────────────────
# POSTURE ENGINE HELPER  (with alert hook)
# ─────────────────────────────────────────────────────────────────────────────

async def _run_posture_engine(domain: str, session_id) -> None:
    if not _POSTURE_AVAILABLE:
        logger.debug("[MonitorMain] Posture engine not installed — skipping")
        return
    try:
        loop    = asyncio.get_event_loop()
        sid_str = str(session_id) if session_id else None
        payload = await loop.run_in_executor(None, partial(_posture_run, domain, sid_str))
        logger.info(
            "[MonitorMain] Posture ✓  domain=%-30s  "
            "score=%.1f  risk=%-8s  grade=%s  "
            "velocity=%+.2f pts/day  breach=%.1f%%  "
            "anomaly=%s  snapshot_id=%s",
            domain,
            payload["score"], payload["risk_level"], payload["grade"],
            payload["risk_velocity"], payload["breach_probability"],
            "YES ⚠" if payload["anomaly"]["is_anomaly"] else "no",
            payload.get("snapshot_id"),
        )
        if payload["anomaly"]["is_anomaly"]:
            logger.warning(
                "[MonitorMain] ⚠ POSTURE ANOMALY  domain=%s  reason=%s",
                domain, payload["anomaly"]["reason"],
            )

        # ★ NEW — fan-out alerts (sync work, run in executor so we don't block)
        if _ALERTS_AVAILABLE:
            try:
                count = await loop.run_in_executor(
                    None,
                    partial(alert_from_posture_sync, domain, payload),
                )
                if count:
                    logger.info(
                        "[MonitorMain] Posture → %d alert(s) created", count,
                    )
            except Exception as e:
                logger.warning("[MonitorMain] Posture alert hook failed: %s", e)

    except Exception as e:
        logger.exception("[MonitorMain] Posture engine failed for %s: %s", domain, e)


# ─────────────────────────────────────────────────────────────────────────────
# ANOMALY DETECTION HELPER  (with alert hook)
# ─────────────────────────────────────────────────────────────────────────────

async def _run_anomaly_detection(
    domain: str,
    session_id: object,
    network_log_file: str | None = None,
) -> None:
    """
    Runs run_anomaly_detection() in a thread executor.
    Pass network_log_file directly — avoids a second DB round-trip and
    ensures the file is read before _archive_log() moves it.
    Never raises.
    """
    if not _ANOMALY_AVAILABLE:
        logger.debug("[MonitorMain] Anomaly engine not installed — skipping")
        return
    try:
        loop    = asyncio.get_event_loop()
        sid_str = str(session_id) if session_id else None

        result: dict = await loop.run_in_executor(
            None,
            partial(_anomaly_run, domain, network_log_file, sid_str),
        )

        is_anomaly = result.get("is_anomaly", False)
        score      = result.get("anomaly_score", 0.0)
        severity   = result.get("severity", "low")
        method     = result.get("detection_method", "unknown")
        reasons    = result.get("top_reasons", [])

        if is_anomaly:
            logger.warning(
                "[MonitorMain] ⚠ ANOMALY DETECTED  "
                "domain=%-30s  score=%.3f  severity=%-8s  method=%s",
                domain, score, severity, method,
            )
            for i, r in enumerate(reasons[:3], start=1):
                logger.warning("[MonitorMain]   reason[%d]: %s", i, r)
        else:
            logger.info(
                "[MonitorMain] Anomaly ✓  domain=%-30s  score=%.3f  "
                "severity=%-4s  method=%s",
                domain, score, severity, method,
            )

        # ★ NEW — fan-out alerts (only fires when result.is_anomaly = True)
        if _ALERTS_AVAILABLE:
            try:
                # session_id ko result me daal de taa k alert me bhi save ho jaye
                if sid_str and "session_id" not in result:
                    result["session_id"] = sid_str
                count = await loop.run_in_executor(
                    None,
                    partial(alert_from_ai_anomaly_sync, domain, result),
                )
                if count:
                    logger.info(
                        "[MonitorMain] AI anomaly → %d alert(s) created", count,
                    )
            except Exception as e:
                logger.warning("[MonitorMain] AI anomaly alert hook failed: %s", e)

    except Exception as e:
        logger.exception("[MonitorMain] Anomaly detection failed for %s: %s", domain, e)


# ─────────────────────────────────────────────────────────────────────────────
# ARCHIVE LOG
# ─────────────────────────────────────────────────────────────────────────────

def _archive_log(network_log: str) -> None:
    try:
        if not network_log or not os.path.exists(network_log):
            return
        os.makedirs(ARCHIVE_LOG_DIR, exist_ok=True)
        dest = os.path.join(ARCHIVE_LOG_DIR, os.path.basename(network_log))
        shutil.move(network_log, dest)
        logger.info("[MonitorMain] Archived log → %s", dest)
    except Exception as e:
        logger.warning("[MonitorMain] Could not archive log %s: %s", network_log, e)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN CYCLE
# ─────────────────────────────────────────────────────────────────────────────

async def run_cycle() -> None:
    logger.info("[MonitorMain] ── Cycle start  %d target(s) ──", len(_crawlers))

    for crawler in _crawlers:
        session_id:  object     = None
        network_log: str | None = None

        logger.info("[MonitorMain] Crawling: %s", crawler.start_url)

        try:
            await crawler.run_once()

            session_id = crawler._session_id
            if not session_id:
                logger.error("[MonitorMain] No session_id for %s", crawler.domain)
                continue

            logger.info("[MonitorMain] Session ID: %s", session_id)

            snapshot = await get_monitor_snapshot(crawler.domain)
            if not snapshot:
                logger.warning("[MonitorMain] No snapshot for %s", crawler.domain)
                continue

            try:
                domain_id = await get_or_create_domain(crawler.domain)
            except Exception as e:
                logger.exception("[MonitorMain] Failed to get domain_id: %s", e)
                continue

            snapshot_dict = dict(snapshot)
            snapshot_dict["domain"]     = crawler.domain
            snapshot_dict["domain_id"]  = domain_id
            snapshot_dict["session_id"] = session_id

            network_log = snapshot_dict.get("network_log_file")

            if not network_log:
                logger.warning("[MonitorMain] No network log in snapshot")
                continue
            if not os.path.exists(network_log):
                logger.warning("[MonitorMain] Network log missing: %s", network_log)
                continue
            if os.path.getsize(network_log) == 0:
                logger.warning("[MonitorMain] Network log empty: %s", network_log)
                _archive_log(network_log)
                network_log = None
                continue

            logger.info(
                "[MonitorMain] Network log: %s (%d bytes)",
                network_log, os.path.getsize(network_log),
            )

            logger.info("[MonitorMain] Running passive scanner for %s", crawler.domain)
            try:
                await passive_scan_snapshot(snapshot_dict, session_id)
                logger.info("[MonitorMain] Passive scan done for %s", crawler.domain)
            except Exception as e:
                logger.exception("[MonitorMain] Passive scan failed: %s", e)

        except Exception as e:
            logger.exception("[MonitorMain] Cycle error for %s: %s", crawler.start_url, e)

        finally:
            # 1. Stop JS pool
            try:
                if crawler.js_pool:
                    await crawler.js_pool.stop()
                    crawler.js_pool = None
            except Exception as e:
                logger.warning("[MonitorMain] Error stopping JS pool: %s", e)

            if session_id:
                # 2. Prioritize
                try:
                    logger.info("[MonitorMain] Running prioritization (session=%s)", session_id)
                    res = run_post_scan_prioritization(session_id=session_id)
                    logger.info(
                        "[MonitorMain] Prioritization done  "
                        "scored=%s  critical=%s  high=%s  errors=%s",
                        res.get("scored", 0), res.get("critical", 0),
                        res.get("high",   0), res.get("errors",   0),
                    )
                except Exception as e:
                    logger.exception("[MonitorMain] Prioritization failed: %s", e)

                # 3. Posture Engine (with built-in alert hook)
                await _run_posture_engine(crawler.domain, session_id)

                # 4. Anomaly Detection  ← BEFORE archive  (with built-in alert hook)
                if network_log and os.path.exists(network_log):
                    await _run_anomaly_detection(
                        domain           = crawler.domain,
                        session_id       = session_id,
                        network_log_file = network_log,
                    )
                else:
                    logger.debug(
                        "[MonitorMain] Skipping anomaly — log absent for %s",
                        crawler.domain,
                    )
            else:
                logger.warning(
                    "[MonitorMain] Skipping prioritization + posture + anomaly"
                    " — no session_id"
                )

            # 5. Archive log  ← LAST
            try:
                if network_log and os.path.exists(network_log):
                    _archive_log(network_log)
            except Exception as e:
                logger.warning("[MonitorMain] Error archiving log: %s", e)

    logger.info("[MonitorMain] ── Cycle end ──")


# ─────────────────────────────────────────────────────────────────────────────
# ENTRYPOINT
# ─────────────────────────────────────────────────────────────────────────────

async def main() -> None:
    logger.info("[MonitorMain] Starting monitoring system...")

    try:
        await init_db()
        logger.info("[MonitorMain] Database initialised")
    except Exception as e:
        logger.exception("[MonitorMain] Database init failed: %s", e)
        return

    os.makedirs(NETWORK_LOG_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_LOG_DIR, exist_ok=True)
    os.makedirs("models", exist_ok=True)

    if not TARGET_URLS:
        logger.error("[MonitorMain] No TARGET_URLS configured")
        return

    for url in TARGET_URLS:
        try:
            _crawlers.append(MonitoringCrawler(start_url=url))
            logger.info("[MonitorMain] Crawler ready for %s", url)
        except Exception as e:
            logger.exception("[MonitorMain] Failed to create crawler for %s: %s", url, e)

    if not _crawlers:
        logger.error("[MonitorMain] No crawlers created — exiting")
        return

    logger.info(
        "[MonitorMain] Monitoring %d target(s)%s%s%s",
        len(_crawlers),
        "" if _POSTURE_AVAILABLE else "  [posture engine NOT installed]",
        "" if _ANOMALY_AVAILABLE else "  [anomaly engine NOT installed]",
        "" if _ALERTS_AVAILABLE else "  [alerts module NOT installed]",
    )

    scheduler = AsyncIOScheduler()
    scheduler.add_job(
        func               = run_cycle,
        trigger            = IntervalTrigger(minutes=MONITOR_INTERVAL_MINUTES),
        id                 = "monitor_cycle",
        max_instances      = 1,
        coalesce           = True,
        misfire_grace_time = 60,
    )
    scheduler.start()
    logger.info("[MonitorMain] Scheduler started — every %d min(s)", MONITOR_INTERVAL_MINUTES)

    try:
        logger.info("[MonitorMain] Running first cycle immediately...")
        await run_cycle()
    except Exception as e:
        logger.exception("[MonitorMain] First cycle failed: %s", e)

    try:
        logger.info("[MonitorMain] System ready — waiting for cycles...")
        await asyncio.Event().wait()
    except (KeyboardInterrupt, SystemExit):
        logger.info("[MonitorMain] Shutdown signal received")
    except Exception as e:
        logger.exception("[MonitorMain] Unexpected error: %s", e)

    finally:
        logger.info("[MonitorMain] Beginning shutdown sequence...")

        if _crawlers:
            flush: list = []
            if _POSTURE_AVAILABLE:
                flush += [
                    _run_posture_engine(c.domain, c._session_id)
                    for c in _crawlers if getattr(c, "_session_id", None)
                ]
            if _ANOMALY_AVAILABLE:
                # Final flush after shutdown — log already archived, engine
                # falls back to reading network_log_file from monitor_snapshots.
                flush += [
                    _run_anomaly_detection(c.domain, c._session_id, None)
                    for c in _crawlers if getattr(c, "_session_id", None)
                ]
            if flush:
                await asyncio.gather(*flush, return_exceptions=True)

        try:
            scheduler.shutdown(wait=False)
            logger.info("[MonitorMain] Scheduler shut down")
        except Exception as e:
            logger.warning("[MonitorMain] Scheduler shutdown error: %s", e)

        try:
            await close_db()
            logger.info("[MonitorMain] Database closed")
        except Exception as e:
            logger.warning("[MonitorMain] DB close error: %s", e)

        logger.info("[MonitorMain] Shutdown complete.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        logger.exception("[MonitorMain] Fatal error: %s", e)
        exit(1)