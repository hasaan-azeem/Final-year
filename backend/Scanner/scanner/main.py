"""
WebXGuard / main.py

BUG FIX 2 — Session ID mismatch:
  The previous version called `await start_scan_session()` unconditionally,
  which created a brand-new UUID and ignored the session_id passed by api.py.
  The API stored `b937c1dc` in _scans and polled it, but the entire scan ran
  under `99ed30ae` — a completely different UUID.  The fix: pass the
  api-provided session_id straight through to start_scan_session().

BUG FIX 3 (passive scanner) — START_URLS[0] IndexError:
  passive_scan_snapshot() hard-coded START_URLS[0] to derive the scope host.
  When the URL comes from the API, config.START_URLS = [] → IndexError.
  Fix: main() now passes start_url into run_passive_scan() which forwards it
  to passive_scan_snapshot() as scope_url.

LOGIN CONFIG:
  When login_config.login_enabled is True, the per-request credentials are
  applied to the config module before the Crawler is constructed.  The config
  module remains the single source of truth for every component that reads it
  (Crawler, passive scanner, etc.).  After the scan the overrides are reset to
  None so a subsequent CLI run is not accidentally affected.

DB pool:
  When called from the API the pool was opened in lifespan and must stay open
  across scans.  close_db() is only called here when running from the CLI.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Imported only for type hints — avoids a circular import at runtime.
    from ..app import LoginConfig

from .db import init_db, close_db
from .scrapper.core import Crawler
from .repositories.sessions import start_scan_session
from .repositories.snapshots import get_snapshots
from .repositories.domains import get_domain_id_for_session
from .scanner_engine.passive_scanner.scanner import passive_scan_snapshot
from .scanner_engine.active_scanner.scanner import run_active_scan
from . import config
from .config import START_URLS, SCAN_TYPE
from .compliance.checker import run_compliance_check

from .ai_risk_analysis.scheduler import run_once, run_fallback_scoring_only
from .ai_risk_analysis.priority_model import (
    PriorityPredictor,
    DatabaseManager,
    DB_CONFIG,
    MODEL_PATH,
    DATASET_PATH,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)
logger = logging.getLogger("webxguard.main")


# ── ML bootstrap ──────────────────────────────────────────────────────────────

def _ensure_model_trained() -> None:
    if Path(MODEL_PATH).exists():
        logger.info("[ML] Saved model found at %s — skipping training", MODEL_PATH)
        return

    if Path(DATASET_PATH).exists():
        logger.info("[ML] Training from CSV dataset: %s", DATASET_PATH)
        p = PriorityPredictor()
        if p.train_from_csv(DATASET_PATH):
            p.save_model(MODEL_PATH)
            logger.info("[ML] Model trained from CSV and saved → %s", MODEL_PATH)
        else:
            logger.error("[ML] CSV training failed — check dataset format")
        return

    logger.warning("[ML] No CSV found at %s — trying DB labelled rows…", DATASET_PATH)
    db = DatabaseManager(DB_CONFIG)
    if not db.connect():
        logger.warning("[ML] DB unreachable — will use rule-based fallback scoring")
        return

    df = db.fetch_training_data()
    db.close()

    if len(df) < 20:
        logger.warning(
            "[ML] Only %d labelled DB rows (need >= 20). "
            "Copy dataset.csv to %s to enable ML scoring.",
            len(df), DATASET_PATH,
        )
        return

    p = PriorityPredictor()
    if p.train_model(df):
        p.save_model(MODEL_PATH)
        logger.info("[ML] Model trained from DB and saved → %s", MODEL_PATH)
    else:
        logger.error("[ML] Training failed")


# ── ML scoring ────────────────────────────────────────────────────────────────

async def run_ml_scoring(session_id: str) -> None:
    logger.info("[ML] Starting priority scoring for session %s", session_id)
    loop = asyncio.get_event_loop()

    ml_succeeded = False
    try:
        ok = await loop.run_in_executor(None, run_once, session_id)
        if ok:
            logger.info("[ML] Priority scoring complete")
            ml_succeeded = True
        else:
            logger.warning("[ML] run_once returned False — triggering fallback")
    except Exception as e:
        logger.error("[ML] run_once raised: %s — triggering fallback", e, exc_info=True)

    if not ml_succeeded:
        try:
            await loop.run_in_executor(None, run_fallback_scoring_only, session_id)
        except Exception as e:
            logger.error("[ML] Fallback scoring also raised: %s", e, exc_info=True)


# ── Login config helper ───────────────────────────────────────────────────────

def _apply_login_config(login_config: "LoginConfig | None") -> None:
    """
    Write per-request login credentials into the config module so the Crawler
    and every other component that imports config picks them up automatically.
    Only applied when login_enabled is True; otherwise config defaults are kept.
    """
    if login_config is None or not login_config.login_enabled:
        return

    config.LOGIN_ENABLED    = True
    config.AUTH_TYPE        = login_config.auth_type
    config.LOGIN_URL        = login_config.login_url
    config.LOGIN_USERNAME   = login_config.login_username
    config.LOGIN_PASSWORD   = login_config.login_password
    config.LOGIN_USER_FIELD = login_config.login_user_field
    config.LOGIN_PASS_FIELD = login_config.login_pass_field

    logger.info(
        "[Main] Login config applied — auth_type=%s  login_url=%s",
        login_config.auth_type,
        login_config.login_url,
    )


def _reset_login_config() -> None:
    """
    Clear login credentials from the config module after the scan completes.
    Prevents credentials leaking into a subsequent CLI run in the same process.
    """
    config.LOGIN_ENABLED    = None
    config.AUTH_TYPE        = None
    config.LOGIN_URL        = None
    config.LOGIN_USERNAME   = None
    config.LOGIN_PASSWORD   = None
    config.LOGIN_USER_FIELD = None
    config.LOGIN_PASS_FIELD = None


# ── Scan helpers ──────────────────────────────────────────────────────────────

async def run_passive_scan(session_id: str, scope_url: str) -> None:
    """
    scope_url: the URL actually being scanned (may differ from START_URLS
               when the request comes from the API).
    """
    snapshots = await get_snapshots(session_id)
    logger.info("[Passive] %d snapshots fetched", len(snapshots))
    for snapshot in snapshots:
        try:
            # BUG FIX 3: pass scope_url so passive scanner doesn't rely on
            # START_URLS[0] which is empty when called via the API.
            await passive_scan_snapshot(snapshot, session_id, scope_url=scope_url)
        except Exception as e:
            logger.exception(
                "[Passive] Failed for snapshot %s: %s",
                snapshot.get("network_log_file"), e,
            )


async def run_active_scan_wrapper(session_id: str) -> None:
    try:
        total_vulns = await run_active_scan(session_id)
        logger.info("[Active] Completed — %d vulnerabilities found.", total_vulns)
    except Exception as e:
        logger.exception("[Active] Scan failed: %s", e)


# ── Main pipeline ─────────────────────────────────────────────────────────────

async def main(
    start_url:    str | None           = None,
    session_id:   str | None           = None,
    login_config: "LoginConfig | None" = None,
    user_id:          int | None       = None,   # ★ ADD
    status_callback                    = None,   # ★ ADD
) -> None:
    """
    Entry point for both the API (all three params supplied) and the CLI
    (all three are None — falls back to config.START_URLS).
    """

    # ── 0. ML bootstrap ───────────────────────────────────────────────────────
    _ensure_model_trained()

    # ── 1. Database ───────────────────────────────────────────────────────────
    # Safe to call even when the API lifespan already called it.
    await init_db()
    logger.info("[Main] Database initialized")

    # ── 2. Resolve URLs ───────────────────────────────────────────────────────
    urls = [start_url] if start_url else START_URLS
    if not urls:
        raise ValueError(
            "No start URLs provided — set START_URLS in config.py "
            "or submit a URL via the API."
        )

    # ── 3. Apply login config (before Crawler is constructed) ─────────────────
    _apply_login_config(login_config)

    # ── 4. Scan session ───────────────────────────────────────────────────────
    # BUG FIX 2: use the session_id created by the API instead of creating a
    # new one.  start_scan_session() accepts an optional session_id param and
    # INSERTs that specific UUID rather than generating a fresh one.
    session_id = await start_scan_session(session_id=session_id)
    logger.info("[Main] New scan session: %s", session_id)

    # ── 5. Crawler ────────────────────────────────────────────────────────────
    crawler = Crawler(start_urls=urls, session_id=session_id)
    try:
        await crawler.run()
    finally:
        if crawler.js_pool:
            await crawler.js_pool.stop()
        logger.info("[Main] Crawler shutdown complete")

    # ── 6. Resolve domain_id ──────────────────────────────────────────────────
    domain_id: int | None = await get_domain_id_for_session(session_id)
    if domain_id is None:
        logger.error(
            "[Main] Could not resolve domain_id for session %s — "
            "compliance check will be skipped", session_id,
        )

    # ── 7. Scan execution ─────────────────────────────────────────────────────
    scope_url = urls[0]
    logger.info("[Main] Selected SCAN_TYPE: %s", SCAN_TYPE)

    if SCAN_TYPE == "passive":
        await run_passive_scan(session_id, scope_url)
    elif SCAN_TYPE == "active":
        await run_active_scan_wrapper(session_id)
    elif SCAN_TYPE == "full":
        await run_passive_scan(session_id, scope_url)
        await run_active_scan_wrapper(session_id)
    else:
        logger.error("[Main] Invalid SCAN_TYPE: %s", SCAN_TYPE)

    # ── 8. Compliance check ───────────────────────────────────────────────────
    if domain_id is not None:
        try:
            logger.info("[Main] Running compliance check...")
            summary = await run_compliance_check(
                session_id = session_id,
                domain_id  = domain_id,
            )
            for std, result in summary.items():
                logger.info(
                    "[Compliance] %-15s  %5.1f%%  %-4s  (%d/%d rules ok)",
                    std,
                    result["score_percent"],
                    result["status"].upper(),
                    result["compliant_rules"],
                    result["total_rules"],
                )
        except Exception as e:
            logger.exception("[Main] Compliance check failed: %s", e)
    else:
        logger.warning("[Main] Compliance check skipped — domain_id unavailable")

    # ── 9. ML priority scoring ────────────────────────────────────────────────
    await run_ml_scoring(session_id)

    # ── 10. Teardown ──────────────────────────────────────────────────────────
    # Reset login credentials so they don't bleed into the next scan.
    _reset_login_config()

    # Only close the DB pool when running from CLI.
    # The API lifespan handler owns the pool lifetime across multiple scans.
    if start_url is None:
        await close_db()
        logger.info("[Main] Database pool closed.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.warning("[Main] Interrupted — running fallback scoring…")
        try:
            run_fallback_scoring_only()
        except Exception as fb_exc:
            logger.error("[Main] Fallback scoring failed: %s", fb_exc)
    except Exception as e:
        logger.exception("[Main] Fatal error: %s", e)