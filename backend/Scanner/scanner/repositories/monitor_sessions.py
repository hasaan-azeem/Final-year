from ..db import fetchrow, fetch, execute
import logging
from datetime import datetime

logger = logging.getLogger("webxguard.monitor_sessions")

# -----------------------------
# Create a monitoring session
# -----------------------------
async def start_monitor_session(domain: str) -> str:
    """
    Start a new monitoring session.
    Returns the session_id (UUID string).
    """
    try:
        row = await fetchrow(
            """
            INSERT INTO monitor_sessions (domain, started_at)
            VALUES ($1, NOW())
            RETURNING id
            """,
            domain
        )
        return str(row["id"])
    except Exception as e:
        logger.error(f"[MonitorSessions] start_monitor_session failed for {domain}: {e}")
        raise

# -----------------------------
# Finish monitoring session
# -----------------------------
async def finish_monitor_session(session_id: str, pages_scanned: int = 0, changes_detected: int = 0):
    """
    Mark monitoring session finished.
    """
    try:
        await execute(
            """
            UPDATE monitor_sessions
            SET finished_at = NOW(),
                pages_scanned = $2,
                changes_detected = $3
            WHERE id = $1
            """,
            session_id, pages_scanned, changes_detected
        )
    except Exception as e:
        logger.error(f"[MonitorSessions] finish_monitor_session failed for {session_id}: {e}")
        raise

# -----------------------------
# Fetch a session by ID
# -----------------------------
async def get_monitor_session(session_id: str) -> dict | None:
    try:
        return await fetchrow(
            "SELECT * FROM monitor_sessions WHERE id=$1",
            session_id
        )
    except Exception as e:
        logger.error(f"[MonitorSessions] get_monitor_session failed: {e}")
        return None