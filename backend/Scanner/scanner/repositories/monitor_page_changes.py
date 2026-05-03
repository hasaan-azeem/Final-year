from ..db import execute, fetch
from typing import List, Dict
import logging

logger = logging.getLogger("webxguard.monitor_page_changes")

# -----------------------------
# Insert a page change
# -----------------------------
async def insert_monitor_page_change(
    session_id: str,
    url: str,
    domain: str,
    old_hash: str | None,
    new_hash: str
) -> None:
    try:
        await execute(
            """
            INSERT INTO monitor_page_changes
            (session_id, url, domain, old_hash, new_hash, changed_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            """,
            session_id, url, domain, old_hash, new_hash
        )
    except Exception as e:
        logger.error(f"[MonitorPageChanges] insert failed for {url}: {e}")
        raise

# -----------------------------
# Fetch all changes for a session
# -----------------------------
async def get_changes_by_session(session_id: str) -> list[dict]:
    try:
        rows = await fetch(
            "SELECT url, domain, old_hash, new_hash, changed_at FROM monitor_page_changes WHERE session_id=$1",
            session_id
        )
        return [
            {
                "url": r["url"],
                "domain": r["domain"],
                "old_hash": r["old_hash"],
                "new_hash": r["new_hash"],
                "changed_at": r["changed_at"],
            }
            for r in rows
        ]
    except Exception as e:
        logger.error(f"[MonitorPageChanges] get_changes_by_session failed for {session_id}: {e}")
        return []

async def fetch_recent_page_changes(session_id: str | None = None) -> List[Dict]:
    """
    Fetch recent page changes from monitor_page_changes table.
    If session_id is provided, filter only for that session.
    Returns list of dicts: {url, old_hash, new_hash, changed_at}
    """
    if session_id:
        rows = await fetch(
            """
            SELECT url, old_hash, new_hash, changed_at
            FROM monitor_page_changes
            WHERE session_id = $1
            ORDER BY changed_at DESC
            """,
            session_id
        )
    else:
        rows = await fetch(
            """
            SELECT url, old_hash, new_hash, changed_at
            FROM monitor_page_changes
            ORDER BY changed_at DESC
            """
        )

    return [
        {
            "url": r["url"],
            "old_hash": r["old_hash"],
            "new_hash": r["new_hash"],
            "changed_at": r["changed_at"]
        }
        for r in rows
    ]