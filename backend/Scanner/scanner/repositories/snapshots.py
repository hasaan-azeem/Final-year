from ..db import fetchrow, fetch
import logging
from typing import Optional

logger = logging.getLogger("webxguard.snapshots")


async def insert_snapshot(
    domain_id: int,
    network_log_file: str | None = None,
    screenshot_path: str | None = None,
    session_id: int | None = None,
) -> Optional[int]:
    """
    Inserts a crawl snapshot for a domain in a scan session.
    Returns the snapshot ID.
    """
    try:
        query = """
            INSERT INTO crawl_snapshots (
                domain_id,
                network_log_file,
                screenshot_path,
                session_id
            )
            VALUES ($1, $2, $3, $4)
            RETURNING id
        """
        row = await fetchrow(
            query,
            domain_id,
            network_log_file,
            screenshot_path,
            session_id,
        )
        return row["id"]
    except Exception as e:
        logger.error(
            f"[Snapshots] Insert failed for domain_id={domain_id}: {e}"
        )
        raise

async def get_snapshots(session_id: str):
    return await fetch("""
        SELECT network_log_file, domain_id
        FROM crawl_snapshots
        WHERE session_id = $1
    """, session_id)