from ..db import fetchrow, fetch, execute
import logging
from datetime import datetime

logger = logging.getLogger("webxguard.monitor_pages")

# -----------------------------
# Upsert page hash
# -----------------------------
async def upsert_monitor_page(domain: str, url: str, html_hash: str) -> None:
    """
    Insert a page hash for monitoring. Updates hash if URL exists.
    """
    try:
        await execute(
            """
            INSERT INTO monitor_pages (domain, url, html_hash, first_seen, last_checked)
            VALUES ($1, $2, $3, NOW(), NOW())
            ON CONFLICT (url)
            DO UPDATE SET
                html_hash = EXCLUDED.html_hash,
                last_checked = NOW()
            """,
            domain, url, html_hash
        )
    except Exception as e:
        logger.error(f"[MonitorPages] upsert_monitor_page failed for {url}: {e}")
        raise

# -----------------------------
# Fetch last known hash
# -----------------------------
async def get_monitor_page_hash(url: str) -> str | None:
    try:
        row = await fetchrow(
            "SELECT html_hash FROM monitor_pages WHERE url=$1",
            url
        )
        return row["html_hash"] if row else None
    except Exception as e:
        logger.error(f"[MonitorPages] get_monitor_page_hash failed for {url}: {e}")
        return None

# -----------------------------
# Fetch all pages for a domain
# -----------------------------
async def get_pages_by_domain(domain: str) -> list[dict]:
    try:
        rows = await fetch(
            "SELECT id, url, html_hash FROM monitor_pages WHERE domain=$1",
            domain
        )
        return [{"id": r["id"], "url": r["url"], "html_hash": r["html_hash"]} for r in rows]
    except Exception as e:
        logger.error(f"[MonitorPages] get_pages_by_domain failed for {domain}: {e}")
        return []