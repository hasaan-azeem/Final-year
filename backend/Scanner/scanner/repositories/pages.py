from ..db import fetchrow, execute, fetch
import logging

logger = logging.getLogger("webxguard.repositories.pages")


async def insert_page(
    domain_id: int,
    url: str,
    html_hash: str | None = None,
    antibot_detected: bool = False,
    spa_shell: bool = False,
    phase: str = "guest",
    public: bool | None = None  # <-- New field
) -> dict:
    """
    Safely insert a page into DB.
    If the page already exists (unique url), fetch the existing row instead.
    """
    try:
        await execute(
            """
            INSERT INTO pages (domain_id, url, html_hash, antibot_detected, spa_shell, phase, public, created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())
            """,
            domain_id, url, html_hash, antibot_detected, spa_shell, phase, public
        )
        page = await fetch_page_by_url(url)
        return page
    except Exception as e:
        if "duplicate key value" in str(e).lower():
            logger.warning(f"[DB] Page already exists: {url}")
            page = await fetch_page_by_url(url)
            if page:
                return page
            else:
                raise
        else:
            logger.error(f"[DB Error] insert_page {url} -> {e}")
            raise


async def fetch_page_by_url(url: str) -> dict | None:
    """
    Fetch a page by its URL.
    Returns None if page does not exist.
    """
    try:
        page = await fetchrow(
            """
            SELECT * FROM pages
            WHERE url=$1
            """,
            url
        )
        return page
    except Exception as e:
        logger.error(f"[DB Error] fetch_page_by_url {url} -> {e}")
        return None


async def get_page_html_hash(conn, page_id):
    row = await conn.fetchrow(
        "SELECT html_hash FROM pages WHERE id=$1",
        page_id
    )
    return row['html_hash'] if row else None


async def update_page_hash(conn, page_id, new_hash):
    await conn.execute(
        "UPDATE pages SET html_hash=$1, updated_at=NOW() WHERE id=$2",
        new_hash,
        page_id
    )


# -----------------------------
# Fetch pages for a session
# -----------------------------
async def get_pages_by_session(session_id: str) -> list[dict]:
    """
    Returns minimal info: id, domain_id, url
    """
    try:
        rows = await fetch(
            "SELECT id, domain_id, url FROM pages WHERE session_id=$1",
            session_id
        )
        return [{'id': r['id'], 'domain_id': r['domain_id'], 'url': r['url']} for r in rows]
    except Exception as e:
        logger.error(f"[DB Error] get_pages_by_session {session_id} -> {e}")
        return []
