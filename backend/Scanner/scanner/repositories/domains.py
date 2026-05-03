import logging
from ..db import fetchrow

logger = logging.getLogger("webxguard.repositories.domains")


async def get_or_create_domain(domain_name: str) -> int:

    # Try to fetch existing domain
    row = await fetchrow("SELECT id FROM domains WHERE domain_name=$1", domain_name)
    if row:
        return row["id"]  # asyncpg.Record, so access by key

    # Insert new domain
    row = await fetchrow(
        "INSERT INTO domains (domain_name, last_crawled) VALUES ($1, NOW()) RETURNING id",
        domain_name
    )
    if row:
        return row["id"]

    raise Exception(f"Failed to insert domain {domain_name}")

async def get_domain_id_for_session(session_id: str) -> int | None:
    """
    Return the primary domain_id for a session.
    Uses the first crawled page's domain.
    Returns None if no pages have been crawled yet.
    """
    from ..db import fetchrow
    import logging
    logger = logging.getLogger("webxguard.repositories.domains")

    row = await fetchrow(
        """
        SELECT p.domain_id
        FROM   pages p
        JOIN   page_endpoints pe ON pe.page_id = p.id
        WHERE  pe.session_id = $1
        ORDER  BY p.id
        LIMIT  1
        """,
        session_id,
    )
    if row:
        return row["domain_id"]

    logger.warning(
        "[Domains] No pages found for session %s — domain_id unresolvable",
        session_id,
    )
    return None