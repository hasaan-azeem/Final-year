from ..db import fetchrow, fetch, execute

async def insert_auth_session(
    domain_id: int,
    session_id: str | None = None,  # must be UUID string
    login_url: str | None = None,
    username: str | None = None,
    password: str | None = None,
) -> dict:
    """
    Insert a new auth session for a domain/login attempt.
    No conflict handling here; just insert.
    """
    query = """
        INSERT INTO auth_sessions
        (domain_id, session_id, login_url, username, password, created_at, last_used)
        VALUES ($1, $2, $3, $4, $5, NOW(), NOW())
        RETURNING *
    """
    return await fetchrow(query, domain_id, session_id, login_url, username, password)

async def get_auth_sessions_for_domain(domain_id: int) -> list[dict]:
    rows = await fetch(
        """
        SELECT *
        FROM auth_sessions
        WHERE domain_id=$1
        ORDER BY last_used DESC
        """,
        domain_id
    ) or []

    return rows