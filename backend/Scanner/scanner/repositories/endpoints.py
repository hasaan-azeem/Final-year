from ..db import fetchrow, execute, fetch

async def insert_endpoint(
    url: str,
    md5_hash: str,
    type: str = "api",
    js_only: bool = False
) -> dict:
    try:
        await execute(
            """
            INSERT INTO endpoints (url, md5_hash, type, js_only, created_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (md5_hash) DO NOTHING
            """,
            url,
            md5_hash,
            type,
            js_only
        )

        return await fetchrow(
            "SELECT * FROM endpoints WHERE md5_hash=$1",
            md5_hash
        )

    except Exception:
        raise

async def link_page_endpoint(page_id: int, endpoint_id: int, session_id: str):
    query = """
        INSERT INTO page_endpoints(page_id, endpoint_id, session_id, created_at)
        VALUES ($1, $2, $3, NOW())
        ON CONFLICT DO NOTHING
    """
    await execute(query, page_id, endpoint_id, session_id)

async def get_endpoints_by_session(session_id: str) -> list[dict]:
    return await fetch("""
        SELECT e.*
        FROM endpoints e
        JOIN page_endpoints pe ON pe.endpoint_id=e.id
        WHERE pe.session_id=$1
    """, session_id)

async def get_endpoints_by_page(page_id):
    query = """
    SELECT e.id, e.url
    FROM endpoints e
    JOIN page_endpoints pe ON e.id = pe.endpoint_id
    WHERE pe.page_id = $1
    """
    rows = await fetch(query, page_id)
    return [{'id': r['id'], 'url': r['url']} for r in rows]