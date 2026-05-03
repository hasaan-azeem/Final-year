"""
repositories/sessions.py

BUG FIX — start_scan_session() must accept an optional session_id.

When called from the API, the session_id is pre-created by api.py so the
frontend can poll /api/scan/{session_id} before the scan even starts.
Previously start_scan_session() always generated its own UUID, so the API's
session_id and the scan's session_id were always different UUIDs.

If session_id is None (CLI usage) a new UUID is generated as before.
"""
from __future__ import annotations

import uuid
from ..db import fetchrow, execute


async def start_scan_session(session_id: str | None = None) -> str:
    """
    Create a new scan session row in the DB.

    Args:
        session_id: pre-created UUID from the API.  If None, a new UUID is
                    generated (original CLI behaviour, unchanged).

    Returns:
        The session_id string that was inserted.
    """
    sid = session_id or str(uuid.uuid4())

    await execute(
        """
        INSERT INTO scan_sessions (id, status, started_at)
        VALUES ($1::uuid, 'running', NOW())
        ON CONFLICT (id) DO NOTHING
        """,
        sid,
    )
    return sid


async def finish_scan_session(session_id: str) -> None:
    await execute(
        """
        UPDATE scan_sessions
        SET    status = 'complete', finished_at = NOW()
        WHERE  id = $1::uuid
        """,
        session_id,
    )

# -----------------------------
# Fetch a scan session by ID
# -----------------------------
async def get_scan_session(session_id: str) -> dict | None:
    query = """
        SELECT *
        FROM scan_sessions
        WHERE id = $1
    """
    row = await fetchrow(query, session_id)
    return row or {}

async def get_user_scan_sessions(user_id: int, limit: int = 100) -> list[dict]:
    """Ek user ki saari scan sessions, latest first."""
    rows = await fetch(
        """
        SELECT id, url, status, started_at, finished_at, scan_type
        FROM   scan_sessions
        WHERE  user_id = $1
        ORDER  BY started_at DESC
        LIMIT  $2
        """,
        user_id, limit,
    )
    return [dict(r) for r in rows]

async def session_belongs_to_user(session_id: str, user_id: int) -> bool:
    """Security check: kya yeh session is user ki hai?"""
    row = await fetchrow(
        "SELECT 1 FROM scan_sessions WHERE id = $1::uuid AND user_id = $2",
        session_id, user_id,
    )
    return row is not None