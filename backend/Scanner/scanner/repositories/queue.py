from ..db import fetchrow, execute
from ..config import MAX_RETRIES_PER_URL

async def enqueue_url(url: str, domain: str, depth: int, session_id: str, retries: int = 0):
    """
    Add URL to queue. If URL exists, keep lowest retries count.
    """
    await execute(
        """
        INSERT INTO crawler_queue (url, domain, depth, session_id, retries)
        VALUES ($1,$2,$3,$4,$5)
        ON CONFLICT (url, session_id) DO UPDATE
        SET retries = LEAST(crawler_queue.retries, $5)
        """,
        url, domain, depth, session_id, retries
    )

async def fetch_next_url(session_id: str) -> dict | None:
    """
    Fetch next pending URL (status='pending') with retries < MAX_RETRIES_PER_URL
    """
    return await fetchrow(
        """
        UPDATE crawler_queue
        SET status='in_progress', updated_at=NOW()
        WHERE id = (
            SELECT id FROM crawler_queue
            WHERE session_id=$1
              AND status='pending'
              AND (retries IS NULL OR retries < $2)
            ORDER BY created_at
            FOR UPDATE SKIP LOCKED
            LIMIT 1
        )
        RETURNING *
        """,
        session_id,
        MAX_RETRIES_PER_URL
    )

async def mark_done(queue_id: int, failed: bool = False):
    """
    Mark queue item as done or failed.
    If failed, increment retries counter.
    """
    if failed:
        # Increment retries
        await execute(
            """
            UPDATE crawler_queue
            SET status='pending', retries = COALESCE(retries, 0) + 1, updated_at=NOW()
            WHERE id=$1
            """,
            queue_id
        )
    else:
        # Mark as done
        await execute(
            """
            UPDATE crawler_queue
            SET status='done', updated_at=NOW()
            WHERE id=$1
            """,
            queue_id
        )
