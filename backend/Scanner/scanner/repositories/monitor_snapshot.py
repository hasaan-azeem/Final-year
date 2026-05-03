from ..db import execute, fetchrow
import logging

logger = logging.getLogger("webxguard.monitor_snapshots")


# -----------------------------
# Upsert snapshot
# -----------------------------
async def insert_monitor_snapshot(
    domain: str,
    network_log_file: str | None,
    session_id: str | None
) -> None:
    """
    FIX: Was a plain INSERT, which silently failed from cycle 2 onwards
    because monitor_snapshots.domain has a UNIQUE constraint.

    When the second (and every subsequent) cycle tried to insert a new row
    for the same domain, PostgreSQL raised a unique-violation; the exception
    was caught and swallowed, so the row was NEVER updated.
    get_monitor_snapshot() then returned the cycle-1 row, whose
    network_log_file had already been deleted → passive scanner got
    FileNotFoundError → zero vulnerabilities were ever reported after
    the very first run.

    The fix is a proper UPSERT: on conflict we overwrite the three mutable
    columns (network_log_file, session_id, updated_at) so every cycle's
    data is stored correctly.
    """
    try:
        await execute(
            """
            INSERT INTO monitor_snapshots
                (domain, network_log_file, session_id, updated_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (domain)
            DO UPDATE SET
                network_log_file = EXCLUDED.network_log_file,
                session_id       = EXCLUDED.session_id,
                updated_at       = NOW()
            """,
            domain, network_log_file, session_id
        )
    except Exception as e:
        logger.error(f"[MonitorSnapshots] upsert failed for {domain}: {e}")
        raise


# -----------------------------
# Fetch latest snapshot
# -----------------------------
async def get_monitor_snapshot(domain: str) -> dict | None:
    try:
        return await fetchrow(
            """
            SELECT *
            FROM monitor_snapshots
            WHERE domain = $1
            ORDER BY updated_at DESC
            LIMIT 1
            """,
            domain
        )
    except Exception as e:
        logger.error(f"[MonitorSnapshots] get_monitor_snapshot failed for {domain}: {e}")
        return None