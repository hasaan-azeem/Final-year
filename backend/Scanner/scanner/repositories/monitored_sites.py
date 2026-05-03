"""
repositories/monitored_sites.py

Continuous Monitoring k liye user-specific sites.
Yeh table user ne kaunse websites monitor pe daali hain track karta hai.
"""
from __future__ import annotations

from urllib.parse import urlparse
from ..db import fetchrow, fetch, execute


def _domain_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


async def add_monitored_site(
    user_id: int,
    url:     str,
) -> dict | None:
    """User k liye naya site add karein. Agar pehle se hai to wahi return."""
    domain = _domain_from_url(url)
    row = await fetchrow(
        """
        INSERT INTO monitored_sites (user_id, url, domain, is_active, created_at)
        VALUES ($1, $2, $3, TRUE, NOW())
        ON CONFLICT (user_id, url) DO UPDATE SET
            is_active = TRUE
        RETURNING *
        """,
        user_id, url, domain,
    )
    return dict(row) if row else None


async def update_site_session(site_id: int, session_id: str) -> None:
    """Jab scan complete ho ya start ho, latest session_id store karein."""
    await execute(
        """
        UPDATE monitored_sites
        SET    last_session_id = $2::uuid,
               last_checked    = NOW()
        WHERE  id = $1
        """,
        site_id, session_id,
    )


async def remove_monitored_site(user_id: int, site_id: int) -> bool:
    """Site delete karein (soft delete = is_active false)."""
    result = await execute(
        """
        UPDATE monitored_sites
        SET    is_active = FALSE
        WHERE  id = $1 AND user_id = $2
        """,
        site_id, user_id,
    )
    # asyncpg execute returns "UPDATE n" string
    try:
        return int(result.split()[-1]) > 0
    except Exception:
        return False


async def get_user_monitored_sites(user_id: int) -> list[dict]:
    """
    User ki saari monitored sites + unka latest scan score / vuln count.
    Frontend ContinuousMonitoring page yeh dikhata hai.
    """
    rows = await fetch(
        """
        SELECT
            ms.id,
            ms.url,
            ms.domain,
            ms.is_active,
            ms.created_at,
            ms.last_checked,
            ms.last_session_id::text                                              AS session_id,
            COALESCE(ss.status, 'pending')                                        AS scan_status,
            COUNT(v.id)                                                           AS total_vulns,
            COUNT(CASE WHEN v.priority_category = 'Critical' THEN 1 END)          AS critical,
            COUNT(CASE WHEN v.priority_category = 'High'     THEN 1 END)          AS high,
            COUNT(CASE WHEN v.priority_category = 'Medium'   THEN 1 END)          AS medium,
            COUNT(CASE WHEN v.priority_category = 'Low'      THEN 1 END)          AS low
        FROM     monitored_sites ms
        LEFT JOIN scan_sessions   ss ON ss.id          = ms.last_session_id
        LEFT JOIN vulnerabilities v  ON v.session_id   = ms.last_session_id
        WHERE    ms.user_id   = $1
          AND    ms.is_active = TRUE
        GROUP BY ms.id, ss.status
        ORDER BY ms.created_at DESC
        """,
        user_id,
    )

    out = []
    for r in rows:
        d = dict(r)
        # Score formula: 100 - Critical*15 - High*8 - Medium*3 - Low*1
        score = max(
            0,
            100 - (d["critical"] or 0) * 15
                - (d["high"]     or 0) * 8
                - (d["medium"]   or 0) * 3
                - (d["low"]      or 0) * 1,
        )
        d["score"] = score
        out.append(d)
    return out