# repositories/vulnerabilities.py
from ..db import execute  # Ensure this uses asyncpg fetchrow

async def create_vulnerability(
    session_id: str,
    domain_id: int,
    page_url: str,
    title: str,
    category: str,
    confidence: str,
    evidence: dict = None,
    raw_data: dict = None,
    parameter_name: str = None,
    payload: str = None,
    page_id: int = None,
    endpoint_id: int = None,
    form_id: int = None
) -> int:
    query = """
    INSERT INTO vulnerabilities
    (session_id, domain_id, page_url, title, category, confidence, evidence, raw_data,
     parameter_name, payload, page_id, endpoint_id, form_id, created_at)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,CURRENT_TIMESTAMP)
    ON CONFLICT (session_id, page_url, title)
    DO UPDATE SET
        confidence = EXCLUDED.confidence,
        evidence = EXCLUDED.evidence,
        raw_data = EXCLUDED.raw_data,
        parameter_name = EXCLUDED.parameter_name,
        payload = EXCLUDED.payload,
        page_id = EXCLUDED.page_id,
        endpoint_id = EXCLUDED.endpoint_id,
        form_id = EXCLUDED.form_id,
        created_at = CURRENT_TIMESTAMP
    RETURNING id
    """
    try:
        vuln_id = await execute(
            query,
            session_id, domain_id, page_url, title, category, confidence,
            evidence, raw_data, parameter_name, payload,
            page_id, endpoint_id, form_id
        )
        return vuln_id
    except Exception as e:
        print(f"[!] Error inserting vulnerability: {e}")
        return None

"""
repositories/vulnerabilities.py  — ADD THIS FUNCTION

Paste this into your existing scanner/repositories/vulnerabilities.py file.
It is the async function that api.py calls to return vuln rows to the frontend.

Requires your existing db.py fetch() helper (same one used by reporters.py).
"""

from ..db import fetch   # adjust relative import to match your package structure


async def get_vulnerabilities_for_session(session_id: str) -> list[dict]:
    """
    Return all vulnerability rows for a scan session, ordered by severity desc.
    Used by the API endpoint GET /api/scan/{session_id}/vulns.
    """
    rows = await fetch(
        """
        SELECT
            id,
            page_url,
            title,
            category,
            confidence,
            cwe,
            wasc,
            reference,
            severity,
            likelihood,
            impact,
            cvss_score,
            exploit_available,
            page_criticality,
            severity_level,
            target_priority,
            priority_category,
            created_at
        FROM vulnerabilities
        WHERE session_id = $1
        ORDER BY
            COALESCE(target_priority, cvss_score, 0) DESC,
            id ASC
        """,
        session_id,
    )
    return [dict(r) for r in rows] if rows else []