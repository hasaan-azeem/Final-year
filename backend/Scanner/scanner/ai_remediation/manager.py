"""
backend/Scanner/scanner/ai_remediation/manager.py
=================================================
Public entry point for getting a remediation for a vulnerability finding.

Lookup order
------------
1. DB cache       (vulnerability_remediations) — instant
2. Static KB      (knowledge_base.py)          — instant, no API
3. Groq LLM       (ai_client.py)               — ~1 second
4. Generic stub                                 — instant, never empty

Whatever wins is cached in DB so subsequent requests for the same
vuln_signature are O(1).

Public API
----------
    await get_remediation_for_vuln(vuln_dict)        # async, used by FastAPI
    get_remediations_for_session_async(session_id)   # async, batched

Internal helpers also expose sync versions for engine code that runs in
thread executors (not currently used, but kept consistent with alerts/).
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from typing import Any
from urllib.parse import urlparse

from .knowledge_base import lookup_kb
from .ai_client       import generate_ai_remediation, generic_stub

logger = logging.getLogger("webxguard.ai_remediation.manager")


# ─────────────────────────────────────────────────────────────────────────────
# Signature — deterministic key for caching
# ─────────────────────────────────────────────────────────────────────────────

def _vuln_signature(
    title:    str | None,
    category: str | None,
    page_url: str | None,
    cwe:      str | None,
) -> str:
    """
    Build a stable lookup key. Same vuln on same page = same signature, so
    we don't generate a new fix every scan. Page URL is normalized to its
    path so query strings don't break caching.
    """
    parts = [
        (category or "").strip().lower(),
        (cwe      or "").strip().lower(),
        (title    or "").strip().lower()[:120],
    ]
    if page_url:
        try:
            p = urlparse(page_url)
            parts.append(f"{p.netloc}{p.path}".lower())
        except Exception:
            parts.append(page_url.lower())
    raw = "|".join(parts)
    digest = hashlib.sha1(raw.encode()).hexdigest()[:24]
    return f"v1:{digest}"


# ─────────────────────────────────────────────────────────────────────────────
# DB cache (async — used by FastAPI request flow)
# ─────────────────────────────────────────────────────────────────────────────

async def _cache_lookup_async(signature: str) -> dict | None:
    """Return cached payload if present, else None."""
    from ..db import fetchrow
    row = await fetchrow(
        """
        SELECT summary, fix_steps, code_example, references, source, model
        FROM   vulnerability_remediations
        WHERE  vuln_signature = $1
        """,
        signature,
    )
    if not row:
        return None
    return {
        "summary":      row["summary"],
        "fix_steps":    row["fix_steps"]  or [],
        "code_example": row["code_example"],
        "references":   row["references"] or [],
        "source":       row["source"],
        "model":        row["model"],
        "cached":       True,
    }


async def _cache_store_async(
    *,
    signature:        str,
    vulnerability_id: int | None,
    payload:          dict,
    title:            str,
    category:         str | None,
    page_url:         str | None,
    cwe:              str | None,
    severity:         str | None,
    generation_ms:    int,
) -> None:
    """Insert or upsert the remediation row. Best-effort — errors are logged."""
    from ..db import execute
    try:
        await execute(
            """
            INSERT INTO vulnerability_remediations (
                vulnerability_id, vuln_signature,
                vuln_title, vuln_category, page_url, cwe, severity,
                summary, fix_steps, code_example, references,
                source, model, generation_ms
            )
            VALUES (
                $1, $2,
                $3, $4, $5, $6, $7,
                $8, $9::jsonb, $10, $11::jsonb,
                $12, $13, $14
            )
            ON CONFLICT (vuln_signature) DO UPDATE SET
                summary       = EXCLUDED.summary,
                fix_steps     = EXCLUDED.fix_steps,
                code_example  = EXCLUDED.code_example,
                references    = EXCLUDED.references,
                source        = EXCLUDED.source,
                model         = EXCLUDED.model,
                generation_ms = EXCLUDED.generation_ms,
                updated_at    = NOW()
            """,
            vulnerability_id, signature,
            title, category, page_url, cwe, severity,
            payload.get("summary"),
            json.dumps(payload.get("fix_steps") or [],   default=str),
            payload.get("code_example"),
            json.dumps(payload.get("references") or [],  default=str),
            payload.get("source") or "ai",
            payload.get("model")  or "unknown",
            generation_ms,
        )
    except Exception as e:
        logger.warning("[Remediation] cache store failed (sig=%s): %s", signature, e)


# ─────────────────────────────────────────────────────────────────────────────
# Public — single vuln
# ─────────────────────────────────────────────────────────────────────────────

async def get_remediation_for_vuln(vuln: dict) -> dict:
    """
    Resolve a remediation payload for one vulnerability row.

    `vuln` is expected to look like a row from the `vulnerabilities` table:
        { id, title, category, page_url, cwe, severity, ... }

    Always returns a payload (worst case the generic stub).
    """
    title    = str(vuln.get("title")    or "Vulnerability")
    category = vuln.get("category")
    page_url = vuln.get("page_url")
    cwe      = vuln.get("cwe")
    severity = vuln.get("severity") or vuln.get("priority_category")
    vuln_id  = vuln.get("id")

    sig = _vuln_signature(title, category, page_url, cwe)

    # ── 1. DB cache ────────────────────────────────────────────────
    cached = await _cache_lookup_async(sig)
    if cached:
        return cached

    # ── 2. Static KB ──────────────────────────────────────────────
    started = time.time()
    payload = lookup_kb(category, title)

    # ── 3. AI fallback ────────────────────────────────────────────
    if payload is None:
        payload = generate_ai_remediation(
            title    = title,
            category = category,
            page_url = page_url,
            cwe      = cwe,
            severity = severity,
        )

    # ── 4. Generic stub ───────────────────────────────────────────
    if payload is None:
        payload = generic_stub(title)

    elapsed_ms = int((time.time() - started) * 1000)

    # Cache for next time (don't cache the generic stub — let LLM retry next time)
    if payload.get("source") in ("static", "ai"):
        await _cache_store_async(
            signature        = sig,
            vulnerability_id = vuln_id,
            payload          = payload,
            title            = title,
            category         = category,
            page_url         = page_url,
            cwe              = cwe,
            severity         = severity,
            generation_ms    = elapsed_ms,
        )

    payload = dict(payload)
    payload["cached"] = False
    return payload


# ─────────────────────────────────────────────────────────────────────────────
# Public — batched for one scan session (used by ScanDetail page)
# ─────────────────────────────────────────────────────────────────────────────

async def get_remediations_for_session_async(
    session_id: str,
    *,
    only_critical_high: bool = False,
    limit:              int  = 50,
) -> list[dict]:
    """
    Generate remediations for every vuln in a session. Returns a list with
    one entry per vulnerability merged with its remediation payload.

    Front-end ScanDetail page calls this once and gets everything ready.
    """
    from ..db import fetch

    where = "session_id = $1::uuid"
    if only_critical_high:
        where += " AND priority_category IN ('Critical', 'High')"

    rows = await fetch(
        f"""
        SELECT id, page_url, title, category, cwe, severity,
               cvss_score, priority_category, target_priority,
               severity_level, confidence
        FROM   vulnerabilities
        WHERE  {where}
        ORDER  BY COALESCE(target_priority, cvss_score, 0) DESC
        LIMIT  {int(limit)}
        """,
        session_id,
    )

    out: list[dict] = []
    for r in rows:
        v = dict(r)
        try:
            rem = await get_remediation_for_vuln(v)
        except Exception as e:
            logger.warning("[Remediation] failed for vuln %s: %s", v.get("id"), e)
            rem = generic_stub(v.get("title") or "Vulnerability")

        v["remediation"] = rem
        out.append(v)

    return out