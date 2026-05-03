"""
reporters.py (FIXED v4)

CRITICAL FIX vs v3:
  Return type of save_vulnerabilities_batch
  ──────────────────────────────────────────
  • In v3, save_vulnerabilities_batch() returned int (saved_count).
  • scanner.py's _flush_batch() iterated the return value as a
    set[tuple[str, str, str]] to match inserted rows back to dedup keys.
  • Result: every key in seen_vulns stayed as None — dedup tracking was
    completely broken. The same finding could be re-scored and re-attempted
    on every scan, wasting significant CPU time (though ON CONFLICT absorbed
    the duplicate INSERT).

  Fix: save_vulnerabilities_batch() now returns set[tuple[str, str, str]]
  where each tuple is (session_id, page_url, title) — the columns of the
  unique constraint (session_id, page_url, title) — matching exactly what
  _flush_batch() expects to update seen_vulns accurately.

  _insert_batch_chunk() is updated to return the same set type, built from
  the RETURNING rows.

  save_bulk() and the fallback path updated accordingly.
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, NamedTuple
from urllib.parse import urlparse, urlunparse

logger = logging.getLogger("webxguard.active_scanner.reporters")

from ....db import fetchrow, execute, fetch

# ═══════════════════════════════════════════════════════════════════════════════
# EMBEDDED CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

BATCH_INSERT_SIZE = 50

_C0_RE = re.compile(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]")

# Type alias for the dedup key returned by batch inserts
InsertedKeySet = set[tuple[str, str, str]]   # (session_id, page_url, title)


# ── Sanitisation helpers ──────────────────────────────────────────────────────

def _clean(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    value = value.replace("\u0000", "").replace("\x00", "")
    return _C0_RE.sub("", value)


def _normalize_payload(payload: str | dict | None) -> dict | None:
    if payload is None:
        return None
    if isinstance(payload, str):
        return {"value": payload}
    return payload


def _clean_obj(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _clean_obj(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_clean_obj(i) for i in obj]
    return _clean(obj)


def _to_json(obj: dict | None) -> str | None:
    if obj is None:
        return None
    try:
        cleaned = _clean_obj(obj)
        return json.dumps(cleaned, ensure_ascii=True)
    except (UnicodeEncodeError, UnicodeDecodeError):
        try:
            return json.dumps(_clean_obj(obj), ensure_ascii=True, default=lambda o: repr(o))
        except Exception as exc:
            logger.warning("[Reporter] JSON serialise failed (fallback): %s", exc)
            return None
    except Exception as exc:
        logger.warning("[Reporter] JSON serialise failed: %s", exc)
        return None


# ── URL normalization ─────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    parsed = urlparse(url)
    path   = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def _normalize_evidence_urls(evidence: dict | None) -> dict | None:
    if evidence and "response" in evidence and "final_url" in evidence["response"]:
        evidence["response"]["final_url"] = _normalize_url(evidence["response"]["final_url"])
    return evidence


def _normalize_raw_data_urls(raw_data: dict | None) -> dict | None:
    if raw_data and "response_url" in raw_data:
        raw_data["response_url"] = _normalize_url(raw_data["response_url"])
    return raw_data


# ── Single vulnerability insert ───────────────────────────────────────────────

async def save_vulnerability(
    *,
    session_id:         str,
    domain_id:          int,
    page_url:           str,
    title:              str,
    category:           str,
    confidence:         str,
    parameter_name:     str | None = None,
    payload:            str | dict | None = None,
    evidence:           dict | None = None,
    raw_data:           dict | None = None,
    cwe:                str | None = None,
    wasc:               str | None = None,
    reference:          str | None = None,
    page_id:            int | None = None,
    endpoint_id:        int | None = None,
    form_id:            int | None = None,
    severity:           float | None = None,
    likelihood:         float | None = None,
    impact:             float | None = None,
    cvss_score:         float | None = None,
    exploit_available:  bool | None = None,
    page_criticality:   float | None = None,
    severity_level:     float | None = None,
    target_priority:    float | None = None,
    priority_category:  str | None = None,
    **kwargs,
) -> int | None:
    """Save a single vulnerability. Returns the inserted row ID, or None if duplicate."""
    try:
        normalized_page_url  = _normalize_url(page_url)
        evidence             = _normalize_evidence_urls(evidence)
        raw_data             = _normalize_raw_data_urls(raw_data)
        normalized_payload   = _normalize_payload(payload)

        row = await fetchrow(
            """
            INSERT INTO vulnerabilities (
                session_id, domain_id, page_url,
                title, category, confidence,
                parameter_name, payload,
                evidence, raw_data,
                cwe, wasc, reference,
                page_id, endpoint_id, form_id,
                severity, likelihood, impact, cvss_score,
                exploit_available, page_criticality,
                severity_level, target_priority, priority_category
            ) VALUES (
                $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,
                $14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25
            )
            ON CONFLICT (session_id, page_url, title)
            DO NOTHING
            RETURNING id
            """,
            _clean(session_id), domain_id, _clean(normalized_page_url),
            _clean(title), _clean(category), _clean(confidence),
            _clean(parameter_name), _to_json(normalized_payload),
            _to_json(evidence), _to_json(raw_data),
            _clean(cwe), _clean(wasc), _clean(reference),
            page_id, endpoint_id, form_id,
            severity, likelihood, impact, cvss_score,
            exploit_available, page_criticality,
            severity_level, target_priority, _clean(priority_category),
        )

        if row:
            logger.info("[Reporter] Saved  id=%-5d  %-20s  %s", row["id"], category, title)
            return row["id"]

        logger.debug(
            "[Reporter] Duplicate skipped: %s | %s | param=%s",
            normalized_page_url, title, parameter_name,
        )
        return None

    except Exception as exc:
        logger.error(
            "[Reporter] Failed to save: category=%s url=%s — %s",
            category, page_url, type(exc).__name__,
        )
        logger.debug("[Reporter] save_vulnerability detail:", exc_info=True)
        return None


# ── Batch insert ──────────────────────────────────────────────────────────────

async def save_vulnerabilities_batch(
    vulns:          list[dict[str, Any]],
    max_batch_size: int = 100,
) -> InsertedKeySet:
    """
    Insert multiple vulnerabilities in a single parameterized query.

    CRITICAL FIX: Now returns InsertedKeySet = set[tuple[str, str, str]]
    where each tuple is (session_id, page_url, title) — the unique constraint
    columns. This allows scanner._flush_batch() to accurately update seen_vulns
    based on which rows the DB actually confirmed inserting.

    Previously returned int (saved count), causing _flush_batch() to leave
    every seen_vulns dedup key as None and re-process duplicates indefinitely.

    Args:
        vulns:          List of vulnerability dicts (as passed by scanner).
        max_batch_size: Chunk size for very large batches (PostgreSQL param limit:
                        65535 / 25 cols = 2621 rows max; 100 is conservative).

    Returns:
        Set of (session_id, page_url, title) tuples that were actually inserted.
    """
    if not vulns:
        return set()

    inserted: InsertedKeySet = set()

    for chunk_idx in range(0, len(vulns), max_batch_size):
        chunk = vulns[chunk_idx:chunk_idx + max_batch_size]
        try:
            chunk_inserted = await _insert_batch_chunk(chunk)
            inserted |= chunk_inserted
        except Exception as exc:
            logger.error("[Reporter] Batch insert failed for chunk: %s", exc)
            # Fallback: individual inserts, reconstruct the inserted key set
            for vuln in chunk:
                try:
                    result = await save_vulnerability(**vuln)
                    if result:
                        key = (
                            _clean(vuln.get("session_id", "")),
                            _normalize_url(vuln.get("page_url", "")),
                            _clean(vuln.get("title", "")),
                        )
                        inserted.add(key)
                except Exception as inner_exc:
                    logger.error("[Reporter] Individual insert failed: %s", inner_exc)

    return inserted


async def _insert_batch_chunk(vulns: list[dict[str, Any]]) -> InsertedKeySet:
    """
    Internal: Build parameterized batch INSERT and return the set of inserted keys.

    RETURNING clause includes session_id, page_url, title so we can build the
    inserted key set without holding a mapping from row-index to vuln dict.
    """
    if not vulns:
        return set()

    cleaned_vulns = []
    for vuln in vulns:
        normalized_page_url = _normalize_url(vuln.get("page_url", ""))
        evidence            = _normalize_evidence_urls(vuln.get("evidence"))
        raw_data            = _normalize_raw_data_urls(vuln.get("raw_data"))
        normalized_payload  = _normalize_payload(vuln.get("payload"))

        cleaned_vulns.append({
            "session_id":       _clean(vuln.get("session_id", "")),
            "domain_id":        vuln.get("domain_id", 0),
            "page_url":         _clean(normalized_page_url),
            "title":            _clean(vuln.get("title", "")),
            "category":         _clean(vuln.get("category", "")),
            "confidence":       _clean(vuln.get("confidence", "")),
            "parameter_name":   _clean(vuln.get("parameter_name")),
            "payload":          _to_json(normalized_payload),
            "evidence":         _to_json(evidence),
            "raw_data":         _to_json(raw_data),
            "cwe":              _clean(vuln.get("cwe")),
            "wasc":             _clean(vuln.get("wasc")),
            "reference":        _clean(vuln.get("reference")),
            "page_id":          vuln.get("page_id"),
            "endpoint_id":      vuln.get("endpoint_id"),
            "form_id":          vuln.get("form_id"),
            "severity":         vuln.get("severity"),
            "likelihood":       vuln.get("likelihood"),
            "impact":           vuln.get("impact"),
            "cvss_score":       vuln.get("cvss_score"),
            "exploit_available":vuln.get("exploit_available"),
            "page_criticality": vuln.get("page_criticality"),
            "severity_level":   vuln.get("severity_level"),
            "target_priority":  vuln.get("target_priority"),
            "priority_category":_clean(vuln.get("priority_category")),
        })

    placeholders = []
    values       = []

    for idx, vuln in enumerate(cleaned_vulns):
        param_indices = list(range(1 + idx * 25, 1 + (idx + 1) * 25))
        placeholders.append(f"({','.join(f'${i}' for i in param_indices)})")
        values.extend([
            vuln["session_id"], vuln["domain_id"], vuln["page_url"],
            vuln["title"], vuln["category"], vuln["confidence"],
            vuln["parameter_name"], vuln["payload"],
            vuln["evidence"], vuln["raw_data"],
            vuln["cwe"], vuln["wasc"], vuln["reference"],
            vuln["page_id"], vuln["endpoint_id"], vuln["form_id"],
            vuln["severity"], vuln["likelihood"], vuln["impact"], vuln["cvss_score"],
            vuln["exploit_available"], vuln["page_criticality"],
            vuln["severity_level"], vuln["target_priority"], vuln["priority_category"],
        ])

    # FIX: RETURNING now includes the unique-constraint columns so we can build
    # the inserted key set directly from DB-confirmed rows (not row index math).
    query = f"""
        INSERT INTO vulnerabilities (
            session_id, domain_id, page_url,
            title, category, confidence,
            parameter_name, payload,
            evidence, raw_data,
            cwe, wasc, reference,
            page_id, endpoint_id, form_id,
            severity, likelihood, impact, cvss_score,
            exploit_available, page_criticality,
            severity_level, target_priority, priority_category
        ) VALUES {','.join(placeholders)}
        ON CONFLICT (session_id, page_url, title)
        DO NOTHING
        RETURNING session_id, page_url, title
    """

    try:
        rows = await fetch(query, *values)

        inserted: InsertedKeySet = {
            (row["session_id"], row["page_url"], row["title"])
            for row in rows
        }

        if inserted:
            logger.info(
                "[Reporter] Batch insert saved %d/%d vulnerabilities",
                len(inserted), len(vulns),
            )
        else:
            logger.debug(
                "[Reporter] Batch insert: all %d were duplicates (skipped)", len(vulns),
            )

        return inserted

    except Exception as exc:
        logger.error("[Reporter] Batch query failed: %s", exc)
        raise


# ── Bulk helper ───────────────────────────────────────────────────────────────

class BulkResult(NamedTuple):
    saved:      int
    duplicates: int
    errors:     int


async def save_bulk(findings: list[dict[str, Any]]) -> BulkResult:
    """Save a list of findings via batch insert with individual fallback."""
    if not findings:
        return BulkResult(0, 0, 0)

    try:
        inserted   = await save_vulnerabilities_batch(findings)
        saved      = len(inserted)
        duplicates = len(findings) - saved
        return BulkResult(saved=saved, duplicates=duplicates, errors=0)

    except Exception as exc:
        logger.warning("[Reporter] Batch save failed, falling back to individual: %s", exc)

        results = await asyncio.gather(
            *(save_vulnerability(**f) for f in findings),
            return_exceptions=True,
        )

        saved = duplicates = errors = 0
        for r in results:
            if isinstance(r, Exception):
                errors += 1
            elif r is None:
                duplicates += 1
            else:
                saved += 1

        return BulkResult(saved=saved, duplicates=duplicates, errors=errors)