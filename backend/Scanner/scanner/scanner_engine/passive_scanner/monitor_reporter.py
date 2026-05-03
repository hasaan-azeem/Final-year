import json
import logging
from typing import Optional
from urllib.parse import urlparse, urlunparse

from ...db import execute

logger = logging.getLogger("webxguard.monitor.reporter")


# ─────────────────────────────────────────────────────────────────────────────
# DERIVED FORMULA
# severity_level = (severity×0.40 + impact×0.35 + likelihood×0.25) × 10
# ─────────────────────────────────────────────────────────────────────────────

def _compute_severity_level(
    severity:   Optional[float],
    impact:     Optional[float],
    likelihood: Optional[float],
) -> Optional[float]:
    if any(v is None for v in (severity, impact, likelihood)):
        return None
    raw = (severity * 0.40 + impact * 0.35 + likelihood * 0.25) * 10
    return round(min(max(raw, 0.0), 10.0), 2)


# ─────────────────────────────────────────────────────────────────────────────
# JSONB SERIALIZER
# asyncpg does not auto-convert dicts to JSONB — must pass a JSON string.
# ─────────────────────────────────────────────────────────────────────────────

def _to_jsonb(obj) -> Optional[str]:
    if obj is None:
        return None
    if isinstance(obj, str):
        return obj      # already serialized — pass through
    try:
        return json.dumps(obj)
    except (TypeError, ValueError) as exc:
        logger.warning(f"[Reporter] JSONB serialization failed: {exc}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# REPORTER
# ─────────────────────────────────────────────────────────────────────────────

class Reporter:
    """
    Single entry point for all monitor scanner modules to record findings
    into monitor_vulnerabilities.

    Constructor
    ───────────
        Reporter(session_id="<uuid>", domain="www.example.com")

    Design
    ──────
    • severity_level computed automatically — scanners never set it.
    • target_priority + priority_category always NULL — AI fills later.
    • evidence + raw_data: pass plain dicts. json.dumps() applied internally.
    • ON CONFLICT (monitor_session_id, page_url, title) refreshes all mutable
      fields EXCEPT target_priority / priority_category so AI scores survive
      re-scans.
    • dedup_key must be a tuple — bare strings are rejected with a warning.
    • Columns not in this table (domain_id, page_id, endpoint_id, form_id,
      parameter_name, payload) are silently accepted and discarded so modules
      written for the main scanner never raise TypeError.
    """

    def __init__(self, session_id: str):
        self.session_id = session_id
        self._seen: set = set()

    @property
    def reported_count(self) -> int:
        return len(self._seen)

    @staticmethod
    def _normalize_url(url: str) -> str:
        p = urlparse(url)
        return urlunparse(p._replace(
            path=p.path.rstrip("/"),
            query="",
            fragment=""
        ))

    @staticmethod
    def _extract_domain(url: str) -> str:
        """
        Derive bare domain (hostname) from any URL.
        e.g. https://www.example.com/login → www.example.com
        Falls back to empty string on parse failure.
        """
        try:
            return urlparse(url).hostname or ""
        except Exception:
            return ""

    async def report(
        self,
        *,
        # ── Required ──────────────────────────────────────────────────────
        page_url:   str,
        title:      str,
        category:   str,
        confidence: str,
        # ── Finding detail ────────────────────────────────────────────────
        evidence:  Optional[dict] = None,
        raw_data:  Optional[dict] = None,
        cwe:       Optional[str]  = None,
        wasc:      Optional[str]  = None,
        reference: Optional[str]  = None,
        # ── AI feature inputs ─────────────────────────────────────────────
        severity:          Optional[float] = None,
        likelihood:        Optional[float] = None,
        impact:            Optional[float] = None,
        cvss_score:        Optional[float] = None,
        exploit_available: Optional[bool]  = None,
        page_criticality:  Optional[float] = None,
        # ── Dedup override ────────────────────────────────────────────────
        dedup_key: Optional[tuple] = None,
        # ── Not columns in this table — accepted to avoid TypeError ───────
        domain_id:      Optional[int] = None,
        page_id:        Optional[int] = None,
        endpoint_id:    Optional[int] = None,
        form_id:        Optional[int] = None,
        parameter_name: Optional[str] = None,
        payload:        Optional[str] = None,
    ) -> None:

        # ── Validate ──────────────────────────────────────────────────────
        if not all([page_url, title, category, confidence]):
            logger.warning(
                f"[Reporter] Skipping — missing required field: "
                f"url={page_url!r} title={title!r} "
                f"category={category!r} confidence={confidence!r}"
            )
            return

        # ── Normalize URL + derive domain ─────────────────────────────────
        normalized_url = self._normalize_url(page_url)
        domain         = self._extract_domain(page_url)

        # ── In-memory dedup ───────────────────────────────────────────────
        if dedup_key is not None and not isinstance(dedup_key, tuple):
            logger.warning(
                f"[Reporter] dedup_key must be a tuple, got "
                f"{type(dedup_key).__name__} — using default for '{title}'"
            )
            dedup_key = None

        key = dedup_key or (normalized_url, title, category)
        if key in self._seen:
            logger.debug(f"[Reporter][Dedup] skipped: {title} | {normalized_url}")
            return
        self._seen.add(key)

        # ── Derived field ─────────────────────────────────────────────────
        severity_level = _compute_severity_level(severity, impact, likelihood)

        # Warn loudly if no AI scores — means the module is the old version
        if severity is None and impact is None and likelihood is None:
            logger.warning(
                f"[Reporter] NO SCORES for '{title}' — module did not call "
                f"build_ai_scores(). Rows will have NULL severity columns."
            )

        # ── Serialize JSONB fields ────────────────────────────────────────
        evidence_str = _to_jsonb(evidence)
        raw_data_str = _to_jsonb(raw_data)

        # ── Upsert ────────────────────────────────────────────────────────
        try:
            await execute(
                """
                INSERT INTO monitor_vulnerabilities (
                    monitor_session_id, domain,       page_url,
                    title,              category,     confidence,
                    evidence,           raw_data,
                    cwe,                wasc,         reference,
                    severity,           likelihood,   impact,
                    cvss_score,         exploit_available, page_criticality,
                    severity_level,
                    target_priority,    priority_category
                )
                VALUES (
                    $1,  $2,  $3,
                    $4,  $5,  $6,
                    $7,  $8,
                    $9,  $10, $11,
                    $12, $13, $14,
                    $15, $16, $17,
                    $18,
                    NULL, NULL
                )
                ON CONFLICT (monitor_session_id, page_url, title) DO UPDATE SET
                    confidence        = EXCLUDED.confidence,
                    evidence          = EXCLUDED.evidence,
                    raw_data          = EXCLUDED.raw_data,
                    cwe               = EXCLUDED.cwe,
                    wasc              = EXCLUDED.wasc,
                    reference         = EXCLUDED.reference,
                    severity          = EXCLUDED.severity,
                    likelihood        = EXCLUDED.likelihood,
                    impact            = EXCLUDED.impact,
                    cvss_score        = EXCLUDED.cvss_score,
                    exploit_available = EXCLUDED.exploit_available,
                    page_criticality  = EXCLUDED.page_criticality,
                    severity_level    = EXCLUDED.severity_level
                    -- target_priority + priority_category deliberately omitted:
                    -- AI scores already written must never be overwritten by re-scan
                """,
                self.session_id,  domain,            normalized_url,    # $1  $2  $3
                title,            category,           confidence,         # $4  $5  $6
                evidence_str,     raw_data_str,                           # $7  $8
                cwe,              wasc,               reference,          # $9  $10 $11
                severity,         likelihood,         impact,             # $12 $13 $14
                cvss_score,       exploit_available,  page_criticality,   # $15 $16 $17
                severity_level,                                            # $18
            )

            logger.info(
                f"[Reporter] {category} | {confidence} | {title} | {normalized_url} "
                f"| severity_level={severity_level} cvss={cvss_score} "
                f"| CWE={cwe} WASC={wasc}"
            )

        except Exception as e:
            logger.error(
                f"[Reporter] Insert failed — '{title}' @ {normalized_url}: {e}"
            )

    # ─────────────────────────────────────────────────────────────────────────
    # JSONB APPEND — domain-level findings (e.g. header / SSL checks)
    # ─────────────────────────────────────────────────────────────────────────

    async def append_evidence_page(
        self,
        page_url:   str,
        title:      str,
        append_url: str,
    ) -> None:
        """
        Atomically append append_url into evidence->affected_pages[]
        for an existing monitor_vulnerabilities row.
        """
        try:
            await execute(
                """
                UPDATE monitor_vulnerabilities
                SET evidence = jsonb_set(
                    COALESCE(evidence, '{"affected_pages":[]}'::jsonb),
                    '{affected_pages}',
                    COALESCE(evidence->'affected_pages', '[]'::jsonb)
                    || to_jsonb($1::text)
                )
                WHERE monitor_session_id = $2
                  AND page_url           = $3
                  AND title              = $4
                """,
                append_url,                        # $1
                self.session_id,                   # $2
                self._normalize_url(page_url),     # $3
                title,                             # $4
            )
            logger.debug(
                f"[Reporter] Appended '{append_url}' → evidence.affected_pages "
                f"for '{title}'"
            )
        except Exception as e:
            logger.error(
                f"[Reporter] append_evidence_page failed — '{title}': {e}"
            )