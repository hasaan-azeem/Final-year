import json
import logging
from urllib.parse import urlparse, urlunparse
from typing import Optional

from ...db import execute

logger = logging.getLogger("webxguard.reporter")


# ─────────────────────────────────────────────────────────────────────────────
# DERIVED FORMULA
# ─────────────────────────────────────────────────────────────────────────────

def _compute_severity_level(
    severity: Optional[float],
    impact: Optional[float],
    likelihood: Optional[float],
) -> Optional[float]:
    if any(v is None for v in (severity, impact, likelihood)):
        return None
    raw = (severity * 0.40 + impact * 0.35 + likelihood * 0.25) * 10
    return round(min(max(raw, 0.0), 10.0), 2)


# ─────────────────────────────────────────────────────────────────────────────
# JSONB SERIALIZER
# asyncpg does NOT auto-convert dicts to JSONB — the value passed for a
# JSONB column must be a JSON string.  This helper lives here only so that
# no scanner module ever needs to call json.dumps() itself.
# ─────────────────────────────────────────────────────────────────────────────

def _to_jsonb(obj) -> Optional[str]:
    if obj is None:
        return None
    if isinstance(obj, str):
        return obj          # already a JSON string — pass through
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
    Single entry point for all scanner modules to record vulnerabilities.

    Design principles
    ─────────────────
    • severity_level computed automatically — scanners never touch it.
    • target_priority + priority_category always NULL — AI fills later.
    • evidence + raw_data: pass plain dicts (or None). json.dumps() is
      applied internally before the DB call — never do it in a scanner.
    • ON CONFLICT refreshes all mutable fields EXCEPT target_priority and
      priority_category so AI scores already written survive re-scans.
    • Dedup is in-memory per Reporter instance (one per scan session).
    """

    def __init__(self, session_id: str, domain_id: int):
        self.session_id = session_id
        self.domain_id  = domain_id
        self._seen: set = set()

    @property
    def reported_count(self) -> int:
        """Number of unique vulnerabilities recorded this session."""
        return len(self._seen)

    @staticmethod
    def _normalize_url(url: str) -> str:
        p = urlparse(url)
        return urlunparse(p._replace(
            path=p.path.rstrip("/"),
            query="",
            fragment=""
        ))

    async def report(
        self,
        *,
        # Required
        page_url:   str,
        title:      str,
        category:   str,
        confidence: str,
        # Context refs
        page_id:      Optional[int] = None,
        endpoint_id:  Optional[int] = None,
        form_id:      Optional[int] = None,
        # Finding detail
        parameter_name: Optional[str]  = None,
        payload:        Optional[str]  = None,
        evidence:       Optional[dict] = None,  # plain dict — serialized here
        raw_data:       Optional[dict] = None,  # plain dict — serialized here
        cwe:            Optional[str]  = None,
        wasc:           Optional[str]  = None,
        reference:      Optional[str]  = None,
        # AI feature inputs
        # severity / likelihood / impact  →  [0, 1]
        # cvss_score / page_criticality   →  [0, 10]
        severity:          Optional[float] = None,
        likelihood:        Optional[float] = None,
        impact:            Optional[float] = None,
        cvss_score:        Optional[float] = None,
        exploit_available: Optional[bool]  = None,
        page_criticality:  Optional[float] = None,
        # Dedup override
        dedup_key: Optional[tuple] = None,
    ) -> None:

        # ── Validate ──────────────────────────────────────────────────────
        if not all([page_url, title, category, confidence]):
            logger.warning(
                f"[Reporter] Skipping — missing required field: "
                f"url={page_url!r} title={title!r} "
                f"category={category!r} confidence={confidence!r}"
            )
            return

        # ── Normalize URL ─────────────────────────────────────────────────
        normalized_url = self._normalize_url(page_url)

        # ── In-memory dedup ───────────────────────────────────────────────
        key = dedup_key or (normalized_url, title, category)
        if key in self._seen:
            return
        self._seen.add(key)

        # ── Derived field ─────────────────────────────────────────────────
        severity_level = _compute_severity_level(severity, impact, likelihood)

        # ── Serialize JSONB fields ────────────────────────────────────────
        evidence_str = _to_jsonb(evidence)
        raw_data_str = _to_jsonb(raw_data)

        # ── Upsert ────────────────────────────────────────────────────────
        try:
            await execute(
                """
                INSERT INTO vulnerabilities (
                    session_id,     domain_id,    page_url,
                    title,          category,     confidence,
                    page_id,        endpoint_id,  form_id,
                    parameter_name, payload,
                    evidence,       raw_data,
                    cwe,            wasc,         reference,
                    severity,       likelihood,   impact,
                    cvss_score,     exploit_available, page_criticality,
                    severity_level,
                    target_priority, priority_category
                )
                VALUES (
                    $1,  $2,  $3,
                    $4,  $5,  $6,
                    $7,  $8,  $9,
                    $10, $11,
                    $12, $13,
                    $14, $15, $16,
                    $17, $18, $19,
                    $20, $21, $22,
                    $23,
                    NULL, NULL
                )
                ON CONFLICT (session_id, page_url, title) DO UPDATE SET
                    confidence        = EXCLUDED.confidence,
                    page_id           = EXCLUDED.page_id,
                    endpoint_id       = EXCLUDED.endpoint_id,
                    form_id           = EXCLUDED.form_id,
                    parameter_name    = EXCLUDED.parameter_name,
                    payload           = EXCLUDED.payload,
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
                self.session_id, self.domain_id,  normalized_url,    # $1  $2  $3
                title,           category,         confidence,         # $4  $5  $6
                page_id,         endpoint_id,      form_id,            # $7  $8  $9
                parameter_name,  payload,                              # $10 $11
                evidence_str,    raw_data_str,                         # $12 $13
                cwe,             wasc,             reference,          # $14 $15 $16
                severity,        likelihood,       impact,             # $17 $18 $19
                cvss_score,      exploit_available, page_criticality,  # $20 $21 $22
                severity_level,                                         # $23
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
    # JSONB APPEND — domain-level findings (e.g. header checks)
    # ─────────────────────────────────────────────────────────────────────────

    async def append_evidence_page(
        self,
        page_url:   str,
        title:      str,
        append_url: str,
    ) -> None:
        """
        Append append_url into evidence->affected_pages[] for an existing row.
        Uses jsonb_set + || for an atomic append that never overwrites
        other keys already in the evidence object.
        """
        try:
            await execute(
                """
                UPDATE vulnerabilities
                SET evidence = jsonb_set(
                    COALESCE(evidence, '{"affected_pages":[]}'::jsonb),
                    '{affected_pages}',
                    COALESCE(evidence->'affected_pages', '[]'::jsonb)
                    || to_jsonb($1::text)
                )
                WHERE session_id = $2
                  AND page_url   = $3
                  AND title      = $4
                """,
                append_url,                          # $1
                self.session_id,                     # $2
                self._normalize_url(page_url),       # $3
                title,                               # $4
            )
            logger.debug(
                f"[Reporter] Appended '{append_url}' → evidence.affected_pages "
                f"for '{title}'"
            )
        except Exception as e:
            logger.error(
                f"[Reporter] append_evidence_page failed — '{title}': {e}"
            )