import asyncio
import logging
from urllib.parse import urlparse
from typing import Optional

from ..scoring import build_ai_scores, cvss_to_severity_band

logger = logging.getLogger("webxguard.headers_extra")

MAX_SNIPPET_LEN = 150

# ─────────────────────────────────────────────────────────────────────────────
# PROFILES  (must be registered in scoring.py)
#
#   "coop_missing_or_unsafe"   → security_headers / medium-high
#   "coep_missing_or_unsafe"   → security_headers / medium
#   "corp_missing_or_unsafe"   → security_headers / medium
# ─────────────────────────────────────────────────────────────────────────────

_SENSITIVE_PREFIXES = (
    "/admin", "/dashboard", "/login", "/account",
    "/payment", "/checkout", "/api", "/profile",
)


def _truncate(text: str) -> str:
    return text[:MAX_SNIPPET_LEN] if text else ""


def _domain_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"


def _boost_confidence(base: str, sensitive: bool) -> str:
    return "high" if sensitive and base == "medium" else base


def _is_sensitive_path(path: str) -> bool:
    lp = path.lower()
    return any(lp.startswith(p) for p in _SENSITIVE_PREFIXES)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_http_headers_extra(
    event:       dict,
    reporter,
    page_id:     Optional[int] = None,
    endpoint_id: Optional[int] = None,
    _seen:       Optional[set] = None,
) -> None:
    """
    Analyze cross-origin isolation headers from a single fetcher HTTP event.

    Checks:
      1. Cross-Origin-Opener-Policy  (COOP)
      2. Cross-Origin-Embedder-Policy (COEP)
      3. Cross-Origin-Resource-Policy (CORP)

    DEDUP: Domain-level (Option B).
      First hit  → inserts row with evidence.affected_pages = [url]
                   and evidence.cvss_band (consistent with headers.py)
      Subsequent → appends url to evidence.affected_pages via
                   reporter.append_evidence_page()

    PERFORMANCE: All three coroutines are gathered concurrently.
    _seen is updated synchronously before any awaits, so there is no
    race between first-hit checks and marks.

    Pass the same _seen set for all events in a scan session so dedup
    works correctly across multiple pages.
    """
    if _seen is None:
        _seen = set()

    try:
        url         = event.get("url")
        raw_headers = event.get("headers", {})
        status_code = event.get("status_code")

        if not url or not isinstance(raw_headers, dict) or status_code is None:
            return

        # Cross-origin headers apply to document and fetch resources;
        # skip sub-resources (images, fonts, media) to avoid noise.
        resource_type = event.get("resource_type", "")
        if resource_type and resource_type not in (
            "document", "xhr", "fetch", "other", ""
        ):
            return

        parsed    = urlparse(url)
        path      = parsed.path.lower() or "/"
        sensitive = _is_sensitive_path(path)
        domain    = _domain_root(url)

        headers = {k.lower(): str(v) for k, v in raw_headers.items()}

        raw_base = {
            "url":         url,
            "status_code": status_code,
            "path":        path,
        }

        # ── Dedup helpers  (synchronous — no races) ───────────────────────

        def _is_first(title: str) -> bool:
            return (domain, title) not in _seen

        def _mark(title: str):
            _seen.add((domain, title))

        # ── Coroutine builder ─────────────────────────────────────────────

        def _make_coro(title, confidence, profile_key, evidence, cwe, wasc, ref):
            """
            Returns the right coroutine without awaiting.
            _mark() is called synchronously so _seen is consistent before
            any I/O is dispatched.
            """
            if _is_first(title):
                _mark(title)
                scores = build_ai_scores(profile_key, url)
                meta   = scores.pop("_meta", {})
                return reporter.report(
                    page_url    = domain,
                    title       = title,
                    category    = "security_headers",
                    confidence  = confidence,
                    page_id     = page_id,
                    endpoint_id = endpoint_id,
                    evidence    = {
                        **evidence,
                        "affected_pages": [url],
                        # consistent with headers.py
                        "cvss_band": cvss_to_severity_band(scores.get("cvss_score")),
                    },
                    raw_data    = {**raw_base, **meta},
                    dedup_key   = (domain, title, "security_headers"),
                    cwe         = cwe,
                    wasc        = wasc,
                    reference   = ref,
                    **scores,
                )
            else:
                return reporter.append_evidence_page(domain, title, url)

        # ── Collect coroutines synchronously ─────────────────────────────
        coros = []

        # ─────────────────────────────────────────────────────────────────
        # 1. Cross-Origin-Opener-Policy (COOP)
        #    Valid: "same-origin", "same-origin-allow-popups"
        # ─────────────────────────────────────────────────────────────────
        coop = headers.get("cross-origin-opener-policy", "").lower().strip()
        if coop not in ("same-origin", "same-origin-allow-popups"):
            conf = _boost_confidence("medium", sensitive)
            coros.append(_make_coro(
                title       = "Missing or Unsafe Cross-Origin-Opener-Policy (COOP)",
                confidence  = conf,
                profile_key = "coop_missing_or_unsafe",
                evidence    = {"cross-origin-opener-policy": _truncate(coop) or "absent"},
                cwe         = "CWE-346",
                wasc        = "WASC-14",
                ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy",
            ))

        # ─────────────────────────────────────────────────────────────────
        # 2. Cross-Origin-Embedder-Policy (COEP)
        #    Valid: "require-corp"
        #    Fire when absent (empty string) OR any other value.
        # ─────────────────────────────────────────────────────────────────
        coep = headers.get("cross-origin-embedder-policy", "").lower().strip()
        if coep != "require-corp":
            conf = _boost_confidence("medium", sensitive)
            coros.append(_make_coro(
                title       = "Missing or Unsafe Cross-Origin-Embedder-Policy (COEP)",
                confidence  = conf,
                profile_key = "coep_missing_or_unsafe",
                evidence    = {"cross-origin-embedder-policy": _truncate(coep) or "absent"},
                cwe         = "CWE-346",
                wasc        = "WASC-14",
                ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy",
            ))

        # ─────────────────────────────────────────────────────────────────
        # 3. Cross-Origin-Resource-Policy (CORP)
        #    Valid: "same-origin", "same-site"
        #    "cross-origin" explicitly widens access — report it.
        # ─────────────────────────────────────────────────────────────────
        corp = headers.get("cross-origin-resource-policy", "").lower().strip()
        if corp not in ("same-origin", "same-site"):
            conf = _boost_confidence("medium", sensitive)
            coros.append(_make_coro(
                title       = "Missing or Unsafe Cross-Origin-Resource-Policy (CORP)",
                confidence  = conf,
                profile_key = "corp_missing_or_unsafe",
                evidence    = {"cross-origin-resource-policy": _truncate(corp) or "absent"},
                cwe         = "CWE-346",
                wasc        = "WASC-14",
                ref         = "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy",
            ))

        # ── Dispatch all coroutines in parallel ───────────────────────────
        if coros:
            await asyncio.gather(*coros)

    except Exception as e:
        logger.error(
            f"[HeadersExtra] Failed for {event.get('url', 'unknown')}: "
            f"{_truncate(str(e))}",
            exc_info=True,
        )