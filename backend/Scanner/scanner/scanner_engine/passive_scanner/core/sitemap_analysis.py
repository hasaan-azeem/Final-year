import asyncio
import re
import logging
from typing import Optional
from urllib.parse import urlparse

from ..scoring import build_ai_scores, get_path_tier_name

logger = logging.getLogger("webxguard.sitemap")

MAX_SNIPPET_LEN   = 150
MAX_URLS_EVIDENCE = 10
LARGE_SITEMAP     = 1000

LOC_RE = re.compile(r"<loc>\s*(.*?)\s*</loc>", re.I | re.S)

_SENSITIVE_TIERS = frozenset({"critical", "high", "elevated"})

_STAGING_KEYWORDS: frozenset = frozenset({
    "staging", "stage",
    "dev", "develop", "development",
    "test", "testing",
    "qa", "uat",
    "beta", "alpha",
    "local", "preprod", "sandbox",
})

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    return (text or "")[:MAX_SNIPPET_LEN]


def _is_sitemap_url(url: str) -> bool:
    path = urlparse(url).path.lower()
    return "sitemap" in path or path.endswith(".xml")


def _path_tier(path: str) -> str:
    """Return the scoring tier name for a path. Computed once per path."""
    return get_path_tier_name(f"https://x{path}")


def _is_sensitive_path(path: str) -> bool:
    return _path_tier(path) in _SENSITIVE_TIERS


def _is_staging_domain(netloc: str) -> bool:
    nl = netloc.lower()
    return any(kw in nl for kw in _STAGING_KEYWORDS)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_sitemap(
    entry:   dict,
    reporter,
    page_id: Optional[int] = None,
) -> None:
    """
    Parse an XML sitemap response and report information-disclosure findings.

    Detects
    ───────
    1. Large attack-surface exposure (> 1 000 URLs).
    2. Sensitive paths in <loc> entries  (one finding per distinct path).
    3. Staging / dev domain references  (one finding per distinct netloc).
    4. URLs with query parameters       (one finding per distinct param set).

    PERFORMANCE:
    ────────────
    • get_path_tier_name() called exactly once per <loc> URL (result reused
      for both the sensitivity check and the evidence dict).
    • All coroutines are collected synchronously then dispatched with a
      single asyncio.gather() call so reporter I/O runs concurrently.

    Parameters
    ──────────
    entry    — one "http"-type event from fetcher's network_events list.
               Expected keys: url, body, status_code.
    reporter — Reporter instance (webxguard.reporter.Reporter).
    page_id  — pages.id FK forwarded to reporter.
    """
    try:
        url         = entry.get("url", "")
        body        = entry.get("body") or ""
        status_code = entry.get("status_code")

        if not url or not body or status_code != 200:
            return

        if not _is_sitemap_url(url):
            return

        if "<urlset" not in body and "<sitemapindex" not in body:
            return

        locs = LOC_RE.findall(body)
        if not locs:
            return

        # Deduplicate loc entries before analysis
        seen_locs: set = set()
        unique_locs:  list = []
        for loc in locs:
            loc = loc.strip()
            if loc and loc not in seen_locs:
                seen_locs.add(loc)
                unique_locs.append(loc)

        coros: list = []

        # ── 1. Large sitemap surface area ─────────────────────────────────
        if len(unique_locs) > LARGE_SITEMAP:
            scores = build_ai_scores("sitemap_large_surface", url)
            meta   = scores.pop("_meta", {})
            coros.append(reporter.report(
                page_url   = url,
                title      = "Large Sitemap Exposes Attack Surface",
                category   = "information_disclosure",
                confidence = "medium",
                page_id    = page_id,
                evidence   = {
                    "url_count":   len(unique_locs),
                    "sample_urls": [_snippet(u) for u in unique_locs[:MAX_URLS_EVIDENCE]],
                },
                raw_data   = {"url_count": len(unique_locs), **meta},
                cwe        = "CWE-200",
                wasc       = "WASC-13",
                reference  = (
                    "https://owasp.org/www-project-web-security-testing-guide"
                    "/latest/4-Web_Application_Security_Testing"
                    "/01-Information_Gathering/03-Review_Webserver_Metafiles"
                ),
                dedup_key  = (url, "Large Sitemap Exposes Attack Surface", "information_disclosure"),
                **scores,
            ))

        # ── Per-URL analysis ──────────────────────────────────────────────
        seen_sensitive:  set = set()
        seen_staging:    set = set()
        seen_query_sigs: set = set()

        for loc in unique_locs:
            parsed = urlparse(loc)
            path   = parsed.path   or ""
            netloc = parsed.netloc or ""
            query  = parsed.query  or ""

            # ── 2. Sensitive path in sitemap ──────────────────────────────
            # BUG FIX: original called get_path_tier_name() twice for the
            # same path — once inside _is_sensitive_path(), then again in the
            # evidence dict. Now computed once and reused for both.
            if path not in seen_sensitive:
                tier = _path_tier(path)                   # ← computed once
                if tier in _SENSITIVE_TIERS:
                    seen_sensitive.add(path)
                    scores = build_ai_scores("sitemap_sensitive_path", url)
                    meta   = scores.pop("_meta", {})
                    coros.append(reporter.report(
                        page_url   = url,
                        title      = "Sensitive Path Listed in Sitemap",
                        category   = "information_disclosure",
                        confidence = "high",
                        page_id    = page_id,
                        evidence   = {
                            "listed_url": _snippet(loc),
                            "path":       _snippet(path),
                            "path_tier":  tier,           # ← reused, not recomputed
                        },
                        raw_data   = {"loc": loc, "path": path, **meta},
                        cwe        = "CWE-200",
                        wasc       = "WASC-13",
                        reference  = (
                            "https://owasp.org/www-community/attacks"
                            "/Information_Leak_through_sitemaps"
                        ),
                        dedup_key  = (url, f"Sensitive Path in Sitemap::{path}", "information_disclosure"),
                        **scores,
                    ))

            # ── 3. Staging / dev domain ───────────────────────────────────
            if netloc and netloc not in seen_staging and _is_staging_domain(netloc):
                seen_staging.add(netloc)
                scores = build_ai_scores("sitemap_staging_domain", url)
                meta   = scores.pop("_meta", {})
                coros.append(reporter.report(
                    page_url   = url,
                    title      = "Staging or Dev Domain Listed in Sitemap",
                    category   = "information_disclosure",
                    confidence = "high",
                    page_id    = page_id,
                    evidence   = {
                        "listed_url":   _snippet(loc),
                        "staging_host": netloc,
                    },
                    raw_data   = {"loc": loc, "netloc": netloc, **meta},
                    cwe        = "CWE-200",
                    wasc       = "WASC-13",
                    reference  = (
                        "https://owasp.org/www-community/attacks"
                        "/Information_Leak_through_sitemaps"
                    ),
                    dedup_key  = (url, f"Staging Domain in Sitemap::{netloc}", "information_disclosure"),
                    **scores,
                ))

            # ── 4. Query parameters in sitemap URL ────────────────────────
            if query:
                param_names = sorted(
                    k for k, _ in (
                        p.split("=", 1) if "=" in p else (p, "")
                        for p in query.split("&")
                    )
                )
                sig = f"{path}::{'&'.join(param_names)}"
                if sig not in seen_query_sigs:
                    seen_query_sigs.add(sig)
                    scores = build_ai_scores("sitemap_query_params", url)
                    meta   = scores.pop("_meta", {})
                    coros.append(reporter.report(
                        page_url   = url,
                        title      = "Sitemap URL Exposes Query Parameters",
                        category   = "information_disclosure",
                        confidence = "medium",
                        page_id    = page_id,
                        evidence   = {
                            "listed_url":  _snippet(loc),
                            "query":       _snippet(query),
                            "param_names": param_names,
                        },
                        raw_data   = {"loc": loc, "query": query, **meta},
                        cwe        = "CWE-200",
                        wasc       = "WASC-13",
                        reference  = (
                            "https://owasp.org/www-community/attacks"
                            "/Information_Leak_through_sitemaps"
                        ),
                        dedup_key  = (url, f"Sitemap Query Params::{sig}", "information_disclosure"),
                        **scores,
                    ))

        # ── Dispatch all coroutines in parallel ───────────────────────────
        if coros:
            await asyncio.gather(*coros)
            logger.info(f"[Sitemap] {len(coros)} finding(s) at {url}")

    except Exception as e:
        logger.error(
            f"[Sitemap] Error on {entry.get('url', '?')}: {e}",
            exc_info=True,
        )