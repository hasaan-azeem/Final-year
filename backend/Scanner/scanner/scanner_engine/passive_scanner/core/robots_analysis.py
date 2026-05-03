import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse, urljoin

from ..scoring import build_ai_scores, get_path_tier_name

logger = logging.getLogger("webxguard.robots")

MAX_SNIPPET_LEN = 100

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    return (text or "")[:MAX_SNIPPET_LEN]


def _is_sensitive(path: str) -> bool:
    """
    Delegate to scoring.py path-tier using a synthetic URL so the full
    tier table is evaluated rather than a local duplicate path list.
    """
    return get_path_tier_name(f"https://x{path}") in ("critical", "high", "elevated")


def _parse_robots(body: str) -> tuple[list, list, list]:
    """
    Parse a robots.txt body into (disallow_paths, allow_paths, sitemap_urls).
    Strips comments, blank lines, and User-agent directives.
    """
    disallow: list = []
    allow:    list = []
    sitemaps: list = []

    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("disallow:"):
            disallow.append(line.split(":", 1)[1].strip())
        elif lower.startswith("allow:"):
            allow.append(line.split(":", 1)[1].strip())
        elif lower.startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())

    return disallow, allow, sitemaps


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_robots(
    entry:   dict,
    reporter,
    page_id: Optional[int] = None,
) -> None:
    """
    Parse a robots.txt response and report path-disclosure and
    misconfiguration findings.

    Finding strategy
    ────────────────
    1. One summary finding for all disallow paths (prevents flooding).
    2. Individual findings for each sensitive disallow path.
    3. Individual findings for allow directives on sensitive paths.
    4. One finding if all-blocking (Disallow: /) or empty disallow present.
    5. Individual findings for wildcard / regex-like disallow patterns.
    6. Individual findings for each Sitemap URL.

    REPORTING GRANULARITY:
    ──────────────────────
    robots.txt is fetched once per domain, so findings are per robots.txt
    URL. No cross-call _seen needed — the reporter dedup_key handles it if
    the same URL is somehow processed twice.

    PERFORMANCE: coroutines collected synchronously then dispatched with
    asyncio.gather() so reporter I/O runs concurrently.
    """
    try:
        url         = entry.get("url", "")
        body        = entry.get("body") or ""
        status_code = entry.get("status_code")

        if not url or not body or status_code != 200:
            return

        if not urlparse(url).path.rstrip("/").lower().endswith("robots.txt"):
            return

        parsed_url = urlparse(url)
        base_url   = f"{parsed_url.scheme}://{parsed_url.netloc}"

        disallow_paths, allow_paths, sitemap_urls = _parse_robots(body)

        coros: list = []

        # ── 1. Disallow summary ───────────────────────────────────────────
        # One finding per robots.txt that collects ALL disallow paths.
        if disallow_paths:
            sensitive_disallows = [p for p in disallow_paths if _is_sensitive(p)]
            scores = build_ai_scores("sensitive_file_unexpected", url)
            meta   = scores.pop("_meta", {})
            coros.append(reporter.report(
                page_url   = url,
                title      = "robots.txt Discloses Disallow Directives",
                category   = "information_disclosure",
                confidence = "high" if sensitive_disallows else "medium",
                page_id    = page_id,
                evidence   = {
                    "disallow_count":     len(disallow_paths),
                    "sensitive_paths":    sensitive_disallows,
                    "all_disallow_paths": disallow_paths[:50],
                },
                raw_data   = {"disallow_paths": disallow_paths, **meta},
                cwe        = "CWE-200",
                wasc       = "WASC-13",
                reference  = (
                    "https://owasp.org/www-project-web-security-testing-guide"
                    "/latest/4-Web_Application_Security_Testing"
                    "/01-Information_Gathering/01-Conduct_Search_Engine_Discovery"
                ),
                dedup_key  = (url, "robots.txt Discloses Disallow Directives", "information_disclosure"),
                **scores,
            ))

        # ── 2. Individual sensitive disallow paths ────────────────────────
        seen_disallow: set = set()
        for path in disallow_paths:
            if path in seen_disallow or not _is_sensitive(path):
                continue
            seen_disallow.add(path)
            full_path = urljoin(base_url, path)
            scores    = build_ai_scores("robots_sensitive_disallow", url)
            meta      = scores.pop("_meta", {})
            coros.append(reporter.report(
                page_url   = url,
                title      = "robots.txt Discloses Sensitive Path",
                category   = "information_disclosure",
                confidence = "high",
                page_id    = page_id,
                evidence   = {
                    "disallow_path": _snippet(path),
                    "full_url":      _snippet(full_path),
                },
                raw_data   = {"path": path, "full_url": full_path, **meta},
                cwe        = "CWE-200",
                wasc       = "WASC-13",
                reference  = (
                    "https://owasp.org/www-project-web-security-testing-guide"
                    "/latest/4-Web_Application_Security_Testing"
                    "/01-Information_Gathering/01-Conduct_Search_Engine_Discovery"
                ),
                dedup_key  = (url, f"robots.txt Sensitive Disallow::{path}", "information_disclosure"),
                **scores,
            ))

        # ── 3. Allow directives exposing sensitive paths ──────────────────
        seen_allow: set = set()
        for path in allow_paths:
            if path in seen_allow or not _is_sensitive(path):
                continue
            seen_allow.add(path)
            full_path = urljoin(base_url, path)
            scores    = build_ai_scores("sensitive_file_exposed", url)
            meta      = scores.pop("_meta", {})
            coros.append(reporter.report(
                page_url   = url,
                title      = "robots.txt Allow Directive Exposes Sensitive Path",
                category   = "information_disclosure",
                confidence = "high",
                page_id    = page_id,
                evidence   = {
                    "allow_path": _snippet(path),
                    "full_url":   _snippet(full_path),
                },
                raw_data   = {"path": path, "full_url": full_path, **meta},
                cwe        = "CWE-200",
                wasc       = "WASC-13",
                reference  = (
                    "https://owasp.org/www-project-web-security-testing-guide"
                    "/latest/4-Web_Application_Security_Testing"
                    "/01-Information_Gathering/01-Conduct_Search_Engine_Discovery"
                ),
                dedup_key  = (url, f"robots.txt Allow Sensitive::{path}", "information_disclosure"),
                **scores,
            ))

        # ── 4. All-blocking or empty Disallow ─────────────────────────────
        # One finding per robots.txt regardless of how many such lines exist.
        for path in disallow_paths:
            if path not in ("", "/"):
                continue
            label  = "all pages" if path == "/" else "empty (no-op)"
            scores = build_ai_scores("sensitive_file_unexpected", url)
            meta   = scores.pop("_meta", {})
            coros.append(reporter.report(
                page_url   = url,
                title      = "robots.txt Contains All-Blocking or Empty Disallow",
                category   = "information_disclosure",
                confidence = "medium",
                page_id    = page_id,
                evidence   = {"disallow_path": _snippet(path), "label": label},
                raw_data   = {"path": path, **meta},
                cwe        = "CWE-200",
                wasc       = "WASC-13",
                reference  = (
                    "https://owasp.org/www-project-web-security-testing-guide"
                    "/latest/4-Web_Application_Security_Testing"
                    "/01-Information_Gathering/01-Conduct_Search_Engine_Discovery"
                ),
                dedup_key  = (url, "robots.txt All-Blocking Disallow", "information_disclosure"),
                **scores,
            ))
            break  # one finding regardless of how many such lines exist

        # ── 5. Wildcard / patterned disallow directives ───────────────────
        seen_wildcards: set = set()
        for pattern in disallow_paths:
            if ("*" not in pattern and "?" not in pattern) or pattern in seen_wildcards:
                continue
            seen_wildcards.add(pattern)
            scores = build_ai_scores("sensitive_file_unexpected", url)
            meta   = scores.pop("_meta", {})
            coros.append(reporter.report(
                page_url   = url,
                title      = "robots.txt Contains Wildcard Disallow Pattern",
                category   = "information_disclosure",
                confidence = "medium",
                page_id    = page_id,
                evidence   = {"pattern": _snippet(pattern)},
                raw_data   = {"pattern": pattern, **meta},
                cwe        = "CWE-200",
                wasc       = "WASC-13",
                reference  = (
                    "https://owasp.org/www-project-web-security-testing-guide"
                    "/latest/4-Web_Application_Security_Testing"
                    "/01-Information_Gathering/01-Conduct_Search_Engine_Discovery"
                ),
                dedup_key  = (url, f"robots.txt Wildcard::{pattern}", "information_disclosure"),
                **scores,
            ))

        # ── 6. Sitemap URLs ───────────────────────────────────────────────
        # BUG FIX: original code wrote `sensitive = _is_sensitive(sitemap_path)`
        # which silently mutated the outer `sensitive` variable, corrupting
        # any logic that depended on it later in the function.
        # Fix: use a local `sitemap_sensitive` name throughout this loop.
        seen_sitemaps: set = set()
        for sitemap_url in sitemap_urls:
            if sitemap_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sitemap_url)
            try:
                sitemap_path      = urlparse(sitemap_url).path
                sitemap_sensitive = _is_sensitive(sitemap_path)   # ← local name, not outer
                scores            = build_ai_scores("robots_sitemap_exposed", url)
                meta              = scores.pop("_meta", {})
                coros.append(reporter.report(
                    page_url   = url,
                    title      = "robots.txt Discloses Sitemap URL",
                    category   = "information_disclosure",
                    confidence = "high" if sitemap_sensitive else "medium",
                    page_id    = page_id,
                    evidence   = {
                        "sitemap_url":    _snippet(sitemap_url),
                        "sensitive_path": sitemap_sensitive,
                    },
                    raw_data   = {"sitemap_url": sitemap_url, **meta},
                    cwe        = "CWE-200",
                    wasc       = "WASC-13",
                    reference  = (
                        "https://owasp.org/www-project-web-security-testing-guide"
                        "/latest/4-Web_Application_Security_Testing"
                        "/01-Information_Gathering/01-Conduct_Search_Engine_Discovery"
                    ),
                    dedup_key  = (url, f"robots.txt Sitemap::{sitemap_url}", "information_disclosure"),
                    **scores,
                ))
            except Exception:
                continue

        # ── Dispatch all coroutines in parallel ───────────────────────────
        if coros:
            await asyncio.gather(*coros)
            logger.info(f"[Robots] {len(coros)} finding(s) for {url}")

    except Exception as e:
        logger.error(
            f"[Robots] Error on {entry.get('url', '?')}: {e}",
            exc_info=True,
        )