import asyncio
import re
import logging
from typing import Optional
from urllib.parse import urlparse

from ..scoring import build_ai_scores, get_path_tier_name

logger = logging.getLogger("webxguard.mixed_content")

MAX_SNIPPET_LEN = 100
MAX_BODY_SCAN   = 500_000   # 500 KB
MAX_MATCHES     = 30        # per-pattern cap

# ─────────────────────────────────────────────────────────────────────────────
# PRECOMPILED PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

# Active resources — script execution / navigation / XHR context
ACTIVE_RE = re.compile(
    r"""
    (?:
        src\s*=\s*       # <script src=, <iframe src=, <embed src=
      | action\s*=\s*    # <form action=
      | import\s+        # ES module import
      | fetch\s*\(       # fetch() API
      | XMLHttpRequest   # XHR
    )
    ["']?(http://[^"'\s>)]+)["']?
    """,
    re.I | re.X,
)

# Passive resources — images / stylesheets / fonts / lazy-load
PASSIVE_RE = re.compile(
    r"""
    (?:
        href\s*=\s*                        # <link href=
      | data-src\s*=\s*                    # lazy-load images
      | url\s*\(                           # CSS url()
      | @import\s+["']                     # CSS @import
      | background-image\s*:\s*url
    )
    ["']?(http://[^"'\s>)]+)["']?
    """,
    re.I | re.X,
)

WS_RE            = re.compile(r"\b(ws://[^\s\"'<>]+)\b", re.I)
EVENTSOURCE_RE   = re.compile(r"new\s+EventSource\s*\(\s*['\"]?(http://[^'\")]+)['\"]?\)", re.I)
SERVICEWORKER_RE = re.compile(r"navigator\.serviceWorker\.register\s*\(\s*['\"]?(http://[^'\")]+)['\"]?", re.I)
MEDIA_RE         = re.compile(r"<(?:video|audio|source)[^>]+src=['\"](http://[^'\"]+)['\"]", re.I)
FONT_RE          = re.compile(r"@font-face\s*{[^}]*src:\s*url\(['\"]?(http://[^'\)]+)['\"]?\)", re.I)
DYNAMIC_HTML_RE  = re.compile(r"(document\.write|innerHTML)\s*.*http://", re.I)

# ─────────────────────────────────────────────────────────────────────────────
# SAFE DOMAINS — skip well-known CDNs to reduce noise
# ─────────────────────────────────────────────────────────────────────────────

_SAFE_DOMAINS: frozenset = frozenset({
    "google-analytics.com",
    "googletagmanager.com",
    "cdnjs.cloudflare.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
})


def _is_safe(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return any(host == d or host.endswith(f".{d}") for d in _SAFE_DOMAINS)
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    return (text or "")[:MAX_SNIPPET_LEN]


def _is_sensitive(url: str) -> bool:
    return get_path_tier_name(url) in ("critical", "high", "elevated")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_mixed_content(
    entry:   dict,
    reporter,
    page_id: Optional[int] = None,
) -> None:
    """
    Detect HTTP sub-resources loaded on HTTPS pages and report them as
    mixed-content findings with appropriate severity tiers.

    REPORTING GRANULARITY:
    ──────────────────────
    Mixed content is per-page-URL (not domain-level) because two pages on
    the same domain can load completely different sub-resources.  Each
    unique (page_url, resource_url) pair produces one finding.

    PERFORMANCE: all coroutines collected synchronously then dispatched
    with asyncio.gather() so reporter I/O runs concurrently.

    Finding tiers
    ─────────────
    Active   (scripts, iframes, XHR, fetch, form actions)
             → profile: mixed_content_active
    Passive  (images, CSS, lazy-load)
             → profile: mixed_content
    Transport (WebSocket ws://, EventSource, ServiceWorker)
             → profile: http_no_https
    Media    (video/audio/source)
             → profile: mixed_content
    Font     (@font-face HTTP)
             → profile: mixed_content
    Dynamic  (innerHTML/document.write with HTTP URL)
             → profile: mixed_content_active  (injection risk)
    """
    try:
        url         = entry.get("url", "")
        status_code = entry.get("status_code")
        body        = entry.get("body") or ""

        if not url or not url.lower().startswith("https://"):
            return
        if status_code != 200:
            return
        if not body.strip():
            return

        body      = body[:MAX_BODY_SCAN]
        sensitive = _is_sensitive(url)

        # Global dedup across all patterns in this event
        seen: set = set()
        coros     = []

        def _make_coro(resource_url, title, profile, cwe, confidence):
            scores = build_ai_scores(profile, url)
            meta   = scores.pop("_meta", {})
            return reporter.report(
                page_url   = url,
                title      = title,
                category   = "mixed_content",
                confidence = confidence,
                page_id    = page_id,
                evidence   = {
                    "resource_url":   _snippet(resource_url),
                    "sensitive_page": sensitive,
                },
                raw_data   = {"resource_url": resource_url, **meta},
                cwe        = cwe,
                wasc       = "WASC-15",
                reference  = "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
                dedup_key  = (url, f"{title}::{resource_url}", "mixed_content"),
                **scores,
            )

        # ── 1. Active mixed content ───────────────────────────────────────
        count = 0
        for resource_url in ACTIVE_RE.findall(body):
            resource_url = resource_url.strip()
            if not resource_url.startswith("http://"):
                continue
            if resource_url in seen or _is_safe(resource_url):
                continue
            seen.add(resource_url)
            count += 1
            if count > MAX_MATCHES:
                break
            coros.append(_make_coro(
                resource_url = resource_url,
                title        = "Active Mixed Content: HTTP Resource on HTTPS Page",
                profile      = "mixed_content_active",
                cwe          = "CWE-319",
                confidence   = "high",
            ))

        # ── 2. Passive mixed content ──────────────────────────────────────
        count = 0
        for resource_url in PASSIVE_RE.findall(body):
            resource_url = resource_url.strip()
            if not resource_url.startswith("http://"):
                continue
            if resource_url in seen or _is_safe(resource_url):
                continue
            seen.add(resource_url)
            count += 1
            if count > MAX_MATCHES:
                break
            coros.append(_make_coro(
                resource_url = resource_url,
                title        = "Passive Mixed Content: HTTP Resource on HTTPS Page",
                profile      = "mixed_content",
                cwe          = "CWE-319",
                confidence   = "high" if sensitive else "medium",
            ))

        # ── 3. Specialist patterns ────────────────────────────────────────
        # (pattern, title, profile, cwe, default_confidence)
        _SPECIALIST: list[tuple] = [
            (WS_RE,            "Insecure WebSocket (ws://) on HTTPS Page",             "http_no_https",       "CWE-326", "high"),
            (EVENTSOURCE_RE,   "Insecure Server-Sent Events (HTTP EventSource)",        "http_no_https",       "CWE-326", "high"),
            (SERVICEWORKER_RE, "ServiceWorker Registered via HTTP on HTTPS Page",       "http_no_https",       "CWE-319", "high"),
            (MEDIA_RE,         "Insecure Media Source (HTTP) on HTTPS Page",            "mixed_content",       "CWE-319", "medium"),
            (FONT_RE,          "Insecure Web Font (HTTP) on HTTPS Page",                "mixed_content",       "CWE-319", "medium"),
            (DYNAMIC_HTML_RE,  "Dynamic HTML Injection with HTTP URL",                  "mixed_content_active","CWE-319", "high"),
        ]

        for pattern, title, profile, cwe, default_conf in _SPECIALIST:
            count = 0
            for match in pattern.findall(body):
                resource_url = (match.strip() if isinstance(match, str) else match[0].strip())
                if resource_url in seen or _is_safe(resource_url):
                    continue
                seen.add(resource_url)
                count += 1
                if count > MAX_MATCHES:
                    break
                confidence = "high" if (sensitive and default_conf == "medium") else default_conf
                coros.append(_make_coro(resource_url, title, profile, cwe, confidence))

        # ── Dispatch all coroutines in parallel ───────────────────────────
        if coros:
            await asyncio.gather(*coros)
            logger.info(f"[MixedContent] {len(coros)} finding(s) on {url}")

    except Exception as e:
        logger.error(
            f"[MixedContent] Error on {entry.get('url', '?')}: {e}",
            exc_info=True,
        )