import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urlparse, urljoin

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.external_links")

MAX_SNIPPET_LEN = 150

# ─────────────────────────────────────────────────────────────────────────────
# SUSPICIOUS DOMAINS
# ─────────────────────────────────────────────────────────────────────────────

SUSPICIOUS_DOMAINS: frozenset[str] = frozenset({
    "example-malicious.com",
    "evil-site.net",
    "phishing.com",
    "adf.ly",
    "bc.vc",
    "clk.sh",
    "shorte.st",
    "linkvertise.com",
    "ouo.io",
    "ouo.press",
    "exe.io",
    "cuty.io",
    "za.gl",
    "droplink.co",
    "fc.lc",
    "shrinke.me",
    "clk.asia",
    "short.am",
    "urlcash.net",
    "adshort.co",
    "clicksfly.com",
    "megaurl.in",
    "adbull.me",
    "tmearn.com",
    "viid.me",
    "linkspy.cc",
    "payurl.in",
    "adlinkfly.in",
    "adshortner.com",
    "shortearn.eu",
    "adflyearn.com",
    "urlgator.com",
    "urlshrt.in",
    "earnlink.io",
    "linkshrink.net",
    "short2url.in",
    "click2earn.me",
    "adslinkfly.online",
    "cashurl.win",
    "adpaylink.com",
    "urlshortx.com",
    "adsafelink.com",
    "linkrex.net",
    "shortzon.com",
    "adshort.im",
    "click2short.com",
    "urlspay.com",
    "adurl.pro",
    "shortlinker.in",
    "shortconnect.com",
    "link4earn.com",
    "adsrt.me",
    "shortifyme.com",
})

# ─────────────────────────────────────────────────────────────────────────────
# VALIDATION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _is_valid_url_like(text: str) -> bool:
    """
    Check if text looks like a URL/path, not arbitrary code/garbage.
    
    Rejects:
    - JavaScript expressions (init={}, var=123, function(){})
    - CSS properties (color: red, width: 100px)
    - Query params only (?foo=bar without path)
    - Code variables ($var, %var)
    - Empty or whitespace-only strings
    
    Accepts:
    - Absolute URLs (http://..., https://...)
    - Protocol-relative (//example.com)
    - Paths (/about, ./page, ../dir)
    - Domains (example.com)
    - URLs with query params (?id=1, example.com?foo=bar)
    """
    if not text or not text.strip():
        return False
    
    text = text.strip()
    
    # Reject pure query strings without a path
    if text.startswith('?') and '=' in text:
        return False
    
    # Reject JavaScript-like expressions
    if any(pat in text for pat in ['{}', 'function', 'var ', 'const ', 'let ', '()', '=>']):
        return False
    
    # Reject CSS-like declarations (color:, width:, etc.)
    if ':' in text and not text.startswith('http'):
        css_props = ['color', 'background', 'width', 'height', 'margin', 'padding', 'font', 'border']
        if any(prop in text.lower() for prop in css_props):
            return False
    
    # Reject email-like without http
    if '@' in text and not text.startswith('http'):
        return False
    
    # Reject strings with unbalanced brackets/braces
    if text.count('[') != text.count(']'):
        return False
    if text.count('{') != text.count('}'):
        return False
    if text.count('(') != text.count(')'):
        return False
    
    # Reject variable/placeholder patterns
    if any(var in text for var in ['$', '%', '${', '#{', '{{']):
        return False
    
    return True


def _safe_urljoin(base_url: str, raw_link: str) -> Optional[str]:
    """
    Safely join base URL with raw link.
    
    Returns full URL on success, None on failure.
    Catches ValueError from malformed URLs.
    """
    if not raw_link or not _is_valid_url_like(raw_link):
        return None
    
    try:
        full_url = urljoin(base_url, raw_link)
        return full_url
    except ValueError as e:
        # Malformed URL (e.g., 'init={}' with brackets in hostname)
        logger.debug(f"[ExternalLinks] Skipped malformed link '{raw_link}': {e}")
        return None
    except Exception as e:
        # Other unexpected errors
        logger.debug(f"[ExternalLinks] Unexpected error joining URLs: {e}")
        return None


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    return (text or "")[:MAX_SNIPPET_LEN]

def _page_host(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except Exception:
        return ""

def _is_external(link_host: str, page_host: str) -> bool:
    """
    True only if link_host is non-empty and differs from the scanned page's
    host.  Filters out same-domain, relative, and pseudo-links (data:, js:).
    """
    if not link_host or not page_host:
        return False
    return link_host.lower() != page_host.lower()

def _is_suspicious(host: str) -> bool:
    return host.lower() in SUSPICIOUS_DOMAINS

def _has_url_in_query(query: str) -> bool:
    """Detect embedded URL values in a query string — open-redirect signal."""
    q = query.lower()
    return "http://" in q or "https://" in q


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_external_links(
    entry:   dict,
    reporter,
    page_id: Optional[int] = None,
    _seen:   Optional[set] = None,
) -> None:
    """
    Scan a rendered HTML body for external links that indicate:
      1. Links to known suspicious / ad-shortener domains.
      2. Query parameters containing embedded URLs (open-redirect candidates).

    Parameters
    ──────────
    entry    — one "http"-type event.  Keys: url, body, status_code.
    reporter — Reporter instance.
    page_id  — pages.id FK forwarded to reporter.
    _seen    — per-scan dedup set (caller-owned).  Pass the same set for all
               events in a scan session so the same suspicious domain on two
               different pages does not create duplicate findings.

    Dedup strategy
    ──────────────
    Both checks are PAGE-level:
      A suspicious domain link on /home and a different link on /contact are
      distinct findings — different pages, potentially different malicious
      content.  However, if the same suspicious domain appears multiple times
      on the SAME page, only one finding is created (per-page inner set).

    _seen key: (page_url, title_slug) — one row per (page, suspicious_domain)
    and one row per (page, redirect_host) regardless of how many href/src
    attributes point to the same destination.

    All report coroutines are collected per-link and flushed with
    asyncio.gather at the end for concurrent DB writes.
    """
    if _seen is None:
        _seen = set()

    try:
        url         = entry.get("url", "")
        body        = entry.get("body") or ""
        status_code = entry.get("status_code")

        if not url or not body or status_code != 200:
            return

        page_host = _page_host(url)
        if not page_host:
            return

        # Extract links from href and src attributes
        raw_links = re.findall(r"""(?:href|src)=['"]([^'"]+)['"]""", body, re.I)
        if not raw_links:
            return

        tasks: list = []

        for raw_link in raw_links:
            # ── CRITICAL FIX: Validate raw_link before urljoin ─────────────
            # This prevents ValueError on malformed links like "init={}"
            if not _is_valid_url_like(raw_link):
                logger.debug(f"[ExternalLinks] Skipped invalid link pattern: {raw_link[:50]}")
                continue

            # ── Safe join with error handling ────────────────────────────
            full_url = _safe_urljoin(url, raw_link)
            if not full_url:
                # Already logged in _safe_urljoin
                continue

            try:
                parsed = urlparse(full_url)
                link_host = (parsed.hostname or "").lower()
                query = parsed.query
            except Exception as e:
                logger.debug(f"[ExternalLinks] Failed to parse URL {full_url}: {e}")
                continue

            if not _is_external(link_host, page_host):
                continue

            # ── 1. Suspicious / ad-shortener domain ───────────────────────
            # Page-level: dedup key includes page url + link_host so:
            #   - same suspicious domain on same page → one finding (inner set)
            #   - same suspicious domain on different page → separate findings
            if _is_suspicious(link_host):
                seen_key = (url, f"suspicious::{link_host}")
                if seen_key not in _seen:
                    _seen.add(seen_key)

                    async def _suspicious(link_host=link_host, full_url=full_url, raw_link=raw_link):
                        try:
                            scores = build_ai_scores("suspicious_external_link", url)
                            meta   = scores.pop("_meta", {})
                            await reporter.report(
                                page_url=url,
                                title="Link to Suspicious / Ad-Shortener Domain",
                                category="information_disclosure",
                                confidence="medium",
                                page_id=page_id,
                                evidence={
                                    "suspicious_domain": link_host,
                                    "full_link":         _snippet(full_url),
                                },
                                raw_data={"raw_link": raw_link, "full_url": full_url, **meta},
                                cwe="CWE-601",
                                wasc="WASC-38",
                                reference="https://cwe.mitre.org/data/definitions/601.html",
                                dedup_key=(url, f"Link to Suspicious Domain::{link_host}", "information_disclosure"),
                            )
                            logger.info(f"[ExternalLinks] Suspicious domain link on {url}: {link_host}")
                        except Exception as e:
                            logger.error(f"[ExternalLinks] Failed to report suspicious link: {e}")

                    tasks.append(_suspicious())

            # ── 2. Open-redirect candidate in query string ─────────────────
            # Page-level: each distinct redirect target on each page is its
            # own finding.  _seen key: (page_url, redirect::link_host).
            if _has_url_in_query(query):
                seen_key = (url, f"redirect::{link_host}")
                if seen_key not in _seen:
                    _seen.add(seen_key)

                    async def _redirect(link_host=link_host, full_url=full_url, raw_link=raw_link, query=query):
                        try:
                            scores = build_ai_scores("open_redirect", url)
                            meta   = scores.pop("_meta", {})
                            await reporter.report(
                                page_url=url,
                                title="Potential Open Redirect Parameter",
                                category="access_control",
                                confidence="medium",
                                page_id=page_id,
                                evidence={
                                    "full_link":    _snippet(full_url),
                                    "query_string": _snippet(query),
                                    "target_host":  link_host,
                                },
                                raw_data={"raw_link": raw_link, "full_url": full_url, **meta},
                                cwe="CWE-601",
                                wasc="WASC-38",
                                reference=(
                                    "https://cheatsheetseries.owasp.org/cheatsheets"
                                    "/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html"
                                ),
                                dedup_key=(url, f"Potential Open Redirect::{link_host}", "access_control"),
                            )
                            logger.info(f"[ExternalLinks] Redirect param on {url} → {link_host}")
                        except Exception as e:
                            logger.error(f"[ExternalLinks] Failed to report redirect: {e}")

                    tasks.append(_redirect())

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"[ExternalLinks] Report task failed: {r}", exc_info=False)

    except Exception as e:
        logger.error(
            f"[ExternalLinks] Error analyzing {entry.get('url', '?')}: {e}",
            exc_info=True,
        )