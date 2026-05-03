import logging
from urllib.parse import urlparse
from functools import lru_cache

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.cache")

MAX_SNIPPET_LEN = 100
MAX_BODY_SIZE = 1_000_000
MAX_CACHE_CONTROL_LEN = 8192

SENSITIVE_ENDPOINTS_SET = frozenset({
    "/admin", "/dashboard", "/internal", "/config", "/backup",
})

CACHEABLE_STATUS_CODES = frozenset({200, 203, 204, 206, 300, 301, 404, 410})


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

def _trunc(text: str, length: int = MAX_SNIPPET_LEN) -> str:
    """Truncate text safely."""
    return text[:length] if text else ""

@lru_cache(maxsize=512)
def _normalize_path(path: str) -> str:
    """Normalize and cache path."""
    return path.rstrip("/").lower()

def _is_sensitive_path(path: str) -> bool:
    """Check if path is sensitive using set lookup."""
    norm_path = _normalize_path(path)
    return (norm_path in SENSITIVE_ENDPOINTS_SET or
            any(norm_path.startswith(ep.rstrip("/") + "/") 
                for ep in SENSITIVE_ENDPOINTS_SET))

def _domain(url: str) -> str:
    """Extract and cache domain."""
    try:
        return urlparse(url).netloc
    except Exception:
        return ""

def _safe_int(value: str, default: int = 0) -> int:
    """Safely convert string to int."""
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return default

def _parse_cache_control(cache_control: str) -> dict:
    """Parse Cache-Control header once, return directives."""
    if not cache_control:
        return {}
    
    directives = {}
    for part in cache_control.split(","):
        part = part.strip().lower()
        if "=" in part:
            k, v = part.split("=", 1)
            directives[k.strip()] = v.strip()
        else:
            directives[part] = True
    return directives


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_cache(
    event: dict,
    reporter,
    page_id=None,
    endpoint_id=None,
    _seen: set = None
):
    """
    Detect cache misconfiguration on sensitive endpoints.

    Optimized: Pre-parse cache headers, use set for status codes,
    only process text content.
    """
    if _seen is None:
        _seen = set()

    # ──── INPUT VALIDATION ────
    url = event.get("url")
    if not url or not isinstance(url, str) or len(url) > 8192:
        return

    method = event.get("method", "GET").upper()
    status_code = event.get("status_code")

    if method != "GET" or not isinstance(status_code, int):
        return
    if status_code not in CACHEABLE_STATUS_CODES:
        return

    try:
        parsed = urlparse(url)
    except Exception:
        return

    path = _normalize_path(parsed.path)
    if not path or not _is_sensitive_path(path):
        return

    # ──── SAFE HEADER EXTRACTION ────
    headers_raw = event.get("headers")
    if not isinstance(headers_raw, dict):
        headers_raw = {}

    headers = {
        k.lower()[:64]: _trunc(str(v), MAX_CACHE_CONTROL_LEN)
        for k, v in headers_raw.items()
    }

    # ──── PARSE CACHE CONTROL ONCE ────
    cache_control = headers.get("cache-control", "")
    cc_parsed = _parse_cache_control(cache_control)

    # Extract specific directives (computed once)
    explicitly_public = "public" in cc_parsed
    private_cache = "private" in cc_parsed
    no_store = "no-store" in cc_parsed
    no_cache = "no-cache" in cc_parsed
    max_age_present = "max-age" in cc_parsed
    s_maxage_present = "s-maxage" in cc_parsed
    immutable_present = "immutable" in cc_parsed

    pragma = headers.get("pragma", "")
    vary = headers.get("vary", "")
    set_cookie = headers.get("set-cookie", "")
    age = headers.get("age", "")
    etag = headers.get("etag", "")
    surrogate_control = headers.get("surrogate-control", "")
    x_cache = headers.get("x-cache", "")
    x_cache_hits = headers.get("x-cache-hits", "")
    cf_cache_status = headers.get("cf-cache-status", "")
    cdn_cache_control = headers.get("cdn-cache-control", "")

    t_path = _trunc(path)
    t_cc = _trunc(cache_control)
    t_vary = _trunc(vary)

    async def _report(
        title, profile_key, confidence,
        evidence, raw_data=None
    ):
        """Report with deduplication."""
        seen_key = (url, title)
        if seen_key in _seen:
            return
        _seen.add(seen_key)

        try:
            scores = build_ai_scores(profile_key, url)
            meta = scores.pop("_meta", {})

            await reporter.report(
                page_url=url,
                title=title,
                category="cache",
                confidence=confidence,
                evidence=evidence,
                raw_data={**(raw_data or {}), **meta},
                cwe="CWE-525",
                wasc="WASC-13",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
                page_id=page_id,
                endpoint_id=endpoint_id,
                **scores,
            )
        except Exception as e:
            logger.error(f"Report failed for {url}: {_trunc(str(e))}")

    try:
        # ── 1. Missing Cache-Control ──────────────────────────────────────────
        if not cache_control:
            await _report(
                title="Cache-Control Header Missing on Sensitive Page",
                profile_key="cache_control_missing",
                confidence="medium",
                evidence={"path": t_path},
            )

        # ── 2. Explicit public cache on sensitive page ────────────────────────
        if explicitly_public and not no_store:
            has_cookie = bool(set_cookie)
            title = "Sensitive Response Explicitly Publicly Cacheable" + (" (Sets Cookie)" if has_cookie else "")
            await _report(
                title=title,
                profile_key="cache_explicitly_public",
                confidence="high" if has_cookie else "medium",
                evidence={"path": t_path, "cache_control": t_cc},
                raw_data={"sets_cookie": has_cookie},
            )

        # ── 3. Missing private / no-store ─────────────────────────────────────
        if not private_cache and not no_store:
            await _report(
                title="Sensitive Response Missing Private/No-Store Directive",
                profile_key="cache_missing_private_nostore",
                confidence="medium",
                evidence={"cache_control": t_cc or "absent", "path": t_path},
            )

        # ── 4. max-age on sensitive page ──────────────────────────────────────
        if max_age_present and not no_store:
            await _report(
                title="Sensitive Page Cached Using max-age Directive",
                profile_key="cache_max_age_sensitive",
                confidence="medium",
                evidence={"cache_control": t_cc, "path": t_path},
            )

        # ── 5. Vary: * on publicly cacheable response ─────────────────────────
        if "*" in vary and explicitly_public:
            await _report(
                title="Vary Header Contains Wildcard (*) on Publicly Cacheable Response",
                profile_key="cache_vary_wildcard",
                confidence="medium",
                evidence={"vary": t_vary, "path": t_path},
                raw_data={"cwe": "CWE-524", "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Vary"},
            )

        # ── 6. Set-Cookie on cacheable response ───────────────────────────────
        if set_cookie and explicitly_public:
            await _report(
                title="Cacheable Response Sets Cookie",
                profile_key="cache_cookie_on_cacheable",
                confidence="medium",
                evidence={"cache_control": t_cc, "path": t_path},
            )

        # ── 7. Legacy Pragma without proper Cache-Control ─────────────────────
        if not cache_control and pragma and "no-cache" not in pragma.lower():
            await _report(
                title="Legacy Pragma Header Used Without Proper Cache-Control",
                profile_key="cache_legacy_pragma",
                confidence="low",
                evidence={"pragma": _trunc(pragma), "path": t_path},
                raw_data={"reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma"},
            )

        # ── 8. Age header — served from cache ────────────────────────────────
        age_int = _safe_int(age)
        if age_int > 0:
            await _report(
                title="Sensitive Response Served From Cache",
                profile_key="cache_served_from_cache",
                confidence="medium",
                evidence={"age": _trunc(age), "path": t_path},
            )

        # ── 9. ETag on sensitive response ─────────────────────────────────────
        if etag and not no_store:
            await _report(
                title="ETag Header Present on Sensitive Response",
                profile_key="cache_etag_sensitive",
                confidence="low",
                evidence={"etag": _trunc(etag), "path": t_path},
                raw_data={"cwe": "CWE-524"},
            )

        # ── 10. s-maxage (shared / CDN cache) ────────────────────────────────
        if s_maxage_present and not no_store:
            await _report(
                title="Sensitive Response Cached by Shared/CDN Cache via s-maxage",
                profile_key="cache_s_maxage_sensitive",
                confidence="high",
                evidence={"cache_control": t_cc, "path": t_path},
                raw_data={"reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#s-maxage"},
            )

        # ── 11. Surrogate-Control max-age ─────────────────────────────────────
        if surrogate_control and "max-age" in surrogate_control.lower():
            await _report(
                title="Sensitive Response Cached via Surrogate-Control Header",
                profile_key="cache_surrogate_control",
                confidence="medium",
                evidence={"surrogate_control": _trunc(surrogate_control), "path": t_path},
                raw_data={"reference": "https://www.w3.org/TR/edge-arch/"},
            )

        # ── 12. CDN / proxy cache HIT ─────────────────────────────────────────
        cdn_hit = (
            "hit" in x_cache.lower() or
            "hit" in x_cache_hits.lower() or
            cf_cache_status.upper() in {"HIT", "REVALIDATED", "UPDATING"} or
            "hit" in cdn_cache_control.lower()
        )
        if cdn_hit:
            await _report(
                title="Sensitive Response Delivered as CDN/Proxy Cache HIT",
                profile_key="cache_cdn_hit_sensitive",
                confidence="high",
                evidence={
                    "x_cache": _trunc(x_cache),
                    "cf_cache_status": _trunc(cf_cache_status),
                    "path": t_path
                },
                raw_data={"reference": "https://portswigger.net/web-security/web-cache-poisoning"},
            )

        # ── 13. immutable on sensitive response ───────────────────────────────
        if immutable_present:
            await _report(
                title="Sensitive Response Marked as Immutable in Cache",
                profile_key="cache_immutable_sensitive",
                confidence="medium",
                evidence={"cache_control": t_cc, "path": t_path},
                raw_data={"reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control#immutable"},
            )

        # ── 14. no-cache without no-store ─────────────────────────────────────
        if no_cache and not no_store:
            await _report(
                title="Sensitive Response Uses no-cache Without no-store (Response Still Stored)",
                profile_key="cache_no_cache_without_nostore",
                confidence="low",
                evidence={"cache_control": t_cc, "path": t_path},
            )

    except Exception as e:
        logger.error(f"[Cache] Failed on {url}: {_trunc(str(e))}")