import asyncio
import re
import logging
from urllib.parse import urlparse
from typing import Optional

from ..scoring import build_ai_scores, cvss_to_severity_band

logger = logging.getLogger("webxguard.headers")

MAX_SNIPPET_LEN = 150

# ─────────────────────────────────────────────────────────────────────────────
# PRECOMPILED PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

HSTS_MAX_AGE_RE = re.compile(r"max-age=(\d+)", re.I)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _truncate(text: str) -> str:
    return text[:MAX_SNIPPET_LEN] if text else ""

def _domain_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _boost_confidence(base: str, sensitive: bool) -> str:
    return "high" if sensitive and base == "medium" else base

_SENSITIVE_PREFIXES = (
    "/admin", "/dashboard", "/login", "/account",
    "/payment", "/checkout", "/api", "/profile",
)

def _is_sensitive_path(path: str) -> bool:
    lp = path.lower()
    return any(lp.startswith(p) for p in _SENSITIVE_PREFIXES)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_headers(
    event:       dict,
    reporter,
    page_id:     Optional[int] = None,
    endpoint_id: Optional[int] = None,
    _seen:       Optional[set] = None,
) -> None:
    """
    Analyze security response headers from a single flat fetcher HTTP event.

    DEDUP — domain-level (Option B):
    ─────────────────────────────────
    Header misconfigs are server-wide, not per-page.
      • First hit on a (domain, title) pair →
            reporter.report(page_url=domain_root,
                            evidence={..., "affected_pages": [url]})
      • Subsequent hit →
            reporter.append_evidence_page(domain_root, title, url)

    Pass the SAME _seen set for every event in a scan session so
    cross-page dedup works correctly.

    PERFORMANCE — parallel reporting:
    ───────────────────────────────────
    All findings discovered in a single event are gathered into one
    asyncio.gather() call so reporter I/O runs concurrently.
    The _seen set is updated synchronously before any awaits, so there
    is no race between the first-hit check and the mark.
    """
    if _seen is None:
        _seen = set()

    try:
        url         = event.get("url")
        raw_headers = event.get("headers", {})
        status_code = event.get("status_code")

        if not url or not isinstance(raw_headers, dict) or status_code is None:
            return

        parsed      = urlparse(url)
        path        = parsed.path.lower() or "/"
        sensitive   = _is_sensitive_path(path)
        is_https    = parsed.scheme == "https"
        domain_root = _domain_root(url)

        headers = {k.lower(): str(v) for k, v in raw_headers.items()}

        # ── Dedup helpers  (synchronous — no races) ───────────────────────

        def _first_hit(title: str) -> bool:
            return (domain_root, title) not in _seen

        def _mark(title: str):
            _seen.add((domain_root, title))

        # ── Coroutine builders  (do NOT await here) ───────────────────────

        def _make_report_coro(
            title:       str,
            confidence:  str,
            profile_key: str,
            evidence:    dict,
            cwe:         str,
            wasc:        str,
            ref:         str,
        ):
            """
            Returns either a full-insert coroutine (first hit) or an
            append coroutine (subsequent hit).

            _mark() is called synchronously so the seen-set is up to date
            before any I/O is awaited.
            """
            if _first_hit(title):
                _mark(title)
                scores = build_ai_scores(profile_key, url)
                meta   = scores.pop("_meta", {})
                return reporter.report(
                    page_url    = domain_root,
                    title       = title,
                    category    = "security_headers",
                    confidence  = confidence,
                    page_id     = page_id,
                    endpoint_id = endpoint_id,
                    evidence    = {
                        **evidence,
                        "affected_pages": [url],
                        "cvss_band":      cvss_to_severity_band(scores.get("cvss_score")),
                    },
                    raw_data    = {
                        "url":          url,
                        "status_code":  status_code,
                        "scheme":       parsed.scheme,
                        "path":         path,
                        **meta,
                    },
                    dedup_key   = (domain_root, title, "security_headers"),
                    cwe         = cwe,
                    wasc        = wasc,
                    reference   = ref,
                    **scores,
                )
            else:
                return reporter.append_evidence_page(domain_root, title, url)

        # ── Collect coroutines synchronously ─────────────────────────────
        coros = []
        
        # ─────────────────────────────────────────────────────────────────
        # 2. Clickjacking — X-Frame-Options (200 only)
        # ─────────────────────────────────────────────────────────────────
        if status_code == 200:
            xfo = headers.get("x-frame-options", "").lower()
            if xfo not in ("deny", "sameorigin"):
                conf = _boost_confidence("medium", sensitive)
                coros.append(_make_report_coro(
                    title       = "Missing Clickjacking Protection (X-Frame-Options)",
                    confidence  = conf,
                    profile_key = f"missing_xfo_{conf}",
                    evidence    = {"x-frame-options": xfo or "absent"},
                    cwe         = "CWE-1021",
                    wasc        = "WASC-14",
                    ref         = "https://owasp.org/www-project-top-ten/2017/A5_2017-Broken_Access_Control.html",
                ))

        # ─────────────────────────────────────────────────────────────────
        # 3. HSTS — fires on ANY HTTPS response (incl. 3xx)
        # ─────────────────────────────────────────────────────────────────
        if is_https:
            hsts = headers.get("strict-transport-security", "").lower()

            if not hsts:
                coros.append(_make_report_coro(
                    title       = "Strict-Transport-Security Not Enabled",
                    confidence  = "medium",
                    profile_key = "hsts_absent",
                    evidence    = {"strict-transport-security": "absent"},
                    cwe         = "CWE-319",
                    wasc        = "WASC-4",
                    ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                ))
            else:
                match   = HSTS_MAX_AGE_RE.search(hsts)
                max_age = int(match.group(1)) if match else 0

                if max_age < 31_536_000:
                    coros.append(_make_report_coro(
                        title       = "Weak HSTS max-age (< 1 year)",
                        confidence  = "medium",
                        profile_key = "hsts_weak_maxage",
                        evidence    = {"max-age": max_age, "minimum_required": 31_536_000},
                        cwe         = "CWE-319",
                        wasc        = "WASC-4",
                        ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    ))

                if "includesubdomains" not in hsts:
                    coros.append(_make_report_coro(
                        title       = "HSTS Missing includeSubDomains",
                        confidence  = "medium",
                        profile_key = "hsts_missing_subdomains",
                        evidence    = {"strict-transport-security": _truncate(hsts)},
                        cwe         = "CWE-319",
                        wasc        = "WASC-4",
                        ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    ))

                if "preload" not in hsts:
                    coros.append(_make_report_coro(
                        title       = "HSTS Not Preloaded",
                        confidence  = "low",
                        profile_key = "hsts_not_preloaded",
                        evidence    = {"strict-transport-security": _truncate(hsts)},
                        cwe         = "CWE-319",
                        wasc        = "WASC-4",
                        ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
                    ))

        # ─────────────────────────────────────────────────────────────────
        # 4. MIME Sniffing — X-Content-Type-Options
        # ─────────────────────────────────────────────────────────────────
        if headers.get("x-content-type-options", "").lower() != "nosniff":
            coros.append(_make_report_coro(
                title       = "Missing X-Content-Type-Options: nosniff",
                confidence  = "low",
                profile_key = "nosniff_absent",
                evidence    = {"x-content-type-options": headers.get("x-content-type-options") or "absent"},
                cwe         = "CWE-693",
                wasc        = "WASC-15",
                ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            ))

        # ─────────────────────────────────────────────────────────────────
        # 5. Referrer-Policy
        # ─────────────────────────────────────────────────────────────────
        referrer = headers.get("referrer-policy", "").lower()
        if not referrer:
            conf = _boost_confidence("medium", sensitive)
            coros.append(_make_report_coro(
                title       = "Missing Referrer-Policy",
                confidence  = conf,
                profile_key = f"referrer_missing_{conf}",
                evidence    = {"referrer-policy": "absent"},
                cwe         = "CWE-200",
                wasc        = "WASC-13",
                ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            ))
        elif referrer == "unsafe-url":
            coros.append(_make_report_coro(
                title       = "Weak Referrer-Policy (unsafe-url)",
                confidence  = "medium",
                profile_key = "referrer_unsafe_url",
                evidence    = {"referrer-policy": "unsafe-url"},
                cwe         = "CWE-200",
                wasc        = "WASC-13",
                ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            ))

        # ─────────────────────────────────────────────────────────────────
        # 6. Permissions-Policy / Feature-Policy
        # ─────────────────────────────────────────────────────────────────
        permissions = (
            headers.get("permissions-policy")
            or headers.get("feature-policy", "")
        )
        if not permissions:
            conf = _boost_confidence("medium", sensitive)
            coros.append(_make_report_coro(
                title       = "Missing Permissions-Policy",
                confidence  = conf,
                profile_key = f"permissions_absent_{conf}",
                evidence    = {"permissions-policy": "absent"},
                cwe         = "CWE-693",
                wasc        = "WASC-15",
                ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            ))
        elif "*" in permissions:
            conf = _boost_confidence("medium", sensitive)
            coros.append(_make_report_coro(
                title       = "Overly Permissive Permissions-Policy (Wildcard)",
                confidence  = conf,
                profile_key = "permissions_wildcard",
                evidence    = {"permissions-policy": _truncate(permissions)},
                cwe         = "CWE-693",
                wasc        = "WASC-15",
                ref         = "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            ))

        # ── Dispatch all coroutines in parallel ───────────────────────────
        if coros:
            await asyncio.gather(*coros)

    except Exception as e:
        logger.error(
            f"[Headers] Failed for {event.get('url', 'unknown')}: "
            f"{_truncate(str(e))}",
            exc_info=True,
        )