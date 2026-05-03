import re
import asyncio
import logging
from urllib.parse import urlparse
from typing import Optional

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.cors")

MAX_SNIPPET_LEN = 100

SENSITIVE_PATHS = [
    "/admin", "/administrator", "/dashboard",
    "/api/", "/api", "/v1/", "/v2/", "/v3/",
    "/internal", "/graphql", "/rest/",
    "/account", "/profile", "/me/",
    "/payment", "/checkout", "/billing",
    "/auth", "/login", "/session",
]

SENSITIVE_EXPOSE_HEADERS = {
    "authorization", "x-api-key", "set-cookie",
    "x-auth-token", "cookie", "x-csrf-token",
}

DANGEROUS_METHODS = {"DELETE", "PUT", "PATCH", "TRACE"}

_POSTMESSAGE_RE = re.compile(
    r'postmessage\s*\([^,]+,\s*(?:[\'"]?\*[\'"]?)\s*[,)]',
    re.IGNORECASE,
)


def _truncate(text: str) -> str:
    return text[:MAX_SNIPPET_LEN] if text else ""

def _domain_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _is_sensitive_path(path: str) -> bool:
    path = path.lower()
    return any(
        path == p.rstrip("/") or path.startswith(p if p.endswith("/") else p + "/")
        for p in SENSITIVE_PATHS
    )

def _origin_uses_http(origin: str) -> bool:
    return origin.lower().startswith("http://")

def _is_postmessage_wildcard(body: str) -> bool:
    if not body:
        return False
    return bool(_POSTMESSAGE_RE.search(body))


async def analyze_cors(
    event: dict,
    reporter,
    page_id: Optional[int] = None,
    endpoint_id: Optional[int] = None,
    _seen: Optional[set] = None,
):
    """
    Detect CORS misconfigurations from a single flat fetcher HTTP event.

    Dedup strategy:
      Domain-level — checks 1-4, 6-9 (header-driven misconfigurations apply
                     to the whole origin; first hit inserts, subsequent hits
                     append the page URL via reporter.append_evidence_page)
      Page-level   — checks 5 and 10 (path-specific exposure and inline JS)

    All 10 checks always run independently (no early returns). _seen is mutated
    synchronously before any await so asyncio.gather() is safe: two concurrent
    coroutines for the same key both run their synchronous guard, one wins the
    insert, the other correctly falls through to append_evidence_page.

    Checks:
      1.  Wildcard origin with credentials
      2.  Null origin with credentials
      3.  Reflected origin with credentials
      4.  External domain with credentials
      5.  Wildcard origin on sensitive endpoint  (page-level)
      6.  Allowed origin uses insecure HTTP
      7.  Dangerous HTTP methods exposed (DELETE/PUT/PATCH/TRACE)
      8.  Sensitive headers in Access-Control-Expose-Headers
      9.  Excessive preflight cache (max-age > 24h)
      10. postMessage with wildcard target origin  (page-level)
    """
    if _seen is None:
        _seen = set()

    try:
        url         = event.get("url")
        status_code = event.get("status_code")
        raw_headers = event.get("headers", {})

        if not url or not status_code or not isinstance(raw_headers, dict):
            return

        resource_type = event.get("resource_type", "")
        if resource_type and resource_type not in (
            "document", "xhr", "fetch", "other", ""
        ):
            return

        parsed      = urlparse(url)
        path        = parsed.path.lower() or "/"
        target_host = parsed.netloc
        domain      = _domain_root(url)
        sensitive   = _is_sensitive_path(path)

        headers = {k.lower(): str(v) for k, v in raw_headers.items()}

        acao_raw = headers.get("access-control-allow-origin", "").strip()
        acac_raw = headers.get("access-control-allow-credentials", "").strip().lower()
        acam_raw = headers.get("access-control-allow-methods", "").strip()
        aceh_raw = headers.get("access-control-expose-headers", "").strip()
        acma_raw = headers.get("access-control-max-age", "").strip()
        body     = event.get("body", "") or ""

        req_hdrs = event.get("request_headers") or {}
        request_origin = (
            req_hdrs.get("origin") or req_hdrs.get("Origin", "")
        ).strip()

        credentials_allowed = acac_raw == "true"

        raw_base = {
            "url":         url,
            "status_code": status_code,
            "path":        path,
            "sensitive":   sensitive,
        }

        _owasp_cors = (
            "https://owasp.org/www-project-web-security-testing-guide/latest/"
            "4-Web_Application_Security_Testing/11-Client-Side_Testing/"
            "07-Testing_for_Cross_Origin_Resource_Sharing"
        )

        # ── Report helpers ────────────────────────────────────────────────────

        async def _domain_report(title, confidence, profile_key, evidence, cwe, wasc, ref):
            """
            Domain-level dedup.
            _seen is mutated synchronously before the first await so concurrent
            gather() calls for different checks cannot double-insert the same key.
            """
            key      = (domain, title)
            is_first = key not in _seen
            _seen.add(key)

            if not is_first:
                await reporter.append_evidence_page(domain, title, url)
                return

            scores = build_ai_scores(profile_key, url)
            meta   = scores.pop("_meta", {})
            await reporter.report(
                page_url=domain,
                title=title,
                category="cors",
                confidence=confidence,
                page_id=page_id,
                endpoint_id=endpoint_id,
                evidence={**evidence, "affected_pages": [url]},
                raw_data={**raw_base, **meta},
                dedup_key=(domain, title, "cors"),
                cwe=cwe,
                wasc=wasc,
                reference=ref,
                **scores,
            )

        async def _page_report(title, confidence, profile_key, evidence, cwe, wasc, ref):
            """Page-level dedup — one row per (url, title)."""
            key = (url, title)
            if key in _seen:
                return
            _seen.add(key)

            scores = build_ai_scores(profile_key, url)
            meta   = scores.pop("_meta", {})
            await reporter.report(
                page_url=url,
                title=title,
                category="cors",
                confidence=confidence,
                page_id=page_id,
                endpoint_id=endpoint_id,
                evidence=evidence,
                raw_data={**raw_base, **meta},
                dedup_key=(url, title, "cors"),
                cwe=cwe,
                wasc=wasc,
                reference=ref,
                **scores,
            )

        # ── Build task list — all 10 checks, all independent ─────────────────

        tasks = []

        # ── 1. Wildcard origin + credentials ──────────────────────────────────
        # Domain-level: server config applies to every endpoint on the origin.
        if acao_raw == "*" and credentials_allowed:
            tasks.append(_domain_report(
                title="CORS: Wildcard Origin with Credentials Allowed",
                confidence="medium",
                profile_key="cors_allow_credentials_wild",
                evidence={
                    "access-control-allow-origin":      "*",
                    "access-control-allow-credentials": "true",
                    "note": "Browsers block wildcard+credentials; non-browser clients may exploit this",
                },
                cwe="CWE-942",
                wasc="WASC-14",
                ref=_owasp_cors,
            ))

        # ── 2. Null origin + credentials ───────────────────────────────────────
        # Domain-level: server trusts null origin everywhere.
        if acao_raw.lower() == "null" and credentials_allowed:
            tasks.append(_domain_report(
                title="CORS: Null Origin Allowed with Credentials",
                confidence="high",
                profile_key="cors_null_origin",
                evidence={
                    "access-control-allow-origin":      "null",
                    "access-control-allow-credentials": "true",
                    "note": "Exploitable via sandboxed iframes or local file requests",
                },
                cwe="CWE-942",
                wasc="WASC-14",
                ref=_owasp_cors,
            ))

        # ── 3. Reflected origin + credentials ──────────────────────────────────
        # Domain-level: the reflection logic lives in server middleware.
        if request_origin and acao_raw == request_origin and credentials_allowed:
            tasks.append(_domain_report(
                title="CORS: Reflected Origin with Credentials Allowed",
                confidence="high",
                profile_key="cors_reflect_origin",
                evidence={
                    "reflected_origin":                 _truncate(request_origin),
                    "access-control-allow-credentials": "true",
                    "note": "Server reflects any Origin — any site can make credentialed cross-origin requests",
                },
                cwe="CWE-942",
                wasc="WASC-14",
                ref=_owasp_cors,
            ))

        # ── 4. External domain with credentials ────────────────────────────────
        # Domain-level: the trusted origin is set server-side for the whole app.
        if credentials_allowed and acao_raw not in ("*", "null", ""):
            allowed_host = urlparse(acao_raw).netloc
            if allowed_host and allowed_host != target_host:
                tasks.append(_domain_report(
                    title=f"CORS: External Origin Trusted with Credentials ({allowed_host})",
                    confidence="high" if sensitive else "medium",
                    profile_key="cors_reflect_origin",
                    evidence={
                        "allowed_origin":                   _truncate(acao_raw),
                        "target_host":                      target_host,
                        "access-control-allow-credentials": "true",
                        "sensitive_path":                   sensitive,
                    },
                    cwe="CWE-942",
                    wasc="WASC-14",
                    ref=_owasp_cors,
                ))

        # ── 5. Wildcard origin on sensitive endpoint ────────────────────────────
        # Page-level: the sensitive path may not exist on every page; we want
        # one finding per URL that exposes a sensitive path with a wildcard ACAO.
        if acao_raw == "*" and sensitive:
            tasks.append(_page_report(
                title="CORS: Wildcard Origin on Sensitive Endpoint",
                confidence="medium",
                profile_key="cors_wildcard",
                evidence={
                    "access-control-allow-origin": "*",
                    "path":  _truncate(path),
                    "note":  "Sensitive endpoint readable from any origin",
                },
                cwe="CWE-942",
                wasc="WASC-14",
                ref=_owasp_cors,
            ))

        # ── 6. Allowed origin uses insecure HTTP ────────────────────────────────
        # Domain-level: the trusted origin is a server-side configuration.
        if acao_raw and acao_raw not in ("*", "null") and _origin_uses_http(acao_raw):
            tasks.append(_domain_report(
                title="CORS: Allowed Origin Uses Insecure HTTP",
                confidence="medium",
                profile_key="cors_http_origin_on_https",
                evidence={
                    "access-control-allow-origin": _truncate(acao_raw),
                    "note": "Trusted origin is HTTP — vulnerable to MITM downgrade attack",
                },
                cwe="CWE-319",
                wasc="WASC-14",
                ref=_owasp_cors,
            ))

        # ── 7. Dangerous HTTP methods exposed via CORS ──────────────────────────
        # Domain-level: Access-Control-Allow-Methods is a server-side header.
        if acam_raw:
            dangerous = [
                m.strip().upper() for m in acam_raw.split(",")
                if m.strip().upper() in DANGEROUS_METHODS
            ]
            if dangerous:
                tasks.append(_domain_report(
                    title="CORS: Dangerous HTTP Methods Exposed",
                    confidence="medium",
                    profile_key="cors_dangerous_methods",
                    evidence={
                        "access-control-allow-methods": _truncate(acam_raw),
                        "dangerous_methods":            dangerous,
                    },
                    cwe="CWE-942",
                    wasc="WASC-14",
                    ref=_owasp_cors,
                ))

        # ── 8. Sensitive headers in Access-Control-Expose-Headers ───────────────
        # Domain-level: header exposure is a server-side configuration.
        if aceh_raw:
            exposed_sensitive = [
                h.strip().lower() for h in aceh_raw.split(",")
                if h.strip().lower() in SENSITIVE_EXPOSE_HEADERS
            ]
            if exposed_sensitive:
                tasks.append(_domain_report(
                    title="CORS: Sensitive Headers Exposed via Access-Control-Expose-Headers",
                    confidence="high",
                    profile_key="cors_exposed_sensitive_headers",
                    evidence={
                        "access-control-expose-headers": _truncate(aceh_raw),
                        "sensitive_headers":             exposed_sensitive,
                    },
                    cwe="CWE-200",
                    wasc="WASC-13",
                    ref=_owasp_cors,
                ))

        # ── 9. Excessive preflight cache (max-age > 24 hours) ──────────────────
        # Domain-level: Access-Control-Max-Age is returned by the server globally.
        if acma_raw:
            try:
                max_age_val = int(acma_raw)
                if max_age_val > 86400:
                    tasks.append(_domain_report(
                        title="CORS: Preflight Response Cached for Excessive Duration",
                        confidence="low",
                        profile_key="cors_excessive_preflight",
                        evidence={
                            "access-control-max-age": acma_raw,
                            "note": f"Preflight cached for {max_age_val}s — threshold is 86400s (24h)",
                        },
                        cwe="CWE-942",
                        wasc="WASC-14",
                        ref="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Max-Age",
                    ))
            except ValueError:
                pass

        # ── 10. postMessage with wildcard target origin ─────────────────────────
        # Page-level: the JS call lives in a specific page's source.
        if _is_postmessage_wildcard(body):
            tasks.append(_page_report(
                title="postMessage Used with Wildcard Target Origin (*)",
                confidence="medium",
                profile_key="cors_wildcard",
                evidence={
                    "note": "postMessage() called with '*' as targetOrigin — any origin can receive the message",
                },
                cwe="CWE-346",
                wasc="WASC-14",
                ref=(
                    "https://owasp.org/www-project-web-security-testing-guide/latest/"
                    "4-Web_Application_Security_Testing/11-Client-Side_Testing/"
                    "10-Testing_for_WebSockets_Security_Vulnerabilities"
                ),
            ))

        # Fire all applicable checks concurrently.
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    except Exception as e:
        logger.error(
            f"[CORS] Failed for {event.get('url', 'unknown')}: {_truncate(str(e))}",
            exc_info=True,
        )