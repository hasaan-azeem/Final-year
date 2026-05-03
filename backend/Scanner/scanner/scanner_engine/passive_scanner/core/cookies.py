import re
import math
import asyncio
import logging
from urllib.parse import urlparse
from typing import Optional

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.cookies")

MAX_SNIPPET_LEN  = 100
LOW_ENTROPY_THRESHOLD = 3.5
ONE_YEAR_SECONDS = 365 * 24 * 60 * 60

JWT_REGEX = re.compile(
    r"^[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,}$"
)

SESSION_KEYWORDS = [
    "session", "sess", "sid", "token", "auth",
    "jsessionid", "phpsessid", "connect.sid", "moodle",
]

SENSITIVE_VALUE_PATTERNS = [
    re.compile(r"^[A-Za-z0-9+/]{40,}={0,2}$"),   # base64 blob
    re.compile(r"[0-9a-fA-F]{32,}"),               # hex hash
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),  # JWT prefix
]

_OWASP_COOKIES = (
    "https://owasp.org/www-project-web-security-testing-guide/latest/"
    "4-Web_Application_Security_Testing/06-Session_Management_Testing/"
    "02-Testing_for_Cookies_Attributes"
)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _truncate(text: str) -> str:
    return text[:MAX_SNIPPET_LEN] if text else ""

def _domain_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _normalize_flags(flags: list) -> str:
    return " ".join(f.lower() for f in (flags or []))

def _is_session_cookie(name: str) -> bool:
    name_lower = name.lower()
    return any(k in name_lower for k in SESSION_KEYWORDS)

def _contains_jwt(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 3 and all(len(p) >= 10 for p in parts)

def _shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    length = len(data)
    return -sum(
        (c := data.count(ch) / length) * math.log2(c)
        for ch in set(data)
    )

def _parse_set_cookie(header: str) -> Optional[dict]:
    """Parse a raw Set-Cookie header string into a cookie dict."""
    try:
        parts  = header.split(";")
        name, value = parts[0].split("=", 1)
        flags  = []
        domain = None
        path   = "/"
        expires = -1

        for p in parts[1:]:
            p = p.strip()
            pl = p.lower()
            if pl == "secure":
                flags.append("secure")
            elif pl == "httponly":
                flags.append("httponly")
            elif pl.startswith("samesite"):
                flags.append(pl)
            elif pl.startswith("domain="):
                domain = p.split("=", 1)[1].strip()
            elif pl.startswith("path="):
                path = p.split("=", 1)[1].strip()
            elif pl.startswith("max-age="):
                try:
                    expires = int(p.split("=", 1)[1].strip())
                except ValueError:
                    pass

        return {
            "name":    name.strip(),
            "value":   value,
            "domain":  domain,
            "path":    path,
            "flags":   flags,
            "expires": expires,
            "session": expires == -1,
        }
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_cookies(
    event: dict,
    reporter,
    page_id: Optional[int] = None,
    endpoint_id: Optional[int] = None,
    _seen: Optional[set] = None,
):
    """
    Analyze cookies from a flat fetcher event for security misconfigurations.

    Reads from:
      event["cookies"]     — list of parsed cookie dicts from the browser jar
      event["set_cookies"] — list of raw Set-Cookie header strings (fallback)
      event["url"]         — page URL

    All findings are DOMAIN-LEVEL:
      First hit per (domain, cookie_name, issue) → inserts row with
        evidence.affected_pages = [url]
      Subsequent hits → appends url via reporter.append_evidence_page()

    cookie_name is stored in parameter_name so the DB links to the
    specific cookie rather than burying it in evidence JSON.

    Checks per cookie (all domain-level):
      1.  Missing Secure flag              (HTTPS only)
      2.  Session cookie missing HttpOnly
      3.  Session cookie missing SameSite  ← FIX: was documented but not implemented
      4.  SameSite=None without Secure
      5.  Weak SameSite=Lax on session cookie
      6.  Low entropy session value
      7.  JWT stored in session cookie
      8.  Excessive lifetime (> 1 year)
      9.  Overly broad domain scope
      10. Sensitive value pattern detected
    """
    if _seen is None:
        _seen = set()

    try:
        url = event.get("url")
        if not url:
            return

        cookies      = list(event.get("cookies") or [])
        set_cookies  = event.get("set_cookies") or []

        if not cookies and set_cookies:
            for sc in set_cookies:
                parsed = _parse_set_cookie(sc)
                if parsed:
                    cookies.append(parsed)

        if not cookies:
            return

        is_https = url.lower().startswith("https")
        domain   = _domain_root(url)

        raw_base = {
            "url":      url,
            "is_https": is_https,
        }

        # ── Dedup helpers ──────────────────────────────────────────────────
        # _seen.add() is called synchronously before any await so concurrent
        # gather() calls for different checks on the same cookie are safe.

        def _first(cookie_name: str, slug: str) -> bool:
            return (domain, cookie_name, slug) not in _seen

        def _mark(cookie_name: str, slug: str):
            _seen.add((domain, cookie_name, slug))

        async def _report(
            cookie_name, slug, title, confidence, profile_key,
            evidence, cwe, wasc, ref,
        ):
            """
            Domain-level report with cookie_name in parameter_name.
            First hit → insert. Repeat hit → append_evidence_page.
            _seen is mutated synchronously before the first await.
            """
            if not _first(cookie_name, slug):
                await reporter.append_evidence_page(domain, title, url)
                return
            _mark(cookie_name, slug)
            scores = build_ai_scores(profile_key, url)
            meta   = scores.pop("_meta", {})
            await reporter.report(
                page_url=domain,
                title=title,
                category="cookies",
                confidence=confidence,
                page_id=page_id,
                endpoint_id=endpoint_id,
                parameter_name=cookie_name,
                evidence={**evidence, "affected_pages": [url]},
                raw_data={**raw_base, **meta},
                dedup_key=(domain, title, "cookies"),
                cwe=cwe,
                wasc=wasc,
                reference=ref,
                **scores,
            )

        # ── Per-cookie checks ──────────────────────────────────────────────
        for cookie in cookies:
            try:
                name        = cookie.get("name")
                value       = cookie.get("value", "")
                raw_flags   = cookie.get("flags", [])
                domain_attr = cookie.get("domain")
                expires     = cookie.get("expires", -1)

                if not name:
                    continue

                flags_str  = _normalize_flags(raw_flags)
                is_session = _is_session_cookie(name)
                tname      = _truncate(name)

                tasks = []

                # ── 1. Missing Secure ──────────────────────────────────────
                # Domain-level: a cookie missing Secure is a site-wide misconfiguration.
                if is_https and "secure" not in flags_str:
                    profile = "session_cookie_not_secure" if is_session else "cookie_missing_secure"
                    conf    = "high" if is_session else "medium"
                    tasks.append(_report(
                        cookie_name=name,
                        slug="missing_secure",
                        title=f"Cookie '{tname}' Missing Secure Flag",
                        confidence=conf,
                        profile_key=profile,
                        evidence={"cookie": tname, "flags": _truncate(flags_str)},
                        cwe="CWE-614",
                        wasc="WASC-15",
                        ref=_OWASP_COOKIES,
                    ))

                # ── 2. Session cookie missing HttpOnly ─────────────────────
                # Domain-level: exposes session to XSS site-wide.
                if is_session and "httponly" not in flags_str:
                    tasks.append(_report(
                        cookie_name=name,
                        slug="missing_httponly",
                        title=f"Session Cookie '{tname}' Missing HttpOnly Flag",
                        confidence="high",
                        profile_key="session_cookie_not_httponly",
                        evidence={"cookie": tname, "flags": _truncate(flags_str)},
                        cwe="CWE-1004",
                        wasc="WASC-15",
                        ref=_OWASP_COOKIES,
                    ))

                # ── 3. Session cookie missing SameSite ─────────────────────
                # Domain-level: absence of SameSite exposes the site to CSRF.
                # FIX: this check was documented in the docstring but never implemented.
                has_samesite = any(f.startswith("samesite") for f in (raw_flags or []))
                if is_session and not has_samesite:
                    tasks.append(_report(
                        cookie_name=name,
                        slug="missing_samesite",
                        title=f"Session Cookie '{tname}' Missing SameSite Attribute",
                        confidence="medium",
                        profile_key="session_cookie_no_samesite",
                        evidence={"cookie": tname, "flags": _truncate(flags_str)},
                        cwe="CWE-352",
                        wasc="WASC-09",
                        ref="https://owasp.org/www-community/attacks/csrf",
                    ))

                # ── 4. SameSite=None without Secure ───────────────────────
                # Domain-level: browser will reject this in modern clients anyway,
                # but the misconfiguration itself is a site-wide issue.
                if "samesite=none" in flags_str and "secure" not in flags_str:
                    tasks.append(_report(
                        cookie_name=name,
                        slug="samesite_none_no_secure",
                        title=f"Cookie '{tname}' SameSite=None Without Secure Flag",
                        confidence="high",
                        profile_key="cookie_samesite_none_insecure",
                        evidence={"cookie": tname, "flags": _truncate(flags_str)},
                        cwe="CWE-614",
                        wasc="WASC-15",
                        ref="https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                    ))

                # ── 5. Weak SameSite=Lax on session cookie ─────────────────
                # Domain-level: Lax only partially protects against CSRF.
                if is_session and "samesite=lax" in flags_str:
                    tasks.append(_report(
                        cookie_name=name,
                        slug="weak_samesite_lax",
                        title=f"Session Cookie '{tname}' Uses Weak SameSite=Lax",
                        confidence="low",
                        profile_key="cookie_weak_samesite_lax",
                        evidence={"cookie": tname, "flags": _truncate(flags_str)},
                        cwe="CWE-352",
                        wasc="WASC-09",
                        ref="https://owasp.org/www-community/attacks/csrf",
                    ))

                # ── 6. Low entropy session value ───────────────────────────
                # Domain-level: predictable session tokens are a site-wide weakness.
                if is_session and value and len(value) >= 16:
                    entropy = _shannon_entropy(value)
                    if entropy < LOW_ENTROPY_THRESHOLD:
                        tasks.append(_report(
                            cookie_name=name,
                            slug="low_entropy",
                            title=f"Session Cookie '{tname}' Has Low Entropy Value",
                            confidence="medium",
                            profile_key="cookie_low_entropy",
                            evidence={
                                "cookie":    tname,
                                "entropy":   round(entropy, 2),
                                "threshold": LOW_ENTROPY_THRESHOLD,
                            },
                            cwe="CWE-331",
                            wasc="WASC-15",
                            ref=_OWASP_COOKIES,
                        ))

                # ── 7. JWT stored in session cookie ────────────────────────
                # Domain-level: architectural decision applies to the whole site.
                if is_session and value and (JWT_REGEX.match(value) or _contains_jwt(value)):
                    tasks.append(_report(
                        cookie_name=name,
                        slug="jwt_stored",
                        title=f"JWT Token Stored in Session Cookie '{tname}'",
                        confidence="low",
                        profile_key="cookie_jwt_stored",
                        evidence={"cookie": tname},
                        cwe="CWE-522",
                        wasc="WASC-13",
                        ref=_OWASP_COOKIES,
                    ))

                # ── 8. Excessive lifetime (> 1 year) ───────────────────────
                # Domain-level: cookie lifetime is set server-side, applies everywhere.
                try:
                    lifetime = int(expires) if expires and expires != -1 else 0
                except (ValueError, TypeError):
                    lifetime = 0

                if lifetime > ONE_YEAR_SECONDS:
                    tasks.append(_report(
                        cookie_name=name,
                        slug="excessive_lifetime",
                        title=f"Cookie '{tname}' Has Excessive Lifetime (> 1 Year)",
                        confidence="medium",
                        profile_key="cookie_excessive_lifetime",
                        evidence={"cookie": tname, "expires_seconds": lifetime},
                        cwe="CWE-613",
                        wasc="WASC-47",
                        ref="https://owasp.org/www-community/controls/Session_Timeout",
                    ))

                # ── 9. Overly broad domain scope ───────────────────────────
                # Domain-level: domain scope is a server-side setting.
                if domain_attr and domain_attr.startswith(".") and domain_attr.count(".") == 1:
                    tasks.append(_report(
                        cookie_name=name,
                        slug="broad_domain",
                        title=f"Cookie '{tname}' Scoped to Overly Broad Domain",
                        confidence="medium",
                        profile_key="cookie_overly_broad_domain",
                        evidence={"cookie": tname, "domain": _truncate(domain_attr)},
                        cwe="CWE-1275",
                        wasc="WASC-15",
                        ref="https://owasp.org/www-community/controls/SecureCookieAttribute",
                    ))

                # ── 10. Sensitive value pattern detected ───────────────────
                # Domain-level: the server always encodes values the same way.
                # Skip if already flagged as JWT to avoid double-reporting.
                if value and not _contains_jwt(value):
                    if any(p.search(value) for p in SENSITIVE_VALUE_PATTERNS):
                        tasks.append(_report(
                            cookie_name=name,
                            slug="sensitive_value",
                            title=f"Cookie '{tname}' May Contain Sensitive Data",
                            confidence="medium",
                            profile_key="cookie_sensitive_value",
                            evidence={"cookie": tname},
                            cwe="CWE-312",
                            wasc="WASC-13",
                            ref=(
                                "https://owasp.org/www-community/vulnerabilities/"
                                "Information_exposure_through_query_strings_in_url"
                            ),
                        ))

                # Fire all checks for this cookie concurrently.
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

            except Exception as ce:
                logger.error(
                    f"[Cookies] Error on cookie '{cookie.get('name')}': {ce}",
                    exc_info=True,
                )

    except Exception as e:
        logger.error(f"[Cookies] Analyzer failure: {e}", exc_info=True)