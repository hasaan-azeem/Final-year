import asyncio
import re
import base64
import json
import logging
from typing import Optional
from urllib.parse import urlparse

from ..scoring import build_ai_scores, get_path_tier_name

logger = logging.getLogger("webxguard.javascript")

MAX_JS_SIZE     = 2 * 1024 * 1024   # 2 MB hard cap
MAX_SNIPPET_LEN = 100
MAX_MATCHES     = 20                 # per-pattern cap

# ─────────────────────────────────────────────────────────────────────────────
# CONTENT-TYPE GATE
# ─────────────────────────────────────────────────────────────────────────────

_JS_CONTENT_TYPES = (
    "application/javascript",
    "text/javascript",
    "application/x-javascript",
)

# ─────────────────────────────────────────────────────────────────────────────
# PRECOMPILED PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

AWS_KEY_RE = re.compile(r"""['"]?AKIA[0-9A-Z]{16}['"]?""")

CLOUD_KEY_RE = re.compile(
    r"\b(?:"
    r"AIza[0-9A-Za-z_\-]{35}"          # Google API key
    r"|sk_live_[0-9a-zA-Z]{24}"         # Stripe secret
    r"|pk_live_[0-9a-zA-Z]{24}"         # Stripe public
    r"|AC[a-zA-Z0-9]{32}"               # Twilio
    r")\b"
)

JWT_RE = re.compile(
    r"\b[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\.[A-Za-z0-9-_]{10,}\b"
)

URL_RE = re.compile(
    r"https?://[a-zA-Z0-9\-\._~:/?#@!$&'()*+,;=%]+"
)

EMAIL_RE = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
)

SECRET_RE = re.compile(
    r"(api[_-]?key|secret|token|auth[_-]?token|client_secret)"
    r"""[\"']?\s*[:=]\s*['\"]([A-Za-z0-9\-_=+]{20,})['\"]""",
    re.I,
)

# Single combined open-redirect pattern — one pass over the body.
OPEN_REDIRECT_RE = re.compile(
    r"(?:window\.location|document\.location|location\.href|location\.assign)"
    r"[^\n]{0,120}"
    r"(?:location\.search|location\.hash|window\.name)",
    re.I,
)

DEBUG_RE = re.compile(
    r"\b(console\.log|debugger|eval|new\s+Function)\b"
)

# ─────────────────────────────────────────────────────────────────────────────
# SKIP LISTS
# ─────────────────────────────────────────────────────────────────────────────

_SKIP_EMAIL_DOMAINS: frozenset = frozenset({
    "example.com", "test.com", "domain.com", "localhost",
    "sentry.io", "webpack", "babel", "jest",
})

_DEV_URL_KEYWORDS = (
    "localhost", "127.0.0.1", "0.0.0.0",
    "dev.", "staging.", ".internal", ".test", ".local",
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    return (text or "")[:MAX_SNIPPET_LEN]


def _is_js_content_type(headers: dict) -> bool:
    ct = headers.get("content-type", "").lower()
    return any(t in ct for t in _JS_CONTENT_TYPES)


def _is_valid_jwt(token: str) -> bool:
    try:
        _, payload, _ = token.split(".")
        payload += "=" * (-len(payload) % 4)
        return isinstance(json.loads(base64.urlsafe_b64decode(payload)), dict)
    except Exception:
        return False


def _looks_random(value: str) -> bool:
    return len(value) >= 20 and len(set(value)) > 10


def _is_skip_email(email: str) -> bool:
    domain = email.split("@")[-1].lower()
    return domain in _SKIP_EMAIL_DOMAINS or "." not in domain


def _is_dev_url(host: str) -> bool:
    h = host.lower()
    return any(k in h for k in _DEV_URL_KEYWORDS)


def _is_sensitive(url: str) -> bool:
    return get_path_tier_name(url) in ("critical", "high", "elevated")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_javascript(
    entry:    dict,
    reporter,
    page_id:  Optional[int] = None,
    _seen:    Optional[set] = None,
) -> None:
    """
    Scan a JavaScript response body for secrets, dangerous patterns,
    and information disclosure.

    Parameters
    ──────────
    entry    — one "http"-type event from fetcher's network_events list.
               Expected keys: url, body, status_code, headers.
    reporter — Reporter instance (webxguard.reporter.Reporter).
    page_id  — pages.id FK forwarded to reporter.
    _seen    — per-scan dedup set (caller owns it).
               Key: (js_url, dedup_suffix).
               Pass the SAME set across all analyze_javascript() calls in a
               scan so the same JS file loaded on multiple pages is only
               reported once per finding type.

    PERFORMANCE: All findings discovered in one call are gathered into a
    single asyncio.gather() so reporter I/O runs concurrently.
    The _seen set is updated synchronously before any awaits.

    REPORTING GRANULARITY:
    ─────────────────────
    JS findings are per JS-file URL (not domain-level) because:
      • Different JS files can expose different secrets.
      • The same JS file on two pages should produce ONE finding,
        not two — hence the cross-call _seen dedup.
    """
    if _seen is None:
        _seen = set()

    try:
        url         = entry.get("url", "")
        body        = entry.get("body") or ""
        status_code = entry.get("status_code")
        headers     = entry.get("headers", {})

        if not url or not body or status_code != 200:
            return

        if not _is_js_content_type(headers):
            return

        if len(body) > MAX_JS_SIZE:
            logger.warning(
                f"[JavaScript] Truncating {len(body)} → {MAX_JS_SIZE} bytes: {url}"
            )
            body = body[:MAX_JS_SIZE]

        sensitive = _is_sensitive(url)

        # ── Dedup helpers  (synchronous — no races) ───────────────────────

        def _first_hit(sig: str) -> bool:
            return (url, sig) not in _seen

        def _mark(sig: str):
            _seen.add((url, sig))

        # ── Coroutine builder ─────────────────────────────────────────────

        def _make_coro(
            sig:        str,      # unique string within this JS URL
            title:      str,
            confidence: str,
            profile_key: str,
            evidence:   dict,
            raw_extra:  dict,
            cwe:        str,
            wasc:       str,
            ref:        str,
            dedup_suffix: str,
        ):
            """
            Mark _seen synchronously, return the reporter coroutine.
            Returns None if this (url, sig) was already seen — caller
            must filter these out before gathering.
            """
            if not _first_hit(sig):
                return None
            _mark(sig)
            scores = build_ai_scores(profile_key, url)
            meta   = scores.pop("_meta", {})
            return reporter.report(
                page_url  = url,
                title     = title,
                category  = "javascript",
                confidence= confidence,
                page_id   = page_id,
                evidence  = evidence,
                raw_data  = {**raw_extra, **meta},
                cwe       = cwe,
                wasc      = wasc,
                reference = ref,
                dedup_key = (url, dedup_suffix, "javascript"),
                **scores,
            )

        # ── Collect coroutines synchronously ─────────────────────────────
        coros = []

        def _add(coro):
            if coro is not None:
                coros.append(coro)

        # ── 1. JWT tokens ─────────────────────────────────────────────────
        seen_jwt: set = set()
        for token in JWT_RE.findall(body):
            if len(token) <= 100 or not _is_valid_jwt(token):
                continue
            prefix = token[:32]
            if prefix in seen_jwt:
                continue
            seen_jwt.add(prefix)
            if len(seen_jwt) > MAX_MATCHES:
                break
            sig = f"jwt::{prefix}"
            _add(_make_coro(
                sig         = sig,
                title       = "Valid JWT Token Found in JavaScript",
                confidence  = "high",
                profile_key = "jwt_exposed",
                evidence    = {"jwt_snippet": _snippet(token)},
                raw_extra   = {"token_prefix": prefix},
                cwe         = "CWE-311",
                wasc        = "WASC-20",
                ref         = "https://owasp.org/www-project-top-ten/2017/A2_2017-Broken-Authentication.html",
                dedup_suffix= f"Valid JWT Token::{prefix}",
            ))

        # ── 2. AWS keys ───────────────────────────────────────────────────
        seen_aws: set = set()
        for match in AWS_KEY_RE.findall(body):
            key = match.strip("'\"")
            if key in seen_aws:
                continue
            seen_aws.add(key)
            if len(seen_aws) > MAX_MATCHES:
                break
            sig = f"aws::{key[:12]}"
            _add(_make_coro(
                sig         = sig,
                title       = "AWS API Key Found in JavaScript",
                confidence  = "high",
                profile_key = "aws_key_exposed",
                evidence    = {"key_snippet": _snippet(key)},
                raw_extra   = {"key_prefix": key[:12]},
                cwe         = "CWE-798",
                wasc        = "WASC-13",
                ref         = "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
                dedup_suffix= f"AWS API Key::{key[:12]}",
            ))

        # ── 3. Cloud API keys (Google / Stripe / Twilio) ──────────────────
        seen_cloud: set = set()
        for match in CLOUD_KEY_RE.findall(body):
            if match in seen_cloud:
                continue
            seen_cloud.add(match)
            if len(seen_cloud) > MAX_MATCHES:
                break
            sig = f"cloud::{match[:12]}"
            _add(_make_coro(
                sig         = sig,
                title       = "Cloud API Key Found in JavaScript",
                confidence  = "high",
                profile_key = "api_key_exposed",
                evidence    = {"key_snippet": _snippet(match)},
                raw_extra   = {"key_prefix": match[:12]},
                cwe         = "CWE-798",
                wasc        = "WASC-13",
                ref         = "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html",
                dedup_suffix= f"Cloud API Key::{match[:12]}",
            ))

        # ── 4. Hardcoded secrets ──────────────────────────────────────────
        seen_secrets: set = set()
        for key_name, secret_value in SECRET_RE.findall(body):
            if not _looks_random(secret_value):
                continue
            inner_sig = f"{key_name.lower()}::{secret_value[:16]}"
            if inner_sig in seen_secrets:
                continue
            seen_secrets.add(inner_sig)
            if len(seen_secrets) > MAX_MATCHES:
                break
            sig = f"secret::{inner_sig}"
            _add(_make_coro(
                sig         = sig,
                title       = "Hardcoded Secret in JavaScript",
                confidence  = "high",
                profile_key = "api_key_exposed",
                evidence    = {
                    "variable":       _snippet(key_name),
                    "secret_snippet": _snippet(secret_value),
                },
                raw_extra   = {
                    "variable":      key_name,
                    "secret_prefix": secret_value[:16],
                },
                cwe         = "CWE-798",
                wasc        = "WASC-13",
                ref         = "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html",
                dedup_suffix= f"Hardcoded Secret::{inner_sig}",
            ))

        # ── 5. Internal / development URLs ────────────────────────────────
        seen_dev_hosts: set = set()
        for raw_url in URL_RE.findall(body):
            try:
                host = urlparse(raw_url).hostname or ""
                if not _is_dev_url(host) or host in seen_dev_hosts:
                    continue
                seen_dev_hosts.add(host)
                if len(seen_dev_hosts) > MAX_MATCHES:
                    break
                sig = f"devurl::{host}"
                _add(_make_coro(
                    sig         = sig,
                    title       = "Internal or Development URL Found in JavaScript",
                    confidence  = "high" if sensitive else "medium",
                    profile_key = "internal_url_exposed",
                    evidence    = {"dev_url": _snippet(raw_url), "host": host},
                    raw_extra   = {"full_url": raw_url},
                    cwe         = "CWE-200",
                    wasc        = "WASC-12",
                    ref         = "https://owasp.org/www-community/vulnerabilities/Information_Leak",
                    dedup_suffix= f"Internal URL::{host}",
                ))
            except Exception:
                continue

        # ── 6. Email addresses ────────────────────────────────────────────
        seen_emails: set = set()
        for email in EMAIL_RE.findall(body):
            if _is_skip_email(email):
                continue
            em = email.lower()
            if em in seen_emails:
                continue
            seen_emails.add(em)
            if len(seen_emails) > MAX_MATCHES:
                break
            sig = f"email::{em}"
            _add(_make_coro(
                sig         = sig,
                title       = "Email Address Found in JavaScript",
                confidence  = "low",
                profile_key = "email_exposed",
                evidence    = {"email": _snippet(email)},
                raw_extra   = {"email": email},
                cwe         = "CWE-200",
                wasc        = "WASC-13",
                ref         = "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure.html",
                dedup_suffix= f"Email Address::{em}",
            ))

        # ── 7. Debug / dangerous functions on sensitive pages ─────────────
        if sensitive:
            seen_debug: set = set()
            for fn in DEBUG_RE.findall(body):
                fn = fn.strip()
                if fn in seen_debug:
                    continue
                seen_debug.add(fn)
                sig = f"debug::{fn}"
                _add(_make_coro(
                    sig         = sig,
                    title       = "Debug or Dangerous Function in Sensitive JavaScript",
                    confidence  = "low",
                    profile_key = "debug_info_exposed",
                    evidence    = {"function": fn},
                    raw_extra   = {"matched_function": fn},
                    cwe         = "CWE-489",
                    wasc        = "WASC-29",
                    ref         = "https://owasp.org/www-community/vulnerabilities/Using_Debugging_Features_in_Production",
                    dedup_suffix= f"Debug Function::{fn}",
                ))

        # ── 8. Open redirect via DOM location manipulation ────────────────
        seen_redirects: set = set()
        for match in OPEN_REDIRECT_RE.finditer(body):
            snippet_text = match.group(0)
            sig_inner    = snippet_text[:48]
            if sig_inner in seen_redirects:
                continue
            seen_redirects.add(sig_inner)
            if len(seen_redirects) > MAX_MATCHES:
                break
            sig = f"redirect::{sig_inner}"
            _add(_make_coro(
                sig         = sig,
                title       = "Potential DOM-Based Open Redirect in JavaScript",
                confidence  = "medium",
                profile_key = "open_redirect",
                evidence    = {"line_snippet": _snippet(snippet_text)},
                raw_extra   = {"match_snippet": snippet_text[:200]},
                cwe         = "CWE-601",
                wasc        = "WASC-38",
                ref         = "https://owasp.org/www-community/attacks/Unvalidated_Redirects_and_Forwards",
                dedup_suffix= f"DOM Open Redirect::{sig_inner}",
            ))

        # ── Dispatch all coroutines in parallel ───────────────────────────
        if coros:
            await asyncio.gather(*coros)

    except Exception as e:
        logger.error(
            f"[JavaScript] Error on {entry.get('url', '?')}: {e}",
            exc_info=True,
        )