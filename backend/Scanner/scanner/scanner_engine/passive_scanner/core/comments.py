import re
import asyncio
import logging
from urllib.parse import urlparse

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.comments")

MAX_SNIPPET_LEN = 200
MAX_COMMENT_LEN = 1000

# ─────────────────────────────────────────────────────────────────────────────
# PATTERNS & KEYWORDS
# ─────────────────────────────────────────────────────────────────────────────

SENSITIVE_KEYWORDS = [
    "password", "secret", "api_key", "token", "authorization",
    "internal", "private", "debug", "staging", "database",
    "db_", "access_key",
]

SENSITIVE_KEYWORDS_WHOLE_WORD = ["dev"]

DEV_KEYWORDS = ["todo", "fixme", "hack", "bug", "temporary"]

INTERNAL_IP_PATTERN = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}"
    r"|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b"
)

INTERNAL_URL_PATTERN = re.compile(
    r"https?://(localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)",
    re.I,
)

CREDENTIAL_PATTERN = re.compile(
    r"(username|user|login|email)\s*[:=]\s*['\"]?([^\s'\"]{3,64})['\"]?",
    re.I,
)

ENDPOINT_PATTERN = re.compile(
    r"(https?://[^\s'\"<>]{10,}|/[a-z0-9_/.-]{5,})",
    re.I,
)

VERSION_PATTERN = re.compile(
    r"\b(v\d+\.\d+[\.\d]*|version\s*[:=]?\s*[\d\.]+)",
    re.I,
)

SECRET_PATTERNS = [
    re.compile(
        r"(api[_-]?key|secret|token)\s*[:=]\s*['\"](?!.*(?:loading|enter|example|placeholder|your[_-]?key))(.{6,128})['\"]",
        re.I,
    ),
    re.compile(
        r"(password|pwd|auth)\s*[:=]\s*['\"](?!.*(?:loading|enter|example|placeholder))(.{6,128})['\"]",
        re.I,
    ),
    re.compile(r"AKIA[0-9A-Z]{16}", re.I),
    re.compile(r"eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}"),
    re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", re.I),
    re.compile(r"['\"][0-9a-f]{32,64}['\"]", re.I),
]

ENDPOINT_SKIP = ["example.com", "schema.org", "w3.org", "xmlns", "google"]

CODE_BLOCK_PATTERN = re.compile(
    r'(<\?php|<script|SELECT\s+\*|INSERT INTO|function\s+\w+\s*\(|def\s+\w+\s*\()',
    re.I,
)

FORM_FIELD_PATTERN = re.compile(
    r'<input[^>]+(?:password|secret|token|auth)[^>]*>',
    re.I,
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _trunc(text: str) -> str:
    return text[:MAX_SNIPPET_LEN] if text else ""

def _is_text_response(headers: dict) -> bool:
    if not headers:
        return True
    ctype = str(headers).lower()
    return any(x in ctype for x in ["html", "text", "javascript", "json"])

def _contains_sensitive(text: str) -> tuple[bool, list[str]]:
    lowered = text.lower()
    matched = [kw for kw in SENSITIVE_KEYWORDS if kw in lowered]
    matched += [kw for kw in SENSITIVE_KEYWORDS_WHOLE_WORD if re.search(rf"\b{re.escape(kw)}\b", lowered)]
    if any(p.search(text) for p in SECRET_PATTERNS):
        matched.append("secret_pattern")
    return bool(matched), list(set(matched))

def _contains_dev_marker(text: str) -> tuple[bool, list[str]]:
    lowered = text.lower()
    matched = [kw for kw in DEV_KEYWORDS if re.search(rf"\b{re.escape(kw)}\b", lowered)]
    return bool(matched), matched

def _domain(url: str) -> str:
    return urlparse(url).netloc


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_comments(event: dict, reporter, page_id=None, endpoint_id=None, _seen: set = None):
    """
    Analyze HTML comments for sensitive information, dev markers, internal IPs/URLs,
    credentials, hidden endpoints, version strings, and commented-out code.

    Dedup strategy:
      Domain-level  — sensitive info, dev markers, version disclosure
                      (these reflect a site-wide posture; one finding per domain)
      Page-level    — internal IPs/URLs, credentials, hidden endpoints,
                      commented-out form fields and code blocks
                      (tied to specific page content)

    _seen must be the per-scan shared set from scanner.py.
    """
    if _seen is None:
        _seen = set()

    url = event.get("url")
    if not url:
        return

    body        = event.get("body", "") or ""
    headers     = event.get("headers", {}) or {}
    status_code = event.get("status_code")

    if not isinstance(body, str) or not body.strip():
        return
    if not _is_text_response(headers):
        return
    if status_code and status_code not in (200, 201, 202):
        return

    comments = re.findall(r"<!--(.*?)-->", body, re.DOTALL | re.IGNORECASE)
    if not comments:
        return

    domain        = _domain(url)
    seen_comments = set()   # deduplicate identical comments within this page

    async def _report(title, profile_key, confidence, evidence, cwe="CWE-615", wasc="WASC-13",
                      reference=None, domain_level=False):
        """
        Dedup-safe reporter.  _seen is mutated synchronously before any await
        so concurrent gather() calls within the same event loop tick cannot
        both pass the guard for the same key.
        """
        seen_key = (domain if domain_level else url, title)
        if seen_key in _seen:
            return
        _seen.add(seen_key)     # mark BEFORE first await

        scores = build_ai_scores(profile_key, url)
        meta   = scores.pop("_meta")

        await reporter.report(
            page_url=url,
            title=title,
            category="information_disclosure",
            confidence=confidence,
            evidence=evidence,
            raw_data=meta,
            cwe=cwe,
            wasc=wasc,
            reference=reference or (
                "https://owasp.org/www-project-web-security-testing-guide/latest/"
                "4-Web_Application_Security_Testing/01-Information_Gathering/"
                "05-Review_Web_Page_Content_for_Information_Leakage"
            ),
            page_id=page_id,
            endpoint_id=endpoint_id,
            **scores,
        )

    try:
        for raw_comment in comments:
            comment = raw_comment.strip()
            if not comment or len(comment) > MAX_COMMENT_LEN:
                continue
            if comment in seen_comments:
                continue
            seen_comments.add(comment)

            truncated   = _trunc(comment)
            is_sensitive, sensitive_matches = _contains_sensitive(comment)
            is_dev, dev_matches             = _contains_dev_marker(comment)

            # Collect all coroutines for this comment then fire them concurrently.
            tasks = []

            # ── 1. Sensitive information ───────────────────────────────────────
            # Domain-level: one report per site regardless of how many pages leak it.
            if is_sensitive:
                tasks.append(_report(
                    title="Sensitive Information Disclosed in HTML Comment",
                    profile_key="comment_sensitive_info",
                    confidence="high",
                    evidence={
                        "snippet": truncated,
                        "matched_indicators": sensitive_matches,
                        **({"dev_markers": dev_matches} if is_dev else {}),
                        "status_code": status_code,
                    },
                    domain_level=True,
                ))

            # ── 2. Dev markers only ────────────────────────────────────────────
            # Domain-level: developer sloppiness is a site-wide trait.
            elif is_dev:
                tasks.append(_report(
                    title="Developer Comment Found in Production HTML",
                    profile_key="comment_dev_marker",
                    confidence="low",
                    evidence={
                        "snippet": truncated,
                        "dev_markers": dev_matches,
                        "status_code": status_code,
                    },
                    domain_level=True,
                ))

            # ── 3. Internal IP address ─────────────────────────────────────────
            # Page-level: different pages may expose different internal IPs.
            ip_match = INTERNAL_IP_PATTERN.search(comment)
            if ip_match:
                tasks.append(_report(
                    title="Internal IP Address Disclosed in HTML Comment",
                    profile_key="comment_internal_ip",
                    confidence="high",
                    evidence={
                        "snippet": truncated,
                        "ip_address": ip_match.group(1),
                        "status_code": status_code,
                    },
                    cwe="CWE-200",
                ))

            # ── 4. Internal URL ────────────────────────────────────────────────
            # Page-level: each page may reference a different internal endpoint.
            url_match = INTERNAL_URL_PATTERN.search(comment)
            if url_match:
                tasks.append(_report(
                    title="Internal URL Disclosed in HTML Comment",
                    profile_key="comment_internal_url",
                    confidence="high",
                    evidence={
                        "snippet": truncated,
                        "internal_url": _trunc(url_match.group(0)),
                        "status_code": status_code,
                    },
                    cwe="CWE-200",
                ))

            # ── 5. Credential pattern ──────────────────────────────────────────
            # Page-level: credentials may vary per page.
            cred_match = CREDENTIAL_PATTERN.search(comment)
            if cred_match:
                tasks.append(_report(
                    title="Credential Pattern Disclosed in HTML Comment",
                    profile_key="comment_credential_pattern",
                    confidence="high",
                    evidence={
                        "snippet": truncated,
                        "field": cred_match.group(1),
                        "status_code": status_code,
                    },
                    cwe="CWE-312",
                ))

            # ── 6. Hidden endpoint / path ──────────────────────────────────────
            # Page-level: different pages may expose different paths.
            ep_match = ENDPOINT_PATTERN.search(comment)
            if ep_match:
                matched_ep = ep_match.group(0)
                if not any(skip in matched_ep.lower() for skip in ENDPOINT_SKIP):
                    tasks.append(_report(
                        title="Hidden Endpoint or Path Disclosed in HTML Comment",
                        profile_key="comment_hidden_endpoint",
                        confidence="low",
                        evidence={
                            "snippet": truncated,
                            "endpoint": _trunc(matched_ep),
                            "status_code": status_code,
                        },
                        cwe="CWE-200",
                    ))

            # ── 7. Version string ──────────────────────────────────────────────
            # Domain-level: the application version is the same across all pages;
            # reporting it once per domain avoids duplicate noise.
            ver_match = VERSION_PATTERN.search(comment)
            if ver_match:
                tasks.append(_report(
                    title="Version Disclosure in HTML Comment",
                    profile_key="comment_version_disclosure",
                    confidence="low",
                    evidence={
                        "snippet": truncated,
                        "version": ver_match.group(0),
                        "status_code": status_code,
                    },
                    cwe="CWE-200",
                    reference=(
                        "https://owasp.org/www-project-web-security-testing-guide/latest/"
                        "4-Web_Application_Security_Testing/01-Information_Gathering/"
                        "02-Fingerprint_Web_Server"
                    ),
                    domain_level=True,   # FIX: was page-level; version is site-wide
                ))

            # ── 8. Commented-out form field ────────────────────────────────────
            # Page-level: specific to this page's markup.
            if FORM_FIELD_PATTERN.search(comment):
                tasks.append(_report(
                    title="Commented-Out Sensitive Form Field Found in HTML",
                    profile_key="comment_form_field",
                    confidence="medium",
                    evidence={"snippet": truncated, "status_code": status_code},
                ))

            # ── 9. Commented-out code block ────────────────────────────────────
            # Page-level: specific to this page's markup.
            if len(comment) > 100 and CODE_BLOCK_PATTERN.search(comment):
                tasks.append(_report(
                    title="Commented-Out Code Block Found in HTML",
                    profile_key="comment_code_block",
                    confidence="medium",
                    evidence={"snippet": truncated, "status_code": status_code},
                ))

            # Fire all checks for this comment concurrently.
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

    except Exception as e:
        logger.error(f"[Comments] Failed on {url}: {_trunc(str(e))}", exc_info=True)