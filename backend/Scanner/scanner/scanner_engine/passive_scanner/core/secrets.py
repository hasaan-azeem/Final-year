import asyncio
import re
import math
import logging
from typing import Optional
from urllib.parse import urlparse

from ..scoring import build_ai_scores, get_path_tier_name

logger = logging.getLogger("webxguard.secrets")

MAX_SNIPPET_LEN = 100
MAX_BODY_SCAN   = 1_000_000   # 1 MB
MAX_MATCHES     = 20          # per-pattern cap

# ─────────────────────────────────────────────────────────────────────────────
# CONTENT-TYPE GATE
# ─────────────────────────────────────────────────────────────────────────────

_SCANNABLE_TYPES = (
    "javascript",
    "application/json",
    "text/html",
    "text/plain",
    "application/xml",
    "text/xml",
)


def _is_scannable(headers: dict) -> bool:
    ct = headers.get("content-type", "").lower()
    return any(t in ct for t in _SCANNABLE_TYPES)


# ─────────────────────────────────────────────────────────────────────────────
# KNOWN-SECRET PATTERNS
# Ordered from highest to lowest severity.
# ─────────────────────────────────────────────────────────────────────────────

KNOWN_PATTERNS: list[tuple] = [
    (
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |)?PRIVATE KEY-----"),
        "Private Key Material Exposed",
        "private_key_exposed",
        "CWE-312",
    ),
    (
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "AWS Access Key Exposed",
        "aws_key_exposed",
        "CWE-798",
    ),
    (
        re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        "Google API Key Exposed",
        "api_key_exposed",
        "CWE-798",
    ),
    (
        re.compile(r"\bsk_live_[0-9a-zA-Z]{24}\b"),
        "Stripe Live Secret Key Exposed",
        "api_key_exposed",
        "CWE-798",
    ),
    (
        re.compile(r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b"),
        "JWT Token Exposed",
        "jwt_exposed",
        "CWE-312",
    ),
]

# Generic high-entropy patterns
GENERIC_SECRET_RE = re.compile(r"[A-Za-z0-9_\-]{32,}")
BASE64_RE         = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

ENTROPY_THRESHOLD_GENERIC = 4.2
ENTROPY_THRESHOLD_BASE64  = 4.5

_SKIP_VALUES: frozenset = frozenset({
    "examplekey", "testkey", "placeholder",
    "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
    "0000000000000000000000000000000000000000",
})

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    s = (text or "")[:MAX_SNIPPET_LEN]
    return s + "..." if len(text or "") > MAX_SNIPPET_LEN else s


def _entropy(s: str) -> float:
    """Shannon entropy — computed once per candidate, result reused."""
    if not s:
        return 0.0
    prob = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob)


def _is_sensitive(url: str) -> bool:
    return get_path_tier_name(url) in ("critical", "high", "elevated")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────────────────────────────────────

async def scan_secrets(
    entry:   dict,
    reporter,
    page_id: Optional[int] = None,
    _seen:   Optional[set] = None,
) -> None:
    """
    Scan an HTTP response body for exposed secrets, API keys, private keys,
    JWTs, and high-entropy strings.

    Scope
    ─────
    Covers HTML, JSON, plain text, and XML responses.
    JavaScript-specific scanning is handled by javascript.py — this module
    focuses on non-JS response bodies (API responses, rendered HTML, configs).

    Parameters
    ──────────
    entry    — one "http"-type event from fetcher's network_events list.
               Expected keys: url, body, status_code, headers.
    reporter — Reporter instance (webxguard.reporter.Reporter).
    page_id  — pages.id FK forwarded to reporter.
    _seen    — per-scan dedup set (caller owns it).
               Key: (url, sig). Pass the same set across all scan_secrets()
               calls in a scan so the same secret exposed on multiple pages
               (e.g., via a shared API response) is only reported once per
               unique value.

    PERFORMANCE: all coroutines collected synchronously then dispatched
    with asyncio.gather() so reporter I/O runs concurrently.
    _entropy() is called exactly once per candidate — result is reused
    in both the threshold check and the evidence dict.
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

        if not _is_scannable(headers):
            return

        body      = body[:MAX_BODY_SCAN]
        sensitive = _is_sensitive(url)

        # Dedup helpers
        def _first_hit(sig: str) -> bool:
            return (url, sig) not in _seen

        def _mark(sig: str):
            _seen.add((url, sig))

        coros: list = []

        # ── 1. Known secret patterns ──────────────────────────────────────
        for pattern, title, profile, cwe in KNOWN_PATTERNS:
            count = 0
            for match in pattern.findall(body):
                value = match.strip()
                if not value or value.lower() in _SKIP_VALUES:
                    continue
                sig = f"{title}::{value[:24]}"
                if not _first_hit(sig):
                    continue
                _mark(sig)
                count += 1
                if count > MAX_MATCHES:
                    break

                scores     = build_ai_scores(profile, url)
                meta       = scores.pop("_meta", {})
                confidence = "high" if sensitive else "medium"

                coros.append(reporter.report(
                    page_url   = url,
                    title      = title,
                    category   = "sensitive_data",
                    confidence = confidence,
                    page_id    = page_id,
                    evidence   = {"snippet": _snippet(value)},
                    raw_data   = {"value_prefix": value[:24], "pattern": title, **meta},
                    cwe        = cwe,
                    wasc       = "WASC-13",
                    reference  = (
                        "https://owasp.org/www-project-top-ten/"
                        "2017/A3_2017-Sensitive_Data_Exposure.html"
                    ),
                    dedup_key  = (url, f"{title}::{value[:24]}", "sensitive_data"),
                    **scores,
                ))

        # ── 2. Generic high-entropy strings ───────────────────────────────
        # BUG FIX: original called _entropy(candidate) three times per match
        # (once for threshold, twice inside evidence/raw_data dicts).
        # Now computed exactly once and the result is reused.
        count = 0
        for candidate in GENERIC_SECRET_RE.findall(body):
            if len(candidate) < 32 or candidate.lower() in _SKIP_VALUES:
                continue
            sig = f"entropy::{candidate[:24]}"
            if not _first_hit(sig):
                continue
            ent = _entropy(candidate)           # ← computed once
            if ent < ENTROPY_THRESHOLD_GENERIC:
                continue
            _mark(sig)
            count += 1
            if count > MAX_MATCHES:
                break

            scores = build_ai_scores("high_entropy_secret", url)
            meta   = scores.pop("_meta", {})

            coros.append(reporter.report(
                page_url   = url,
                title      = "High-Entropy String (Possible Secret)",
                category   = "sensitive_data",
                confidence = "medium" if sensitive else "low",
                page_id    = page_id,
                evidence   = {"snippet": _snippet(candidate), "entropy": round(ent, 2)},
                raw_data   = {"value_prefix": candidate[:24], "entropy": round(ent, 2), **meta},
                cwe        = "CWE-522",
                wasc       = "WASC-13",
                reference  = (
                    "https://cheatsheetseries.owasp.org/cheatsheets"
                    "/Cryptographic_Storage_Cheat_Sheet.html"
                ),
                dedup_key  = (url, f"High-Entropy::{candidate[:24]}", "sensitive_data"),
                **scores,
            ))

        # ── 3. Base64 high-entropy strings ────────────────────────────────
        # Same _entropy-once fix applied here too.
        count = 0
        for candidate in BASE64_RE.findall(body):
            sig = f"b64::{candidate[:24]}"
            if not _first_hit(sig):
                continue
            ent = _entropy(candidate)           # ← computed once
            if ent < ENTROPY_THRESHOLD_BASE64:
                continue
            _mark(sig)
            count += 1
            if count > MAX_MATCHES:
                break

            scores = build_ai_scores("high_entropy_secret", url)
            meta   = scores.pop("_meta", {})

            coros.append(reporter.report(
                page_url   = url,
                title      = "Base64 High-Entropy String (Possible Secret)",
                category   = "sensitive_data",
                confidence = "medium" if sensitive else "low",
                page_id    = page_id,
                evidence   = {"snippet": _snippet(candidate), "entropy": round(ent, 2)},
                raw_data   = {"value_prefix": candidate[:24], "entropy": round(ent, 2), **meta},
                cwe        = "CWE-522",
                wasc       = "WASC-13",
                reference  = (
                    "https://cheatsheetseries.owasp.org/cheatsheets"
                    "/Cryptographic_Storage_Cheat_Sheet.html"
                ),
                dedup_key  = (url, f"Base64-Entropy::{candidate[:24]}", "sensitive_data"),
                **scores,
            ))

        # ── Dispatch all coroutines in parallel ───────────────────────────
        if coros:
            await asyncio.gather(*coros)
            logger.info(f"[Secrets] {len(coros)} finding(s) at {url}")

    except Exception as e:
        logger.error(
            f"[Secrets] Error on {entry.get('url', '?')}: {e}",
            exc_info=True,
        )