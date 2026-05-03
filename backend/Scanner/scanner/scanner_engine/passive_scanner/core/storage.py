import asyncio
import itertools
import re
import math
import logging
from typing import Optional
from urllib.parse import urlparse

from ..scoring import build_ai_scores, get_path_tier_name

logger = logging.getLogger("webxguard.client_storage")

MAX_SNIPPET_LEN = 120
MAX_ITEMS       = 200   # global cap across ALL storage types combined

# ─────────────────────────────────────────────────────────────────────────────
# PATTERNS
# ─────────────────────────────────────────────────────────────────────────────

JWT_RE = re.compile(
    r"^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$"
)

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"
)

SECRET_KW_RE = re.compile(
    r"(api[_-]?key|secret|token|auth|refresh|session)",
    re.I,
)

BASE64_RE = re.compile(r"^[A-Za-z0-9+/=]{40,}$")

HIGH_ENTROPY_THRESHOLD = 4.2
HIGH_ENTROPY_MIN_LEN   = 32

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    s = text[:MAX_SNIPPET_LEN]
    return s + "..." if len(text) > MAX_SNIPPET_LEN else s


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    probs = [value.count(c) / len(value) for c in set(value)]
    return -sum(p * math.log2(p) for p in probs)


def _is_sensitive(url: str) -> bool:
    return get_path_tier_name(url) in ("critical", "high", "elevated")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_client_storage(
    entry:   dict,
    reporter,
    page_id: Optional[int] = None,
) -> None:
    """
    Inspect localStorage and sessionStorage for sensitive values.

    Expected entry format (type="client_storage" event from fetcher)
    ─────────────────────────────────────────────────────────────────
    {
        "type":           "client_storage",
        "url":            "https://example.com/dashboard",
        "client_storage": {
            "localStorage":   {"key": "value", ...},
            "sessionStorage": {"key": "value", ...},
        },
        "timestamp": "..."
    }

    Finding tiers
    ─────────────
    JWT token       → profile: storage_jwt
    Secret keyword  → profile: storage_sensitive_value
    Email address   → profile: email_exposed
    High entropy    → profile: api_key_exposed
    Base64 blob     → profile: storage_sensitive_value

    PERFORMANCE:
    ────────────
    All storage types are flattened into a single capped iterator with
    itertools.islice() before analysis begins — this avoids the original
    bug where `break` only exited the inner (per-key) loop, causing the
    warning to fire once per storage type and the outer loop to waste
    iterations on storage types that would produce nothing.

    All coroutines are collected synchronously then dispatched with a
    single asyncio.gather() call so reporter I/O runs concurrently.
    """
    try:
        url = entry.get("url", "")
        if not url:
            return

        if entry.get("type") != "client_storage":
            return

        storage_entries = entry.get("client_storage", {})
        if not isinstance(storage_entries, dict) or not storage_entries:
            return

        sensitive = _is_sensitive(url)

        # ── Flatten all storage types into one capped sequence ────────────
        # BUG FIX: original used nested loops with `break` only exiting the
        # inner loop.  With 3 storage types each exceeding MAX_ITEMS, the
        # warning fired 3 times and the outer loop made 3 wasted iterations.
        # itertools.islice applies the cap globally in one step.
        all_pairs = itertools.islice(
            (
                (storage_type, key, value)
                for storage_type, items in storage_entries.items()
                if isinstance(items, dict)
                for key, value in items.items()
            ),
            MAX_ITEMS + 1,   # fetch one extra to detect overflow
        )
        pairs = list(all_pairs)
        if len(pairs) > MAX_ITEMS:
            logger.warning(f"[ClientStorage] Capping at {MAX_ITEMS} items at {url}")
            pairs = pairs[:MAX_ITEMS]

        # ── Collect coroutines synchronously ─────────────────────────────
        seen: set = set()
        coros: list = []

        def _add(coro):
            if coro is not None:
                coros.append(coro)

        for storage_type, key, value in pairs:
            str_value = str(value).strip()
            if not str_value:
                continue

            snip = _snippet(str_value)

            # ── 1. JWT token ──────────────────────────────────────────────
            if JWT_RE.match(str_value):
                dk = (storage_type, key, "jwt")
                if dk not in seen:
                    seen.add(dk)
                    scores = build_ai_scores("storage_jwt", url)
                    meta   = scores.pop("_meta", {})
                    _add(reporter.report(
                        page_url   = url,
                        title      = "JWT Token in Client Storage",
                        category   = "client_storage",
                        confidence = "high",
                        page_id    = page_id,
                        evidence   = {
                            "storage_type":   storage_type,
                            "key":            key,
                            "value_snippet":  snip,
                            "sensitive_page": sensitive,
                        },
                        raw_data   = {"storage_type": storage_type, "key": key, **meta},
                        cwe        = "CWE-522",
                        wasc       = "WASC-13",
                        reference  = (
                            "https://cheatsheetseries.owasp.org/cheatsheets"
                            "/JSON_Web_Token_for_Java_Cheat_Sheet.html"
                            "#do-not-store-a-jwt-in-local-storage"
                        ),
                        dedup_key  = (url, f"JWT Token in Client Storage::{storage_type}::{key}", "client_storage"),
                        **scores,
                    ))
                # Fall through — key name may also match SECRET_KW_RE

            # ── 2. Secret keyword in key name or value ────────────────────
            if SECRET_KW_RE.search(key) or SECRET_KW_RE.search(str_value):
                dk = (storage_type, key, "secret")
                if dk not in seen:
                    seen.add(dk)
                    scores = build_ai_scores("storage_sensitive_value", url)
                    meta   = scores.pop("_meta", {})
                    _add(reporter.report(
                        page_url   = url,
                        title      = "Secret Keyword in Client Storage",
                        category   = "client_storage",
                        confidence = "high" if sensitive else "medium",
                        page_id    = page_id,
                        evidence   = {
                            "storage_type":   storage_type,
                            "key":            key,
                            "value_snippet":  snip,
                            "sensitive_page": sensitive,
                        },
                        raw_data   = {"storage_type": storage_type, "key": key, **meta},
                        cwe        = "CWE-312",
                        wasc       = "WASC-13",
                        reference  = (
                            "https://owasp.org/www-community/vulnerabilities"
                            "/Information_Exposure_Through_Client_Storage"
                        ),
                        dedup_key  = (url, f"Secret Keyword in Storage::{storage_type}::{key}", "client_storage"),
                        **scores,
                    ))

            # ── 3. Email address ──────────────────────────────────────────
            for email in EMAIL_RE.findall(str_value):
                dk = (storage_type, key, f"email::{email.lower()}")
                if dk in seen:
                    continue
                seen.add(dk)
                scores = build_ai_scores("email_exposed", url)
                meta   = scores.pop("_meta", {})
                _add(reporter.report(
                    page_url   = url,
                    title      = "Email Address in Client Storage",
                    category   = "client_storage",
                    confidence = "high" if sensitive else "low",
                    page_id    = page_id,
                    evidence   = {
                        "storage_type":   storage_type,
                        "key":            key,
                        "email":          email,
                        "sensitive_page": sensitive,
                    },
                    raw_data   = {"storage_type": storage_type, "key": key, "email": email, **meta},
                    cwe        = "CWE-200",
                    wasc       = "WASC-13",
                    reference  = (
                        "https://owasp.org/www-community/vulnerabilities"
                        "/Information_Exposure_Through_Client_Storage"
                    ),
                    dedup_key  = (url, f"Email in Storage::{storage_type}::{key}::{email.lower()}", "client_storage"),
                    **scores,
                ))

            # ── 4. High-entropy value (likely secret/key) ─────────────────
            if len(str_value) > HIGH_ENTROPY_MIN_LEN:
                ent = _entropy(str_value)
                if ent >= HIGH_ENTROPY_THRESHOLD:
                    dk = (storage_type, key, "entropy")
                    if dk not in seen:
                        seen.add(dk)
                        scores = build_ai_scores("api_key_exposed", url)
                        meta   = scores.pop("_meta", {})
                        _add(reporter.report(
                            page_url   = url,
                            title      = "High-Entropy Value in Client Storage",
                            category   = "client_storage",
                            confidence = "high" if sensitive else "medium",
                            page_id    = page_id,
                            evidence   = {
                                "storage_type":   storage_type,
                                "key":            key,
                                "entropy":        round(ent, 2),
                                "value_snippet":  snip,
                                "sensitive_page": sensitive,
                            },
                            raw_data   = {"storage_type": storage_type, "key": key, "entropy": round(ent, 2), **meta},
                            cwe        = "CWE-312",
                            wasc       = "WASC-13",
                            reference  = (
                                "https://owasp.org/www-community/vulnerabilities"
                                "/Information_Exposure_Through_Client_Storage"
                            ),
                            dedup_key  = (url, f"High Entropy Storage::{storage_type}::{key}", "client_storage"),
                            **scores,
                        ))

            # ── 5. Large base64 blob ──────────────────────────────────────
            if len(str_value) > 100 and BASE64_RE.match(str_value):
                dk = (storage_type, key, "base64")
                if dk not in seen:
                    seen.add(dk)
                    scores = build_ai_scores("storage_sensitive_value", url)
                    meta   = scores.pop("_meta", {})
                    _add(reporter.report(
                        page_url   = url,
                        title      = "Base64 Blob in Client Storage",
                        category   = "client_storage",
                        confidence = "high" if sensitive else "medium",
                        page_id    = page_id,
                        evidence   = {
                            "storage_type":   storage_type,
                            "key":            key,
                            "value_length":   len(str_value),
                            "value_snippet":  snip,
                            "sensitive_page": sensitive,
                        },
                        raw_data   = {"storage_type": storage_type, "key": key, "value_length": len(str_value), **meta},
                        cwe        = "CWE-312",
                        wasc       = "WASC-13",
                        reference  = (
                            "https://owasp.org/www-community/vulnerabilities"
                            "/Information_Exposure_Through_Client_Storage"
                        ),
                        dedup_key  = (url, f"Base64 Storage::{storage_type}::{key}", "client_storage"),
                        **scores,
                    ))

        # ── Dispatch all coroutines in parallel ───────────────────────────
        if coros:
            await asyncio.gather(*coros)
            logger.info(f"[ClientStorage] {len(coros)} finding(s) at {url}")

    except Exception as e:
        logger.error(
            f"[ClientStorage] Error on {entry.get('url', '?')}: {e}",
            exc_info=True,
        )