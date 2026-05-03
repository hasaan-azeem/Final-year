"""
utils/helpers.py (PRODUCTION v3)
═════════════════════════════════

URL normalization, parameter extraction, payload loading, hashing,
CVSS scoring, and general-purpose helpers shared across all active
scanner modules.

IMPROVEMENTS in v3:

  Asset Filtering (NEW)
  ─────────────────────
  • is_injectable_response() — fast filter to skip CSS, JS, images before
    module invocation. Checks status (204, 304), Content-Type, body length.
  • should_scan_response() — variant with logging reason for skipped assets.

  Production Hardening
  ────────────────────
  • compute_cvss() validates vector inputs (raises ValueError on invalid)
  • Payload cache distinguishes missing files from load errors
  • load_payloads() returns empty dict rather than raising on missing
    (for optional module payloads)
"""
from __future__ import annotations

import difflib
import hashlib
import json
import logging
import math
import re
import threading
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import (
    parse_qs,
    quote,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)

logger = logging.getLogger("webxguard.utils.helpers")


# ═══════════════════════════════════════════════════════════════════════════════
# EMBEDDED CONFIGURATION (No external config file needed)
# ═══════════════════════════════════════════════════════════════════════════════

# Payload directory location
PAYLOAD_DIR_NAME = "payloads"

# URL normalization cache size (LRU)
URL_CACHE_SIZE = 1024

# Body fingerprint cache size (LRU)
FINGERPRINT_CACHE_SIZE = 512

# CVSS computation cache size (LRU)
CVSS_CACHE_SIZE = 256


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  EXCEPTIONS
# ╚══════════════════════════════════════════════════════════════════════════════

class PayloadLoadError(RuntimeError):
    """Raised when a payload file cannot be loaded or is malformed."""


class CVSSValidationError(ValueError):
    """Raised when CVSS vector components are invalid."""


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  CONSTANTS
# ╚══════════════════════════════════════════════════════════════════════════════

_PAYLOAD_DIR: Path = Path(__file__).parent.parent / PAYLOAD_DIR_NAME

_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})

# SQL / injection characters kept raw so the server sees them as syntax.
# Spaces are excluded — they become %20 for a valid HTTP request line.
_SQL_SAFE_CHARS: str = "'\"`=<>(),-+*!|&#~@/\\;:."

# Dynamic content patterns stripped before body diffing / hashing.
_DYNAMIC_PATTERNS: tuple[re.Pattern, ...] = (
    re.compile(r'<input[^>]+name=["\']_?csrf[^>]+>',            re.I),
    re.compile(r'value=["\'][0-9A-Za-z+/=_\\-]{16,}["\']',     re.I),
    re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?'),
    re.compile(r'_=[0-9]+'),
    re.compile(r'nonce=["\'][^"\']{8,}["\']',                   re.I),
    re.compile(r'__RequestVerificationToken[^"\']*["\'][^"\']+["\']', re.I),
    re.compile(r'viewstate["\']?\s*value=["\'][^"\']+["\']',    re.I),
    re.compile(r'\bts=\d{10,13}'),
)
_DYNAMIC_SENTINEL: str = "__DYNAMIC__"

_SEVERITY_LABELS: tuple[tuple[float, str], ...] = (
    (9.0, "Critical"),
    (7.0, "High"),
    (4.0, "Medium"),
    (1.0, "Low"),
    (0.0, "Info"),
)

SEVERITY_MAP: dict[str, float] = {
    "sql_injection":     9.5,
    "command_injection": 9.5,
    "xxe":               8.5,
    "ssti":              8.5,
    "ssrf":              8.0,
    "path_traversal":    7.5,
    "xss":               7.0,
    "idor":              7.0,
    "open_redirect":     5.0,
    "csrf":              6.0,
    "headers":           3.0,
}

LIKELIHOOD_MAP: dict[str, float] = {
    "certain":   1.0,
    "firm":      0.7,
    "tentative": 0.4,
}

_CVSS_AV  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_CVSS_AC  = {"L": 0.77, "H": 0.44}
_CVSS_PR  = {
    "N": {"U": 0.85, "C": 0.85},
    "L": {"U": 0.62, "C": 0.68},
    "H": {"U": 0.27, "C": 0.50},
}
_CVSS_UI  = {"N": 0.85, "R": 0.62}
_CVSS_CIA = {"N": 0.00, "L": 0.22, "H": 0.56}


# ═══════════════════════════════════════════════════════════════════════════════
# ASSET FILTERING (NEW)
# ═══════════════════════════════════════════════════════════════════════════════

# Response status codes that indicate no injectable content
UNINJECTABLE_STATUS: frozenset[int] = frozenset({204, 304, 400})

# Content-types that are NEVER worth scanning for injection
SKIP_CONTENT_TYPES: frozenset[str] = frozenset({
    "text/css",
    "application/javascript",
    "text/javascript",
    "application/ecmascript",
    "text/ecmascript",
    "application/wasm",
    "application/pdf",
    "application/zip",
    "application/gzip",
    "application/x-rar-compressed",
    "application/x-7z-compressed",
    "application/x-tar",
})

# Content-type prefixes that indicate binary or media files
SKIP_CONTENT_PREFIXES: tuple[str, ...] = (
    "image/",
    "video/",
    "audio/",
    "font/",
    "application/octet-stream",
    "application/x-",  # catch application/x-yaml, application/x-protobuf, etc.
)


def is_injectable_response(
    status:        int,
    content_type:  str,
    body_len:      int = 0,
) -> bool:
    """
    Return True if this response is worth scanning for injection vulnerabilities.

    Fast filter to skip assets and non-injectable content before module invocation.
    Checks (in order of speed):
      1. Status code (204, 304 → skip)
      2. Content-Type header (CSS, JS, images → skip)
      3. Body size (< 32 bytes → likely not injectable)

    Args:
        status:       HTTP response status (200, 404, 500, etc.)
        content_type: Raw Content-Type header value
        body_len:     Length of response body in bytes (optional)

    Returns:
        True if worth scanning, False if definitely skip.

    Examples:
        is_injectable_response(200, "text/html; charset=utf-8", 5000) → True
        is_injectable_response(200, "text/css", 10000) → False
        is_injectable_response(304, "text/html", 0) → False
        is_injectable_response(200, "image/png", 50000) → False
    """
    # Fast path: skip empty/no-content responses
    if status in UNINJECTABLE_STATUS:
        return False

    # Fast path: skip by Content-Type
    ct_lower = content_type.lower()

    # Exact match (includes charset suffix)
    for skip_ct in SKIP_CONTENT_TYPES:
        if ct_lower.startswith(skip_ct):
            return False

    # Prefix match (binary types, fonts, media)
    for skip_prefix in SKIP_CONTENT_PREFIXES:
        if ct_lower.startswith(skip_prefix):
            return False

    # Very short responses (< 32 bytes) are rarely worth scanning
    # Exception: allow short responses if they're HTML/JSON/XML
    if body_len > 0 and body_len < 32:
        if not any(ct_lower.startswith(x) for x in ("text/html", "application/json", "application/xml")):
            return False

    return True


def should_scan_response(
    status:       int,
    content_type: str,
    body_len:     int = 0,
    url:          str | None = None,
) -> tuple[bool, str | None]:
    """
    Enhanced version of is_injectable_response with logging reason.

    Returns (should_scan: bool, skip_reason: str | None)

    Example:
        should, reason = should_scan_response(200, "text/css", 5000)
        if not should:
            logger.debug(f"Skipped: {reason}")
    """
    if status in UNINJECTABLE_STATUS:
        return False, f"Status {status} (no content)"

    ct_lower = content_type.lower()

    for skip_ct in SKIP_CONTENT_TYPES:
        if ct_lower.startswith(skip_ct):
            return False, f"Content-Type: {skip_ct}"

    for skip_prefix in SKIP_CONTENT_PREFIXES:
        if ct_lower.startswith(skip_prefix):
            return False, f"Content-Type prefix: {skip_prefix}"

    if body_len > 0 and body_len < 32:
        if not any(ct_lower.startswith(x) for x in ("text/html", "application/json", "application/xml")):
            return False, f"Body too short ({body_len} bytes)"

    return True, None


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  PAYLOAD LOADING
# ╚══════════════════════════════════════════════════════════════════════════════

_payload_cache: dict[str, dict[str, Any]] = {}
_payload_lock:  threading.Lock            = threading.Lock()


def load_payloads(name: str, allow_missing: bool = False) -> dict[str, Any]:
    """
    Load and cache a payload JSON file by module name (no extension).

    Uses double-checked locking so the lock is NOT held during file I/O.

    Args:
        name: Payload name without extension (e.g., "sqli" for "sqli.json")
        allow_missing: If True, return {} instead of raising on missing file

    Returns:
        Dictionary of payloads

    Raises:
        PayloadLoadError: If file not found (unless allow_missing=True) or malformed JSON
    """
    # Fast path — no lock needed for a read once populated
    if name in _payload_cache:
        return _payload_cache[name]

    path = _PAYLOAD_DIR / f"{name}.json"
    if not path.exists():
        if allow_missing:
            logger.debug("[helpers] Payload file not found (optional): %s", path)
            with _payload_lock:
                _payload_cache[name] = {}
            return {}
        raise PayloadLoadError(
            f"Payload file not found: {path}. "
            f"Expected directory: {_PAYLOAD_DIR}"
        )

    # Read outside the lock to avoid blocking sibling threads on I/O
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise PayloadLoadError(
            f"Malformed JSON in payload file '{path}': {exc}"
        ) from exc

    if not isinstance(data, dict):
        raise PayloadLoadError(
            f"Payload file '{name}' must be a JSON object at the top level."
        )

    # Write into cache under lock (another thread may have beaten us — that's fine)
    with _payload_lock:
        _payload_cache.setdefault(name, data)

    logger.debug("[helpers] Loaded payload file: %s (%d top-level keys)",
                 name, len(data))
    return _payload_cache[name]


def invalidate_payload_cache(name: str | None = None) -> None:
    """Evict one entry (by name) or flush the entire cache (name=None)."""
    with _payload_lock:
        if name is None:
            _payload_cache.clear()
            logger.debug("[helpers] Payload cache flushed.")
        else:
            _payload_cache.pop(name, None)
            logger.debug("[helpers] Payload cache evicted: %s", name)


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  URL UTILITIES
# ╚══════════════════════════════════════════════════════════════════════════════

@lru_cache(maxsize=URL_CACHE_SIZE)
def normalize_url(url: str) -> str:
    """
    ✅ OPTIMIZED: Canonical form for storage and de-duplication.
    Results cached via LRU (1024 entries).
    """
    parsed = urlparse(url.strip())
    clean  = parsed._replace(
        scheme   = parsed.scheme.lower(),
        netloc   = parsed.netloc.lower(),
        fragment = "",
    )
    result = urlunparse(clean)
    if result.endswith("/") and parsed.path not in ("/", ""):
        result = result.rstrip("/")
    return result


@lru_cache(maxsize=URL_CACHE_SIZE)
def url_key(url: str) -> str:
    """
    ✅ OPTIMIZED: Canonical key for endpoint deduplication.
    Returns scheme + host + path, all lowercase.
    Results cached via LRU.
    """
    p = urlparse(url.strip())
    return urlunparse(p._replace(
        scheme   = p.scheme.lower(),
        netloc   = p.hostname.lower() if p.hostname else p.netloc.lower(),
        path     = p.path.rstrip("/") or "/",
        params   = "",
        query    = "",
        fragment = "",
    ))


def sanitize_url(url: str) -> str:
    """Strip embedded credentials from a URL before logging or storing."""
    p = urlparse(url)
    if p.username or p.password:
        clean_netloc = p.hostname or ""
        if p.port:
            clean_netloc += f":{p.port}"
        return urlunparse(p._replace(netloc=clean_netloc))
    return url


def is_injectable_url(url: str) -> bool:
    """
    Return True only for http:// and https:// URLs.
    Rejects data:, javascript:, mailto:, ftp:, and relative URLs.
    """
    scheme = urlparse(url).scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        logger.debug("[helpers] Skipping non-HTTP URL scheme '%s': %s",
                     scheme, sanitize_url(url))
        return False
    return True


def get_query_params(url: str) -> dict[str, list[str]]:
    """Return parsed query parameters as {name: [value, ...]}."""
    return parse_qs(urlparse(url).query, keep_blank_values=True)


def inject_param(url: str, param: str, value: str) -> str:
    """
    Inject *value* into *param* in the query string of *url*.

    Contract
    ────────
    1. SQL characters (' " ` # ; etc.) in *value* are kept raw.
    2. Spaces in *value* → %20 for a valid HTTP request line.
    3. ALL EXISTING params are re-encoded normally through urlencode.
    4. Never introduces a second '?'.
    """
    if not value:
        logger.warning("[helpers] inject_param called with empty value "
                       "for param '%s' in %s", param, sanitize_url(url))

    parsed   = urlparse(url)
    existing = parse_qs(parsed.query, keep_blank_values=True)
    encoded_value = quote(value, safe=_SQL_SAFE_CHARS)
    existing[param] = [encoded_value]

    SENTINEL = "\x00INJECTED\x00"
    existing[param] = [SENTINEL]
    new_query = urlencode(existing, doseq=True)
    new_query = new_query.replace(quote(SENTINEL, safe=""), encoded_value)
    return urlunparse(parsed._replace(query=new_query))


def inject_all_params(url: str, value: str) -> list[tuple[str, str]]:
    """
    Return [(param_name, injected_url), ...] for every query param.
    """
    return [
        (name, inject_param(url, name, value))
        for name in get_query_params(url)
    ]


def inject_headers(
    base_headers: dict[str, str],
    header_name:  str,
    value:        str,
) -> dict[str, str]:
    """Return a copy of *base_headers* with *header_name* set to *value*."""
    return {**base_headers, header_name: value}


def is_same_domain(url: str, base_url: str) -> bool:
    """True when both URLs share the same netloc (host + port)."""
    return urlparse(url).netloc.lower() == urlparse(base_url).netloc.lower()


def absolute_url(base: str, href: str) -> str:
    """Resolve a potentially-relative *href* against *base*."""
    return urljoin(base, href)


def has_query_params(url: str) -> bool:
    return bool(urlparse(url).query)


def extract_path_ids(url: str) -> list[str]:
    """
    Return numeric path segments that look like resource IDs.
    /users/42/posts/7  →  ["42", "7"]
    """
    return re.findall(r"/(\d{1,12})(?=/|$)", urlparse(url).path)


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  BODY NORMALIZATION & DIFFING
# ╚══════════════════════════════════════════════════════════════════════════════

def normalize_body_tokens(body: str) -> str:
    """
    Replace dynamic tokens (CSRF, timestamps, UUIDs, nonces, ViewState…)
    with a fixed sentinel so structurally identical pages compare equal.
    """
    for pattern in _DYNAMIC_PATTERNS:
        body = pattern.sub(_DYNAMIC_SENTINEL, body)
    return body


@lru_cache(maxsize=FINGERPRINT_CACHE_SIZE)
def body_fingerprint(body: str) -> str:
    """
    ✅ OPTIMIZED: MD5 of the token-normalized response body.
    Results cached via LRU (512 entries).
    """
    return hashlib.md5(normalize_body_tokens(body).strip().encode()).hexdigest()


def structural_diff_ratio(a: str, b: str) -> float:
    """
    Fraction of content that differs between two response bodies,
    after dynamic-token normalisation.

    Uses difflib.SequenceMatcher (LCS-based).
    Returns 0.0 for identical bodies, 1.0 for completely different.
    """
    a = normalize_body_tokens(a)
    b = normalize_body_tokens(b)
    if a == b:
        return 0.0
    ratio = difflib.SequenceMatcher(None, a, b, autojunk=False).ratio()
    return round(1.0 - ratio, 4)


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  HASHING
# ╚══════════════════════════════════════════════════════════════════════════════

def md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  CVSS v3.1 SCORING
# ╚══════════════════════════════════════════════════════════════════════════════

@dataclass(frozen=True)
class CvssVector:
    """CVSS v3.1 Base Score vector."""
    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S:  str = "U"
    C:  str = "H"
    I:  str = "H"
    A:  str = "H"

    def validate(self) -> None:
        """Raise CVSSValidationError if any component is invalid."""
        valid = {
            "AV": {"N", "A", "L", "P"},
            "AC": {"L", "H"},
            "PR": {"N", "L", "H"},
            "UI": {"N", "R"},
            "S":  {"U", "C"},
            "C":  {"N", "L", "H"},
            "I":  {"N", "L", "H"},
            "A":  {"N", "L", "H"},
        }
        for field, allowed in valid.items():
            value = getattr(self, field)
            if value not in allowed:
                raise CVSSValidationError(
                    f"Invalid {field}={value}; allowed: {allowed}"
                )


CVSS_PRESETS: dict[str, CvssVector] = {
    "sql_injection":     CvssVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="H", A="H"),
    "command_injection": CvssVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
    "xxe":               CvssVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="L", A="L"),
    "ssti":              CvssVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="H", A="H"),
    "ssrf":              CvssVector(AV="N", AC="L", PR="N", UI="N", S="C", C="H", I="N", A="N"),
    "path_traversal":    CvssVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N"),
    "xss":               CvssVector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    "idor":              CvssVector(AV="N", AC="L", PR="L", UI="N", S="U", C="H", I="H", A="N"),
    "open_redirect":     CvssVector(AV="N", AC="L", PR="N", UI="R", S="C", C="L", I="L", A="N"),
    "csrf":              CvssVector(AV="N", AC="L", PR="N", UI="R", S="U", C="N", I="H", A="N"),
    "headers":           CvssVector(AV="N", AC="H", PR="N", UI="R", S="U", C="L", I="N", A="N"),
}


@lru_cache(maxsize=CVSS_CACHE_SIZE)
def compute_cvss(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s:  str = "U",
    c:  str = "H",
    i:  str = "H",
    a:  str = "H",
    vuln_type: str | None = None,
) -> float:
    """
    ✅ OPTIMIZED: Compute a CVSS v3.1 Base Score.
    Results cached via LRU (256 entries).

    Raises CVSSValidationError on invalid input.
    """
    # Use preset if provided
    if vuln_type is not None and vuln_type in CVSS_PRESETS:
        preset = CVSS_PRESETS[vuln_type]
        av, ac, pr, ui, s = preset.AV, preset.AC, preset.PR, preset.UI, preset.S
        c, i, a = preset.C, preset.I, preset.A

    # Validate inputs (catch typos early)
    try:
        vector = CvssVector(AV=av, AC=ac, PR=pr, UI=ui, S=s, C=c, I=i, A=a)
        vector.validate()
    except (ValueError, CVSSValidationError) as exc:
        logger.error("[helpers] CVSS validation failed: %s", exc)
        raise CVSSValidationError(str(exc)) from exc

    av_val = _CVSS_AV.get(av, 0.85)
    ac_val = _CVSS_AC.get(ac, 0.77)
    pr_val = _CVSS_PR.get(pr, {}).get(s, 0.85)
    ui_val = _CVSS_UI.get(ui, 0.85)
    c_val  = _CVSS_CIA.get(c, 0.56)
    i_val  = _CVSS_CIA.get(i, 0.56)
    a_val  = _CVSS_CIA.get(a, 0.56)

    iss    = 1.0 - ((1.0 - c_val) * (1.0 - i_val) * (1.0 - a_val))

    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)

    exploitability = 8.22 * av_val * ac_val * pr_val * ui_val

    if impact <= 0.0:
        return 0.0

    if s == "U":
        raw = min(impact + exploitability, 10.0)
    else:
        raw = min(1.08 * (impact + exploitability), 10.0)

    score = _round_up(raw)
    logger.debug("[helpers] CVSS v3.1 score: %.1f (vuln_type=%s)", score, vuln_type)
    return score


def compute_cvss_vector(
    vector:    CvssVector | None = None,
    vuln_type: str         | None = None,
) -> float:
    """Legacy wrapper: accepts a CvssVector object."""
    if vector is None and vuln_type is not None:
        vector = CVSS_PRESETS.get(vuln_type)
    if vector is None:
        vector = CvssVector()

    return compute_cvss(
        av=vector.AV, ac=vector.AC, pr=vector.PR, ui=vector.UI, s=vector.S,
        c=vector.C, i=vector.I, a=vector.A, vuln_type=vuln_type
    )


def _round_up(value: float) -> float:
    """CVSS spec §7.4 'round up': smallest value ≥ input with 1 decimal place."""
    return math.ceil(value * 10) / 10


def cvss_vector_string(vector: CvssVector, version: str = "3.1") -> str:
    """Produce the canonical CVSS vector string."""
    return (
        f"CVSS:{version}"
        f"/AV:{vector.AV}/AC:{vector.AC}/PR:{vector.PR}/UI:{vector.UI}"
        f"/S:{vector.S}/C:{vector.C}/I:{vector.I}/A:{vector.A}"
    )


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  SEVERITY HELPERS
# ╚══════════════════════════════════════════════════════════════════════════════

def severity_level(score: float) -> int:
    """Map CVSS score to integer level: 5=Critical 4=High 3=Medium 2=Low 1=Info."""
    if score >= 9.0: return 5
    if score >= 7.0: return 4
    if score >= 4.0: return 3
    if score >= 1.0: return 2
    return 1


def severity_label(score: float) -> str:
    """Human-readable severity label from a CVSS score."""
    for threshold, label in _SEVERITY_LABELS:
        if score >= threshold:
            return label
    return "Info"


def priority_category(priority: float) -> str:
    """Map a target priority float to a display category string."""
    if priority >= 8.0: return "Critical Priority"
    if priority >= 6.0: return "High Priority"
    if priority >= 4.0: return "Medium Priority"
    return "Low Priority"


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  CONTENT-TYPE HELPERS
# ╚══════════════════════════════════════════════════════════════════════════════

def is_xml_content(content_type: str) -> bool:
    """
    True for XML content types (not HTML).
    """
    ct = content_type.lower()
    return "xml" in ct and "html" not in ct


def is_html_content(content_type: str) -> bool:
    """True for HTML content types."""
    ct = content_type.lower()
    return "text/html" in ct or "xhtml" in ct


def is_json_content(content_type: str) -> bool:
    return "json" in content_type.lower()


def is_form_content(content_type: str) -> bool:
    return "application/x-www-form-urlencoded" in content_type.lower()


def is_multipart_content(content_type: str) -> bool:
    return "multipart/form-data" in content_type.lower()


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  MISC UTILITIES
# ╚══════════════════════════════════════════════════════════════════════════════

def truncate(text: str, limit: int = 500) -> str:
    """Truncate *text* to *limit* characters, appending '…' if cut."""
    if not isinstance(text, str):
        text = str(text)
    return text if len(text) <= limit else text[:limit] + "…"


def safe_str(value: Any, limit: int = 2048) -> str:
    """Convert any value to a UTF-8–safe string, truncated to *limit* chars."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    return truncate(str(value), limit)


def chunk(lst: list, size: int) -> list[list]:
    """Split *lst* into sub-lists of at most *size* elements."""
    return [lst[i:i + size] for i in range(0, len(lst), size)]


def flatten(nested: list[list]) -> list:
    """Flatten one level of nesting from a list of lists."""
    return [item for sub in nested for item in sub]


def deep_get(d: dict, *keys: str, default: Any = None) -> Any:
    """Safe nested dict access without chained .get() calls."""
    current = d
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key, default)
        if current is default:
            return default
    return current