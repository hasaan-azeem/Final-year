"""
ai_engine/extractor.py
======================
Parse a WebXGuard network-log JSONL file and return a typed feature vector.

Feature set (21 dimensions)
----------------------------
request_count          – total requests
unique_urls            – distinct URLs seen
get_ratio              – GET  / total
post_ratio             – POST / total
error_rate             – (4xx + 5xx) / total
rate_403               – 403 / total
rate_500               – 5xx / total
avg_response_size      – mean Content-Length (bytes)
content_type_entropy   – Shannon entropy of Content-Type distribution
resource_type_entropy  – Shannon entropy of resource_type distribution
cookie_count           – total Set-Cookie occurrences
unique_cookie_names    – distinct cookie names
missing_csp_ratio      – requests lacking Content-Security-Policy
missing_hsts_ratio     – requests lacking Strict-Transport-Security
missing_xfo_ratio      – requests lacking X-Frame-Options
suspicious_path_count  – URLs matching admin/debug/config/backup paths
sqli_pattern_count     – URLs matching SQL injection patterns
xss_pattern_count      – URLs matching XSS payloads
request_burstiness     – coefficient of variation of inter-request timestamps
user_agent_count       – distinct User-Agent values
url_entropy            – Shannon entropy of URL character distribution
"""
from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("webxguard.ai_engine.extractor")

# ---------------------------------------------------------------------------
# Compiled patterns
# ---------------------------------------------------------------------------

_SUSPICIOUS_PATH_RE = re.compile(
    r"/(admin|administrator|wp-admin|phpmyadmin|"
    r"config|backup|\.git|\.env|debug|console|"
    r"shell|cmd|exec|eval|passwd|shadow|etc)",
    re.IGNORECASE,
)

_SQLI_RE = re.compile(
    r"(\bunion\b.*\bselect\b|"
    r"\bselect\b.*\bfrom\b|"
    r"'\s*(or|and)\s*'?\d|"
    r"--\s*$|"
    r";\s*drop\s+table|"
    r"xp_cmdshell|"
    r"information_schema)",
    re.IGNORECASE,
)

_XSS_RE = re.compile(
    r"(<script|javascript:|"
    r"onerror\s*=|onload\s*=|"
    r"<img[^>]*src\s*=\s*[\"']?\s*javascript|"
    r"alert\s*\(|"
    r"document\.cookie|"
    r"eval\s*\()",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Feature name registry  (order is the ML vector order — never change it)
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    "request_count",
    "unique_urls",
    "get_ratio",
    "post_ratio",
    "error_rate",
    "rate_403",
    "rate_500",
    "avg_response_size",
    "content_type_entropy",
    "resource_type_entropy",
    "cookie_count",
    "unique_cookie_names",
    "missing_csp_ratio",
    "missing_hsts_ratio",
    "missing_xfo_ratio",
    "suspicious_path_count",
    "sqli_pattern_count",
    "xss_pattern_count",
    "request_burstiness",
    "user_agent_count",
    "url_entropy",
]


@dataclass
class SnapshotFeatures:
    """Typed container for one snapshot's 21-dim feature vector."""

    request_count:          int   = 0
    unique_urls:            int   = 0
    get_ratio:              float = 0.0
    post_ratio:             float = 0.0
    error_rate:             float = 0.0
    rate_403:               float = 0.0
    rate_500:               float = 0.0
    avg_response_size:      float = 0.0
    content_type_entropy:   float = 0.0
    resource_type_entropy:  float = 0.0
    cookie_count:           int   = 0
    unique_cookie_names:    int   = 0
    missing_csp_ratio:      float = 0.0
    missing_hsts_ratio:     float = 0.0
    missing_xfo_ratio:      float = 0.0
    suspicious_path_count:  int   = 0
    sqli_pattern_count:     int   = 0
    xss_pattern_count:      int   = 0
    request_burstiness:     float = 0.0
    user_agent_count:       int   = 0
    url_entropy:            float = 0.0

    # Metadata — NOT part of the ML vector
    raw_entry_count: int = field(default=0, repr=False)
    parse_errors:    int = field(default=0, repr=False)

    def to_vector(self) -> list[float]:
        return [float(getattr(self, name)) for name in FEATURE_NAMES]

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in FEATURE_NAMES}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _shannon_entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in counter.values():
        if count > 0:
            p = count / total
            entropy -= p * math.log(p)
    return round(entropy, 6)


def _url_char_entropy(urls: list[str]) -> float:
    if not urls:
        return 0.0
    return _shannon_entropy(Counter("".join(urls)))


def _coeff_of_variation(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    mean = sum(values) / len(values)
    if mean < 1e-9:
        return 0.0
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return round(math.sqrt(variance) / mean, 6)


def _content_length(headers: dict) -> float | None:
    for key, value in headers.items():
        if key.lower() == "content-length":
            try:
                return float(value)
            except (ValueError, TypeError):
                return None
    return None


def _content_type(headers: dict) -> str:
    for key, value in headers.items():
        if key.lower() == "content-type":
            return str(value).split(";")[0].strip().lower() or "unknown"
    return "unknown"


def _parse_timestamps(entries: list[dict]) -> list[float]:
    import datetime as _dt
    times: list[float] = []
    for i, entry in enumerate(entries):
        raw = entry.get("timestamp")
        if raw is None:
            times.append(float(i))
            continue
        try:
            if isinstance(raw, (int, float)):
                times.append(float(raw))
            else:
                parsed = _dt.datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
                times.append(parsed.timestamp())
        except Exception:
            times.append(float(i))
    return sorted(times)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_features(jsonl_path: str | Path) -> SnapshotFeatures:
    """
    Parse *jsonl_path* and return a :class:`SnapshotFeatures` instance.
    Never raises — returns a zero-vector on failure.
    """
    path = Path(jsonl_path)
    features = SnapshotFeatures()

    if not path.exists():
        logger.error("[Extractor] File not found: %s", path)
        features.parse_errors = 1
        return features

    entries: list[dict] = []
    parse_errors = 0

    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        entries.append(obj)
                except json.JSONDecodeError:
                    parse_errors += 1
                    logger.debug("[Extractor] JSON error line %d in %s", lineno, path)
    except OSError as exc:
        logger.error("[Extractor] Cannot open %s: %s", path, exc)
        features.parse_errors = 1
        return features

    features.raw_entry_count = len(entries) + parse_errors
    features.parse_errors    = parse_errors

    if not entries:
        logger.warning("[Extractor] No valid JSON entries in %s", path)
        return features

    total = len(entries)
    features.request_count = total

    urls:           list[str]    = []
    methods:        Counter[str] = Counter()
    status_codes:   list[int]    = []
    response_sizes: list[float]  = []
    content_types:  Counter[str] = Counter()
    resource_types: Counter[str] = Counter()
    cookie_names:   set[str]     = set()
    cookie_total                 = 0
    missing_csp = missing_hsts = missing_xfo = 0
    susp_paths = sqli_hits = xss_hits = 0
    user_agents: set[str] = set()

    for entry in entries:
        url    = str(entry.get("url", ""))
        method = str(entry.get("method", "GET")).upper()
        status = entry.get("status_code")

        urls.append(url)
        methods[method] += 1

        if isinstance(status, int):
            status_codes.append(status)

        headers: dict = entry.get("headers", {}) or {}
        size = _content_length(headers)
        if size is not None:
            response_sizes.append(size)

        content_types[_content_type(headers)] += 1
        resource_types[str(entry.get("resource_type", "other")).lower()] += 1

        cookies = entry.get("cookies") or []
        if isinstance(cookies, list):
            for ck in cookies:
                if isinstance(ck, dict):
                    name = ck.get("name") or ck.get("key") or ""
                    if name:
                        cookie_names.add(str(name))
                        cookie_total += 1
                elif isinstance(ck, str) and ck:
                    cookie_names.add(ck.split("=")[0].strip())
                    cookie_total += 1

        sec: dict = entry.get("security_headers", {}) or {}
        if not (sec.get("Content-Security-Policy") or sec.get("content-security-policy")):
            missing_csp += 1
        if not (sec.get("Strict-Transport-Security") or sec.get("strict-transport-security")):
            missing_hsts += 1
        if not (sec.get("X-Frame-Options") or sec.get("x-frame-options")):
            missing_xfo += 1

        if _SUSPICIOUS_PATH_RE.search(url):
            susp_paths += 1
        if _SQLI_RE.search(url):
            sqli_hits += 1
        if _XSS_RE.search(url):
            xss_hits += 1

        req_hdrs: dict = entry.get("request_headers", {}) or {}
        for key, value in req_hdrs.items():
            if key.lower() == "user-agent" and value:
                user_agents.add(str(value))

    features.unique_urls = len(set(urls))
    features.get_ratio   = round(methods.get("GET",  0) / total, 6)
    features.post_ratio  = round(methods.get("POST", 0) / total, 6)

    if status_codes:
        n = len(status_codes)
        features.error_rate = round(sum(1 for s in status_codes if s >= 400) / n, 6)
        features.rate_403   = round(sum(1 for s in status_codes if s == 403) / n, 6)
        features.rate_500   = round(sum(1 for s in status_codes if s >= 500) / n, 6)

    features.avg_response_size = (
        round(sum(response_sizes) / len(response_sizes), 2) if response_sizes else 0.0
    )

    features.content_type_entropy  = _shannon_entropy(content_types)
    features.resource_type_entropy = _shannon_entropy(resource_types)
    features.cookie_count          = cookie_total
    features.unique_cookie_names   = len(cookie_names)
    features.missing_csp_ratio     = round(missing_csp  / total, 6)
    features.missing_hsts_ratio    = round(missing_hsts / total, 6)
    features.missing_xfo_ratio     = round(missing_xfo  / total, 6)
    features.suspicious_path_count = susp_paths
    features.sqli_pattern_count    = sqli_hits
    features.xss_pattern_count     = xss_hits

    timestamps = _parse_timestamps(entries)
    inter_arrs = [
        timestamps[i + 1] - timestamps[i]
        for i in range(len(timestamps) - 1)
        if timestamps[i + 1] - timestamps[i] >= 0
    ]
    features.request_burstiness = _coeff_of_variation(inter_arrs)
    features.user_agent_count   = len(user_agents)
    features.url_entropy        = _url_char_entropy(urls)

    logger.debug(
        "[Extractor] %s → %d requests, %d unique URLs, %d parse errors",
        path.name, features.request_count, features.unique_urls, features.parse_errors,
    )
    return features