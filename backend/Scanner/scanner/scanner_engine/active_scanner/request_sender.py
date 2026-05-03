"""
request_sender.py (PRODUCTION v5 — OWASP-Style Network Intelligence)

NEW in v5 vs v4:
  User-Agent Rotation
  ────────────────────
  • Pool of 10 realistic browser User-Agents rotated per request.
  • Randomised Accept-Language and Accept headers to mimic real browsers.
  • Prevents scanner fingerprinting that causes server-side blocking.

  Adaptive Per-Host Throttling
  ─────────────────────────────
  • Tracks 429 / 5xx / timeout rates per host in _host_health dict.
  • Automatically increases delay for "unhealthy" hosts (up to 5s).
  • Automatically recovers delay when host responds cleanly again.
  • Mirrors OWASP ZAP's "Alert Threshold" behaviour.

  Smarter Exponential Backoff
  ────────────────────────────
  • True exponential: 1s → 2s → 4s with ±25% jitter.
  • Timeout errors back off separately from HTTP error codes.
  • Respects Retry-After header (up to 60s).

  Connection Pool Tuning
  ───────────────────────
  • limit_per_host reduced to 3 (was 5) to avoid triggering bot detection.
  • keepalive_timeout extended to 60s to reuse connections like a browser.
  • force_close=False to maintain session continuity.

  Timeout Configuration
  ──────────────────────
  • DEFAULT_TIMEOUT: 15s (was 12s) — gives slow legitimate servers more room.
  • CONNECT_TIMEOUT: 8s (was 5s) — avoids false-positive failures on high-latency hosts.
  • READ_TIMEOUT: 12s (was 10s) — matches ZAP's default read window.
  • TIMEOUT_TIME_BLIND: 30s (was 25s) — safe margin for time-based SQLi detection.
"""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
import time
from collections import OrderedDict, defaultdict
from typing import Any
from urllib.parse import urlparse

import aiohttp

logger = logging.getLogger("webxguard.active_scanner.request_sender")

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

DEFAULT_TIMEOUT         = 15      # ✅ v5: 12s → 15s (more room for slow hosts)
DEFAULT_CONNECT_TIMEOUT = 8       # ✅ v5: 5s → 8s (high-latency tolerance)
DEFAULT_READ_TIMEOUT    = 12      # ✅ v5: 10s → 12s (match ZAP default)
TIMEOUT_ASSET_CHECK     = 6
TIMEOUT_TIME_BLIND      = 30      # ✅ v5: 25s → 30s (safer time-based SQLi margin)

RETRY_BACKOFF_BASE      = 1.0     # ✅ v5: base for exponential: 1s, 2s, 4s
RETRY_BACKOFF_MAX       = 30.0    # Cap at 30s
DEFAULT_MAX_BODY_BYTES  = 2_000_000
DEFAULT_MAX_REDIRECTS   = 10
DEFAULT_CONCURRENCY     = 5       # ✅ v5: was 10 — reduced to avoid bot detection
MIN_REQUEST_DELAY_MS    = 300     # ✅ v5: was 25ms — 300ms base delay like ZAP

MAX_CACHE_ENTRIES   = 2_048
MAX_SLOW_HOSTS      = 512
MAX_HOST_RATE_LOCKS = 1024

# ✅ v5: Adaptive throttle thresholds
HOST_PENALTY_THRESHOLD  = 0.3    # If >30% requests fail → slow down
HOST_RECOVERY_RATE      = 0.1    # Recovery factor when host is healthy
HOST_MAX_DELAY_MS       = 5000   # Max adaptive delay cap (5s)
HOST_MIN_DELAY_MS       = 100    # Min adaptive delay floor (100ms)

DEBUG_MODE: bool = os.getenv("WEBXGUARD_DEBUG", "false").lower() == "true"
REQUEST_TIMEOUT = DEFAULT_TIMEOUT

try:
    DEFAULT_TIMEOUT = int(os.getenv("WEBXGUARD_REQUEST_TIMEOUT", DEFAULT_TIMEOUT))
    REQUEST_TIMEOUT = DEFAULT_TIMEOUT
except (ValueError, TypeError):
    pass

RETRYABLE_STATUSES: frozenset[int] = frozenset({429, 500, 502, 503, 504})

_BINARY_CT_PREFIXES: tuple[str, ...] = (
    "image/", "video/", "audio/",
    "application/octet-stream",
    "application/zip",
    "application/x-",
    "font/",
)

# ═══════════════════════════════════════════════════════════════════════════════
# ✅ v5 NEW: USER-AGENT ROTATION POOL
# ═══════════════════════════════════════════════════════════════════════════════

_USER_AGENTS: tuple[str, ...] = (
    # Chrome on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Chrome on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Firefox on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Firefox on Linux
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari on Mac
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    # Edge on Windows
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Chrome on Android
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Mobile Safari/537.36",
    # Safari on iPhone
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    # Chrome on Linux
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    # Old Chrome (mimics legacy client)
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36",
)

_ACCEPT_LANGUAGES: tuple[str, ...] = (
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.8,de;q=0.6",
    "en;q=0.9",
)


def _random_browser_headers() -> dict[str, str]:
    """Return a randomised set of realistic browser headers."""
    return {
        "User-Agent":      random.choice(_USER_AGENTS),
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": random.choice(_ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection":      "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest":  "document",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Site":  "none",
        "Sec-Fetch-User":  "?1",
    }


# ═══════════════════════════════════════════════════════════════════════════════
# ScanResponse
# ═══════════════════════════════════════════════════════════════════════════════

class ScanResponse:
    """Lightweight, pre-read wrapper around an aiohttp response."""

    __slots__ = (
        "status", "headers", "headers_lower", "body", "url",
        "elapsed", "redirected", "final_url", "truncated",
        "body_lower", "body_len",
    )

    def __init__(
        self,
        status:     int,
        headers:    dict[str, str],
        body:       str,
        url:        str,
        elapsed:    float,
        redirected: bool = False,
        final_url:  str  = "",
        truncated:  bool = False,
    ):
        self.status       = status
        self.headers      = headers
        self.url          = url
        self.elapsed      = elapsed
        self.redirected   = redirected
        self.final_url    = final_url or url
        self.truncated    = truncated
        self.body         = body
        self.body_lower   = body.lower()
        self.body_len     = len(body)
        self.headers_lower: dict[str, str] = {k.lower(): v for k, v in headers.items()}

    def __repr__(self) -> str:
        trunc = " [TRUNCATED]" if self.truncated else ""
        return (
            f"<ScanResponse {self.status} {self.url}"
            f" ({self.body_len}B){trunc} {self.elapsed:.2f}s>"
        )


# ═══════════════════════════════════════════════════════════════════════════════
# Bounded LRU dict
# ═══════════════════════════════════════════════════════════════════════════════

class _BoundedDict(OrderedDict):
    def __init__(self, maxsize: int):
        super().__init__()
        self._maxsize = maxsize

    def __setitem__(self, key: Any, value: Any) -> None:
        if key in self:
            self.move_to_end(key)
        super().__setitem__(key, value)
        if len(self) > self._maxsize:
            self.popitem(last=False)


# ═══════════════════════════════════════════════════════════════════════════════
# ✅ v5 NEW: Host Health Tracker
# ═══════════════════════════════════════════════════════════════════════════════

class _HostHealth:
    """
    Tracks success/failure rate per host and computes an adaptive delay.

    OWASP ZAP-style: backs off aggressively when a host is blocking,
    recovers gradually when it becomes healthy again.
    """

    __slots__ = ("total", "failures", "current_delay_ms")

    def __init__(self, base_delay_ms: float):
        self.total           = 0
        self.failures        = 0
        self.current_delay_ms = base_delay_ms

    def record_success(self, base_delay_ms: float) -> None:
        self.total += 1
        # Recover toward base delay on each success
        self.current_delay_ms = max(
            base_delay_ms,
            self.current_delay_ms * (1.0 - HOST_RECOVERY_RATE),
        )

    def record_failure(self) -> None:
        self.total    += 1
        self.failures += 1
        failure_rate = self.failures / max(self.total, 1)
        if failure_rate >= HOST_PENALTY_THRESHOLD:
            # Penalise: double the delay, capped at HOST_MAX_DELAY_MS
            self.current_delay_ms = min(
                self.current_delay_ms * 2.0,
                HOST_MAX_DELAY_MS,
            )
            logger.debug(
                "[HostHealth] Penalty applied (failure_rate=%.0f%%) → delay=%.0fms",
                failure_rate * 100, self.current_delay_ms,
            )

    @property
    def delay_s(self) -> float:
        # Add ±20% jitter to spread out burst requests
        jitter = random.uniform(0.8, 1.2)
        return (self.current_delay_ms * jitter) / 1000.0


# ═══════════════════════════════════════════════════════════════════════════════
# RequestSender
# ═══════════════════════════════════════════════════════════════════════════════

class RequestSender:
    """
    Async HTTP client with OWASP-style network intelligence.

    v5 additions over v4:
    • User-Agent rotation per request
    • Adaptive per-host throttling (_HostHealth)
    • True exponential backoff: 1s → 2s → 4s with jitter
    • Reduced default concurrency (5) and per-host connection limit (3)
    """

    def __init__(
        self,
        timeout:          int   = DEFAULT_TIMEOUT,
        connect_timeout:  int   = DEFAULT_CONNECT_TIMEOUT,
        read_timeout:     int   = DEFAULT_READ_TIMEOUT,
        max_retries:      int   = 3,            # ✅ v5: 2 → 3
        verify_ssl:       bool  = True,
        follow_redirects: bool  = True,
        max_redirects:    int   = DEFAULT_MAX_REDIRECTS,
        headers:          dict  | None = None,
        max_body_bytes:   int   = DEFAULT_MAX_BODY_BYTES,
        concurrency:      int   = DEFAULT_CONCURRENCY,
        min_delay_ms:     float = MIN_REQUEST_DELAY_MS,
        cache_get:        bool  = True,
        retry_jitter:     bool  = True,
        rotate_agents:    bool  = True,          # ✅ v5: NEW
    ):
        self.timeout          = timeout
        self.connect_timeout  = connect_timeout
        self.read_timeout     = read_timeout
        self.max_retries      = max_retries
        self.verify_ssl       = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects    = max_redirects
        self.max_body_bytes   = max_body_bytes
        self.concurrency      = concurrency
        self.min_delay_ms     = min_delay_ms
        self.cache_get        = cache_get
        self.retry_jitter     = retry_jitter
        self.rotate_agents    = rotate_agents

        # Static override headers (caller-supplied) merged on top of browser headers
        self._static_headers: dict[str, str] = headers or {}

        self._session:     aiohttp.ClientSession | None = None
        self._get_cache:   _BoundedDict = _BoundedDict(MAX_CACHE_ENTRIES)
        self._slow_hosts:  _BoundedDict = _BoundedDict(MAX_SLOW_HOSTS)

        # ✅ v5: Per-host health tracking (replaces raw rate lock dict)
        self._host_health:      dict[str, _HostHealth] = {}
        self._host_rate_locks:  dict[str, asyncio.Lock] = {}
        self._host_last_sent:   dict[str, float]        = {}
        self._max_host_locks    = MAX_HOST_RATE_LOCKS

    # ── Lifecycle ──────────────────────────────────────────────────────────────

    async def start(self) -> None:
        ssl_ctx = False if not self.verify_ssl else None

        connector = aiohttp.TCPConnector(
            ssl                   = ssl_ctx,
            limit                 = self.concurrency,
            limit_per_host        = 3,           # ✅ v5: 5 → 3 (less aggressive)
            ttl_dns_cache         = 300,
            enable_cleanup_closed = True,
            force_close           = False,
            use_dns_cache         = True,
            keepalive_timeout     = 60,          # ✅ v5: 30 → 60s (browser-like)
        )

        session_timeout = aiohttp.ClientTimeout(
            total        = self.timeout * (self.max_retries + 1) * 2,
            connect      = self.connect_timeout,
            sock_read    = self.read_timeout,
            sock_connect = self.connect_timeout,
        )

        self._session = aiohttp.ClientSession(connector=connector, timeout=session_timeout)

        logger.info(
            "[Sender] v5 started — timeout=%ds connect=%ds retries=%d "
            "concurrency=%d delay=%.0fms rotate_agents=%s",
            self.timeout, self.connect_timeout, self.max_retries,
            self.concurrency, self.min_delay_ms, self.rotate_agents,
        )

    async def close(self) -> None:
        if self._session:
            await self._session.close()
            self._session = None
        self._get_cache.clear()
        self._slow_hosts.clear()
        self._host_health.clear()
        self._host_rate_locks.clear()
        self._host_last_sent.clear()

    async def __aenter__(self) -> "RequestSender":
        await self.start()
        return self

    async def __aexit__(self, *_: Any) -> None:
        await self.close()

    # ── Public API ─────────────────────────────────────────────────────────────

    async def get(
        self,
        url:              str,
        params:           dict | None = None,
        follow_redirects: bool | None = None,
        extra_headers:    dict | None = None,
        use_cache:        bool        = False,
    ) -> ScanResponse | None:
        if use_cache and self.cache_get:
            key = _cache_key("GET", url, params, extra_headers)
            cached = self._get_cache.get(key)
            if cached is not None:
                return cached

        resp = await self._send("GET", url, params=params,
                                follow_redirects=follow_redirects,
                                extra_headers=extra_headers)

        if use_cache and self.cache_get and resp is not None:
            self._get_cache[_cache_key("GET", url, params, extra_headers)] = resp

        return resp

    async def post(
        self,
        url:              str,
        data:             dict | None = None,
        json:        Any  | None = None,
        extra_headers:    dict | None = None,
        follow_redirects: bool | None = None,
    ) -> ScanResponse | None:
        return await self._send("POST", url, data=data, json=json,
                                extra_headers=extra_headers,
                                follow_redirects=follow_redirects)

    async def send_raw(
        self,
        method:           str,
        url:              str,
        data:             Any  | None = None,
        json:             Any  | None = None,
        params:           dict | None = None,
        extra_headers:    dict | None = None,
        follow_redirects: bool | None = None,
    ) -> ScanResponse | None:
        return await self._send(method, url, data=data, json=json,
                                params=params, extra_headers=extra_headers,
                                follow_redirects=follow_redirects)

    async def get_headers_only(
        self,
        url: str,
        timeout_override: float | None = None,
    ) -> dict[str, str] | None:
        if not self._session:
            return None

        host = urlparse(url).netloc.lower()
        timeout_to_use = timeout_override or TIMEOUT_ASSET_CHECK
        per_request_timeout = aiohttp.ClientTimeout(total=timeout_to_use)

        try:
            await self._rate_limit(host)
            async with self._session.head(
                url,
                headers         = self._build_headers(),
                timeout         = per_request_timeout,
                allow_redirects = False,
            ) as resp:
                return dict(resp.headers)
        except Exception as exc:
            if DEBUG_MODE:
                logger.debug("[Sender] get_headers_only failed for %s: %s", url, exc)
            return None

    # ── Internal ───────────────────────────────────────────────────────────────

    def _build_headers(self, extra: dict | None = None) -> dict[str, str]:
        """
        ✅ v5 NEW: Build per-request headers with rotated User-Agent.

        Merge order (last wins):
          base browser headers → static overrides → per-request extras
        """
        headers = _random_browser_headers() if self.rotate_agents else {
            "User-Agent":      "WebXGuardBot/1.0 (Active Scanner)",
            "Accept":          "text/html,application/xhtml+xml,application/json,*/*",
            "Accept-Encoding": "gzip, deflate",
        }
        headers.update(self._static_headers)
        if extra:
            headers.update(extra)
        return headers

    def _get_host_health(self, host: str) -> _HostHealth:
        """Lazily create a _HostHealth entry for a host."""
        if host not in self._host_health:
            # Evict if at capacity
            if len(self._host_health) >= self._max_host_locks:
                oldest = next(iter(self._host_health))
                del self._host_health[oldest]
            self._host_health[host] = _HostHealth(self.min_delay_ms)
        return self._host_health[host]

    async def _rate_limit(self, host: str) -> None:
        """
        ✅ v5: Adaptive per-host rate limiting driven by _HostHealth.

        Replaces the flat min_delay_ms with a dynamic delay that increases
        when a host is blocking us and recovers when it's healthy.
        """
        if self.min_delay_ms <= 0:
            return

        # Evict rate lock if at capacity
        if len(self._host_rate_locks) >= self._max_host_locks:
            oldest = next(iter(self._host_rate_locks))
            del self._host_rate_locks[oldest]
            self._host_last_sent.pop(oldest, None)

        if host not in self._host_rate_locks:
            self._host_rate_locks[host] = asyncio.Lock()
            self._host_last_sent[host]  = 0.0

        health = self._get_host_health(host)

        async with self._host_rate_locks[host]:
            desired_delay_s = health.delay_s
            elapsed_s = time.monotonic() - self._host_last_sent[host]
            gap_s     = desired_delay_s - elapsed_s
            if gap_s > 0:
                await asyncio.sleep(gap_s)
            self._host_last_sent[host] = time.monotonic()

    async def _read_body(self, resp: aiohttp.ClientResponse) -> tuple[str, bool]:
        ct = resp.headers.get("Content-Type", "").lower()
        if any(ct.startswith(bt) for bt in _BINARY_CT_PREFIXES):
            return "[binary content skipped]", False

        raw       = await resp.content.read(self.max_body_bytes + 1)
        truncated = len(raw) > self.max_body_bytes
        if truncated:
            raw = raw[:self.max_body_bytes]

        encoding = resp.charset or "utf-8"
        return raw.decode(encoding, errors="replace"), truncated

    def _base_timeout_for_host(self, host: str) -> float:
        if host in self._slow_hosts:
            multiplier = min(self._slow_hosts[host], 1.8)
            return min(self.timeout * multiplier, self.timeout * 2)
        return float(self.timeout)

    def _backoff(self, attempt: int, retry_after: int | None = None) -> float:
        """
        ✅ v5: True exponential backoff — 1s, 2s, 4s (not 2^attempt from 0).

        OWASP ZAP uses similar progressive delays to avoid hammering
        servers that are already under stress.
        """
        if retry_after is not None:
            return min(float(retry_after), 60.0)
        # True exponential starting at 1s: 1 * 2^attempt
        delay = RETRY_BACKOFF_BASE * (2 ** attempt)
        if self.retry_jitter:
            delay *= random.uniform(0.75, 1.25)
        return min(delay, RETRY_BACKOFF_MAX)

    async def _send(
        self,
        method:           str,
        url:              str,
        data:             Any  | None = None,
        json:             Any  | None = None,
        params:           dict | None = None,
        extra_headers:    dict | None = None,
        follow_redirects: bool | None = None,
    ) -> ScanResponse | None:
        if not self._session:
            raise RuntimeError(
                "RequestSender not started — call `await sender.start()` first."
            )

        should_follow = (follow_redirects
                         if follow_redirects is not None
                         else self.follow_redirects)

        host   = urlparse(url).netloc.lower()
        health = self._get_host_health(host)
        base_t = self._base_timeout_for_host(host)
        per_request_timeout = aiohttp.ClientTimeout(
            total        = base_t + self.connect_timeout,
            connect      = self.connect_timeout,
            sock_read    = min(self.read_timeout, base_t),
            sock_connect = self.connect_timeout,
        )

        last_error: BaseException | None = None

        for attempt in range(self.max_retries + 1):
            await self._rate_limit(host)

            # ✅ v5: Fresh browser-like headers on every attempt
            headers = self._build_headers(extra_headers)

            try:
                t0 = time.monotonic()
                async with self._session.request(
                    method,
                    url,
                    params          = params,
                    data            = data,
                    json            = json,
                    headers         = headers,
                    allow_redirects = should_follow,
                    max_redirects   = self.max_redirects,
                    timeout         = per_request_timeout,
                ) as resp:
                    elapsed     = time.monotonic() - t0

                    # Asset filter — check Content-Type before reading body
                    content_type = resp.headers.get("Content-Type", "")
                    from .utils.helpers import is_injectable_response

                    try:
                        content_length = int(resp.headers.get("Content-Length", "0"))
                    except (ValueError, TypeError):
                        content_length = 0

                    if not is_injectable_response(resp.status, content_type, content_length):
                        body = "[asset/non-injectable skipped]"
                        trunc = False
                    else:
                        body, trunc = await self._read_body(resp)

                    final_url = str(resp.url)

                    # Track slow hosts
                    if elapsed > self.timeout * 0.8:
                        slowdown = elapsed / self.timeout
                        prev     = self._slow_hosts.get(host, 1.0)
                        self._slow_hosts[host] = (prev + slowdown) / 2

                    # 429 — respect Retry-After, record failure
                    if resp.status == 429 and attempt < self.max_retries:
                        health.record_failure()
                        ra   = resp.headers.get("Retry-After")
                        wait = self._backoff(attempt, int(ra) if ra and ra.isdigit() else None)
                        logger.warning(
                            "[Sender] 429 rate-limited — backing off %.1fs (attempt %d) %s",
                            wait, attempt + 1, url,
                        )
                        await asyncio.sleep(wait)
                        continue

                    # 5xx — record failure and retry with backoff
                    if resp.status in (500, 502, 503, 504) and attempt < self.max_retries:
                        health.record_failure()
                        wait = self._backoff(attempt)
                        logger.debug(
                            "[Sender] %d server error — retry in %.1fs (attempt %d) %s",
                            resp.status, wait, attempt + 1, url,
                        )
                        await asyncio.sleep(wait)
                        continue

                    # ✅ v5: Record success → helps health recovery
                    health.record_success(self.min_delay_ms)

                    return ScanResponse(
                        status     = resp.status,
                        headers    = dict(resp.headers),
                        body       = body,
                        url        = url,
                        elapsed    = elapsed,
                        redirected = final_url != url,
                        final_url  = final_url,
                        truncated  = trunc,
                    )

            except asyncio.TimeoutError as exc:
                last_error = exc
                health.record_failure()    # ✅ v5: penalise host on timeout
                if attempt < self.max_retries:
                    wait = self._backoff(attempt)
                    logger.warning(
                        "[Sender] Timeout — backing off %.1fs (attempt %d/%d) %s %s",
                        wait, attempt + 1, self.max_retries + 1, method, url,
                    )
                    await asyncio.sleep(wait)

            except aiohttp.TooManyRedirects:
                logger.warning("[Sender] Too many redirects (%d): %s",
                               self.max_redirects, url)
                return None

            except (
                aiohttp.ServerDisconnectedError,
                aiohttp.ServerTimeoutError,
            ) as exc:
                last_error = exc
                health.record_failure()    # ✅ v5
                if attempt < self.max_retries:
                    wait = self._backoff(attempt)
                    logger.debug(
                        "[Sender] Server dropped connection (%s) — retry %.1fs (attempt %d) %s",
                        type(exc).__name__, wait, attempt + 1, url,
                    )
                    await asyncio.sleep(wait)

            except aiohttp.ClientConnectorError as exc:
                last_error = exc
                health.record_failure()    # ✅ v5
                if attempt < self.max_retries:
                    wait = self._backoff(attempt)
                    logger.debug("[Sender] ConnectorError — retry %.1fs: %s", wait, exc)
                    await asyncio.sleep(wait)

            except aiohttp.ClientResponseError as exc:
                last_error = exc
                if exc.status in RETRYABLE_STATUSES and attempt < self.max_retries:
                    health.record_failure()
                    await asyncio.sleep(self._backoff(attempt))

            except aiohttp.ClientError as exc:
                last_error = exc
                if attempt < self.max_retries:
                    await asyncio.sleep(self._backoff(attempt))

            except Exception as exc:
                last_error = exc
                logger.debug("[Sender] Unexpected error (attempt %d) %s %s: %s",
                             attempt + 1, method, url, exc)
                if attempt < self.max_retries:
                    await asyncio.sleep(self._backoff(attempt))

        logger.warning(
            "[Sender] All %d attempts exhausted — host delay now %.0fms: %s %s — %s",
            self.max_retries + 1,
            self._get_host_health(host).current_delay_ms,
            method, url, last_error,
        )
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _cache_key(
    method:        str,
    url:           str,
    params:        dict | None,
    extra_headers: dict | None,
) -> str:
    raw = json.dumps(
        {
            "method":  method.upper(),
            "url":     url,
            "params":  sorted((params or {}).items()),
            "headers": sorted((extra_headers or {}).items()),
        },
        sort_keys=True,
    ).encode()
    return hashlib.sha256(raw).hexdigest()[:16]