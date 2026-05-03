import re
import asyncio
import aiohttp
import hashlib
import json
import logging
import math
import os
import time

from collections import deque, Counter
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Set, Tuple
from urllib.parse import urlparse

from bs4 import BeautifulSoup
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from .monitoring_fetcher import JSBrowserPool, detect_antibot, get_network_log_file, _batch_log
from .parser import detect_spa_shell, extract_links
from .robots import can_fetch

from ..repositories.monitor_pages        import upsert_monitor_page, get_monitor_page_hash
from ..repositories.monitor_snapshot     import insert_monitor_snapshot
from ..repositories.monitor_sessions     import start_monitor_session, finish_monitor_session
from ..repositories.monitor_page_changes import insert_monitor_page_change

from ..monitoring_config import (
    MAX_CONCURRENT_REQUESTS,
    MAX_PAGES,
    MAX_DEPTH,
    MONITOR_INTERVAL_MINUTES,
)

logger = logging.getLogger("webxguard.monitoring")

NETWORK_LOG_DIR   = "network_logs"
HASH_HISTORY_SIZE = 4

# ── Entropy / diff-ratio thresholds ──────────────────────────────────────────
# Pages whose normalised text has Shannon entropy below this are considered
# trivial (e.g. blank shells, pure-nav pages) and are not stored.
MIN_ENTROPY = 3.5          # bits per character

# If the normalised-text length changes by less than this fraction the
# fingerprint is NOT stored — the page hasn't changed enough to matter.
MIN_DIFF_RATIO = 0.10      # 10 %

NON_HTML_EXTENSIONS = (
    ".pdf", ".zip", ".rar", ".exe",
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".mp4", ".mp3", ".doc", ".docx", ".xls", ".xlsx",
    ".css", ".js", ".woff", ".woff2", ".ttf",
)

# ─────────────────────────────────────────────────────────────────────────────
# DYNAMIC PATTERNS — stripped before fingerprinting
# ─────────────────────────────────────────────────────────────────────────────
_DYNAMIC_PATTERNS = [
    re.compile(r'\b\d{10,13}\b'),
    re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?'),
    re.compile(r'\b\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b'),
    re.compile(r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b', re.I),
    re.compile(r'\b[0-9a-f]{32,64}\b', re.I),
    re.compile(r'\b[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b'),
    re.compile(r'\b\d{1,3}(?:[,_]\d{3})+\b'),
    re.compile(r'\b\d+(?:\.\d+)?[KkMmBb]\b'),
    re.compile(r'[?&][a-z_]+=[^\s&"\'<>]+', re.I),
    re.compile(r'\b\d{6,}\b'),
]


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def _string_entropy(text: str) -> float:
    """
    Shannon entropy (bits per character) of *text*.
    Returns 0.0 for empty / very short strings.
    """
    if not text or len(text) < 20:
        return 0.0
    counter = Counter(text)
    length  = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


def monitor_fingerprint(html: str) -> Tuple[str, str]:
    """
    Strip dynamic noise from *html*, return (sha256_hex, normalised_text).

    The normalised text is returned so callers can run entropy and
    diff-ratio checks WITHOUT re-parsing the document a second time.
    Returns ("", "") on failure or empty input.
    """
    try:
        if not html:
            return "", ""
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript", "svg", "canvas", "meta", "link"]):
            tag.decompose()
        for tag in soup.find_all(True):
            tag.attrs = {}
        text = soup.get_text(separator=" ", strip=True)
        for pattern in _DYNAMIC_PATTERNS:
            text = pattern.sub("", text)
        text = re.sub(r'\s+', ' ', text).strip()
        return hashlib.sha256(text.encode("utf-8")).hexdigest(), text
    except Exception as e:
        logger.debug(f"[Monitor] monitor_fingerprint failed: {e}")
        return "", ""


# ─────────────────────────────────────────────────────────────────────────────
# CHANGE EVENT
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class ChangeEvent:
    url:        str
    domain:     str
    old_hash:   Optional[str]
    new_hash:   str
    session_id: Optional[str]
    changed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def summary(self) -> str:
        if self.old_hash is None:
            return f"[NEW PAGE] {self.url}"
        return (
            f"[CHANGED]  {self.url}\n"
            f"           old={self.old_hash[:12]}…  new={self.new_hash[:12]}…"
        )


# ─────────────────────────────────────────────────────────────────────────────
# AIOHTTP NETWORK EVENT BUILDER
# ─────────────────────────────────────────────────────────────────────────────
def _build_aiohttp_event(
    url: str,
    method: str,
    status: int,
    response_headers: dict,
    cookies: list,
    body: str | None,
    elapsed_s: float,
) -> dict:
    """
    Build a network event dict in the same shape the passive scanner expects.
    """
    headers_lower = {k.lower(): v for k, v in response_headers.items()}

    set_cookies = [
        v for k, v in response_headers.items()
        if k.lower() == "set-cookie"
    ]

    security_headers = {
        "content-security-policy":         headers_lower.get("content-security-policy"),
        "strict-transport-security":        headers_lower.get("strict-transport-security"),
        "x-content-type-options":           headers_lower.get("x-content-type-options"),
        "x-frame-options":                   headers_lower.get("x-frame-options"),
        "referrer-policy":                   headers_lower.get("referrer-policy"),
        "permissions-policy":                headers_lower.get("permissions-policy"),
        "access-control-allow-origin":       headers_lower.get("access-control-allow-origin"),
        "access-control-allow-credentials":  headers_lower.get("access-control-allow-credentials"),
        "cache-control":                     headers_lower.get("cache-control"),
        "vary":                              headers_lower.get("vary"),
    }

    return {
        "type":             "http",
        "url":              url,
        "method":           method,
        "status_code":      status,
        "headers":          headers_lower,
        "content_type":     headers_lower.get("content-type", ""),
        "request_headers":  {},
        "request_body":     None,
        "set_cookies":      set_cookies,
        "cookies":          cookies,
        "security_headers": security_headers,
        "body":             body,
        "resource_type":    "document",
        "elapsed_s":        elapsed_s,
        "source":           "aiohttp",
        "timestamp":        datetime.now(timezone.utc).isoformat(),
    }


async def _write_aiohttp_network_log(
    network_log: str,
    page_id: int,
    url: str,
    method: str,
    status: int,
    response_headers: dict,
    body: str | None,
    elapsed_s: float,
    cookies: list,
    set_cookie_strings: list,
) -> None:
    """Write aiohttp response to JSONL in passive-scanner-compatible format."""
    http_event = _build_aiohttp_event(
        url, method, status, response_headers,
        cookies, body, elapsed_s,
    )
    
    cookies_event = {
        "type":        "cookies",
        "url":         url,
        "cookies":     cookies,
        "set_cookies": set_cookie_strings,
        "status_code": status,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }

    await asyncio.to_thread(
        _batch_log, network_log, page_id, [http_event, cookies_event]
    )


# ─────────────────────────────────────────────────────────────────────────────
# MONITORING CRAWLER
# ─────────────────────────────────────────────────────────────────────────────
class MonitoringCrawler:
    def __init__(self, start_url: str):
        self.start_url = start_url.rstrip("/")
        self.domain    = urlparse(start_url).netloc

        self._queue:            asyncio.Queue         = None
        self._seen:             Set[str]              = set()
        self._seen_lock         = asyncio.Lock()
        self._page_count:       int                   = 0
        self._page_count_lock   = asyncio.Lock()

        self._hash_cache:       Dict[str, str]        = {}
        self._hash_cache_lock   = asyncio.Lock()

        self._hash_history:     Dict[str, Deque[str]] = {}
        self._hash_history_lock = asyncio.Lock()

        # Cache normalised text *lengths* so we can compute diff-ratio
        # without re-parsing HTML; persists across cycles (same crawler instance).
        self._text_len_cache:      Dict[str, int] = {}
        self._text_len_cache_lock  = asyncio.Lock()

        self.js_pool:           Optional[JSBrowserPool] = None
        self._js_pool_failed:   bool                    = False
        self._network_log_path: Optional[str]           = None
        self._session_id:       Optional[str]           = None

        self.semaphore          = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.domain_semaphore   = asyncio.Semaphore(3)
        self._scheduler:        Optional[AsyncIOScheduler] = None

        logger.info(f"[Monitor] Target: {self.domain}")

    # ──────────────────────────────────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────────────────────────────────
    def _in_scope(self, url: str) -> bool:
        try:
            return urlparse(url).netloc == self.domain
        except Exception:
            return False

    def _is_html_url(self, url: str) -> bool:
        return not url.lower().endswith(NON_HTML_EXTENSIONS)

    async def _enqueue(self, url: str, depth: int) -> None:
        async with self._seen_lock:
            if url in self._seen:
                return
            self._seen.add(url)
        await self._queue.put((url, depth))

    # ──────────────────────────────────────────────────────────────────────
    # Hash helpers
    # ──────────────────────────────────────────────────────────────────────
    async def _get_known_hash(self, url: str) -> Optional[str]:
        async with self._hash_cache_lock:
            if url in self._hash_cache:
                return self._hash_cache[url]
        try:
            db_hash = await get_monitor_page_hash(url)
        except Exception:
            db_hash = None
        if db_hash:
            async with self._hash_cache_lock:
                self._hash_cache[url] = db_hash
        return db_hash

    async def _store_hash(self, url: str, new_hash: str) -> None:
        async with self._hash_cache_lock:
            self._hash_cache[url] = new_hash
        try:
            await upsert_monitor_page(self.domain, url, new_hash)
        except Exception as e:
            logger.error(f"[Monitor] _store_hash failed for {url}: {e}")

    async def _is_real_change(self, url: str, new_hash: str) -> bool:
        async with self._hash_history_lock:
            if url not in self._hash_history:
                self._hash_history[url] = deque(maxlen=HASH_HISTORY_SIZE)
            history = self._hash_history[url]
            is_new  = new_hash not in history
            history.append(new_hash)
            if not is_new:
                logger.debug(f"[Monitor][FlipFlop] {url} — {new_hash[:12]}… suppressed")
            return is_new

    # ──────────────────────────────────────────────────────────────────────
    # Content change detection with guards
    # ──────────────────────────────────────────────────────────────────────
    async def _check_content_change(
        self, url: str, new_hash: str, norm_text: str
    ) -> None:

        # ── Guard 1: entropy — skip low-entropy / trivial pages ────────────
        entropy = _string_entropy(norm_text)
        if entropy < MIN_ENTROPY:
            logger.debug(
                f"[Monitor][LowEntropy] {url} — "
                f"entropy={entropy:.2f} < {MIN_ENTROPY:.1f}, skipped"
            )
            return

        # ── Guard 2: diff-ratio — skip pages that barely changed ───────────
        new_len = len(norm_text)
        async with self._text_len_cache_lock:
            old_len = self._text_len_cache.get(url)

        if old_len is not None and old_len > 0:
            diff_ratio = abs(new_len - old_len) / max(old_len, new_len)
            if diff_ratio < MIN_DIFF_RATIO:
                logger.debug(
                    f"[Monitor][SmallDiff] {url} — "
                    f"diff={diff_ratio:.1%} < {MIN_DIFF_RATIO:.0%}, skipped"
                )
                # Still update the rolling length baseline
                async with self._text_len_cache_lock:
                    self._text_len_cache[url] = new_len
                return

        # Update rolling length baseline
        async with self._text_len_cache_lock:
            self._text_len_cache[url] = new_len

        # ── Guard 3: hash equality ──────────────────────────────────────────
        old_hash = await self._get_known_hash(url)

        if old_hash and old_hash == new_hash:
            logger.debug(f"[Monitor][NoChange] {url}")
            await self._is_real_change(url, new_hash)
            return

        # ── Guard 4: flip-flop suppression ─────────────────────────────────
        if not await self._is_real_change(url, new_hash):
            await self._store_hash(url, new_hash)
            return

        # ── All guards passed → record the real change ──────────────────────
        event = ChangeEvent(
            url=url, domain=self.domain,
            old_hash=old_hash, new_hash=new_hash,
            session_id=self._session_id,
        )
        logger.info(f"[Monitor] {event.summary()}")

        try:
            await insert_monitor_page_change(
                session_id=self._session_id,
                url=url,
                domain=self.domain,
                old_hash=old_hash,
                new_hash=new_hash,
            )
        except Exception as e:
            logger.error(f"[Monitor] insert_monitor_page_change failed: {e}")

        await self._store_hash(url, new_hash)

    # ──────────────────────────────────────────────────────────────────────
    # JS Pool Management
    # ──────────────────────────────────────────────────────────────────────
    async def _try_start_js_pool(self) -> bool:
        """Start JS pool once; don't retry if it failed."""
        if self._js_pool_failed:
            return False
        if self.js_pool is not None and self.js_pool.context:
            return True

        try:
            self.js_pool = JSBrowserPool()
            await self.js_pool.start()
            if not self.js_pool.context:
                raise RuntimeError("Playwright context failed to initialize")
            logger.info("[Monitor] JS browser pool started")
            return True
        except Exception as exc:
            logger.warning(
                "[Monitor] JS pool unavailable (%s) — using aiohttp-only mode.",
                exc,
            )
            self.js_pool         = None
            self._js_pool_failed = True
            return False

    # ──────────────────────────────────────────────────────────────────────
    # Worker
    # ──────────────────────────────────────────────────────────────────────
    async def _worker(self, session: aiohttp.ClientSession, stop_event: asyncio.Event):
        while not stop_event.is_set():
            try:
                url, depth = await asyncio.wait_for(
                    self._queue.get(), timeout=2.0
                )
            except asyncio.TimeoutError:
                break

            try:
                async with self._page_count_lock:
                    if self._page_count >= MAX_PAGES:
                        self._queue.task_done()
                        continue
                    self._page_count += 1

                if depth > MAX_DEPTH:
                    self._queue.task_done()
                    continue

                if not await can_fetch(url):
                    self._queue.task_done()
                    continue

                async with self.domain_semaphore, self.semaphore:
                    try:
                        async with session.head(url, allow_redirects=True) as head:
                            ct = head.headers.get("content-type", "")
                            if "text/html" not in ct and ct:
                                self._queue.task_done()
                                continue
                    except Exception:
                        pass

                    # ── Step 1: aiohttp fetch (always) ────────────────────
                    t0 = time.monotonic()
                    async with session.get(url, allow_redirects=True) as r:
                        html           = await r.text(errors="ignore")
                        resp_status    = r.status
                        resp_headers   = dict(r.headers)
                        elapsed        = time.monotonic() - t0

                    if not html:
                        raise Exception("Empty HTML")

                    logger.info(
                        f"[Monitor][{self.domain}] {url} | "
                        f"Status: {resp_status} | HTML len: {len(html)}"
                    )

                    # ── Step 2: antibot check with header context ──────────
                    # CRITICAL FIX: pass headers + status to detect_antibot
                    if detect_antibot(html, resp_status, resp_headers):
                        logger.warning(
                            f"[Monitor] Anti-bot detected on {url} "
                            f"(status={resp_status}), skipping"
                        )
                        self._queue.task_done()
                        continue

                    # ── Step 3: fingerprint & change detection ────────────
                    is_js_heavy = (
                        detect_spa_shell(html)
                        or "<script" in html
                        or '<div id="app"' in html
                    )

                    if is_js_heavy:
                        js_ready = await self._try_start_js_pool()
                        if js_ready and self.js_pool and self.js_pool.context:
                            try:
                                js_html, dyn_links, *_ = await self.js_pool.fetch_js(
                                    url, page_id=0, network_log_path=self._network_log_path
                                )
                                if js_html:
                                    fp, norm_text = monitor_fingerprint(js_html)
                                    if fp:
                                        await self._check_content_change(url, fp, norm_text)
                                    if depth < MAX_DEPTH:
                                        for link in (dyn_links or []):
                                            if self._in_scope(link) and self._is_html_url(link):
                                                await self._enqueue(link, depth + 1)
                            except Exception as js_exc:
                                logger.warning(
                                    f"[Monitor] JS fetch failed for {url}: {js_exc}"
                                )
                                # Fallback to static HTML
                                fp, norm_text = monitor_fingerprint(html)
                                if fp:
                                    await self._check_content_change(url, fp, norm_text)
                        else:
                            # JS pool failed or unavailable
                            fp, norm_text = monitor_fingerprint(html)
                            if fp:
                                await self._check_content_change(url, fp, norm_text)
                    else:
                        # Static page
                        fp, norm_text = monitor_fingerprint(html)
                        if fp:
                            await self._check_content_change(url, fp, norm_text)

                    # ── Step 4: network log ──────────────────────────────
                    # Always log aiohttp response so passive scanner has data
                    aiohttp_cookies = []
                    set_cookie_strings = [
                        v for k, v in resp_headers.items()
                        if k.lower() == "set-cookie"
                    ]

                    await _write_aiohttp_network_log(
                        network_log      = self._network_log_path,
                        page_id          = 0,
                        url              = url,
                        method           = "GET",
                        status           = resp_status,
                        response_headers = resp_headers,
                        body             = html,
                        elapsed_s        = elapsed,
                        cookies          = aiohttp_cookies,
                        set_cookie_strings = set_cookie_strings,
                    )

                    # ── Step 5: extract links ────────────────────────────
                    if depth < MAX_DEPTH:
                        for link in extract_links(url, html, [self.domain]):
                            if self._in_scope(link) and self._is_html_url(link):
                                await self._enqueue(link, depth + 1)

            except Exception as e:
                logger.error(f"[Monitor][WorkerError] {url} -> {e}")
            finally:
                self._queue.task_done()

    # ──────────────────────────────────────────────────────────────────────
    # Run once
    # ──────────────────────────────────────────────────────────────────────
    async def run_once(self):
        logger.info(f"[Monitor] ── Cycle start {datetime.now(timezone.utc).isoformat()} ──")

        self._queue      = asyncio.Queue()
        self._seen       = set()
        self._page_count = 0

        self._session_id = await start_monitor_session(self.domain)

        os.makedirs(NETWORK_LOG_DIR, exist_ok=True)
        self._network_log_path = get_network_log_file(self.domain, self._session_id)

        await self._enqueue(self.start_url, 0)

        timeout   = aiohttp.ClientTimeout(total=20, connect=5, sock_read=15)
        connector = aiohttp.TCPConnector(
            limit=MAX_CONCURRENT_REQUESTS * 2,
            limit_per_host=10,
            ssl=False,
        )

        stop_event = asyncio.Event()

        async with aiohttp.ClientSession(timeout=timeout, connector=connector) as session:
            workers = [
                asyncio.create_task(self._worker(session, stop_event))
                for _ in range(MAX_CONCURRENT_REQUESTS)
            ]
            await asyncio.gather(*workers)

        await insert_monitor_snapshot(
            domain=self.domain,
            network_log_file=self._network_log_path,
            session_id=self._session_id,
        )

        await finish_monitor_session(self._session_id)

        if self.js_pool:
            await self.js_pool.stop()
            self.js_pool = None

        logger.info(
            f"[Monitor] ── Cycle end  "
            f"session={self._session_id}  pages={self._page_count} ──"
        )

    # ──────────────────────────────────────────────────────────────────────
    # Continuous
    # ──────────────────────────────────────────────────────────────────────
    def run_continuous(self, interval_minutes: int = None, run_immediately: bool = True):
        interval = interval_minutes or MONITOR_INTERVAL_MINUTES
        loop     = asyncio.get_event_loop()

        self._scheduler = AsyncIOScheduler(event_loop=loop)
        self._scheduler.add_job(
            func=self.run_once,
            trigger=IntervalTrigger(minutes=interval),
            id="monitoring_cycle",
            max_instances=1,
            coalesce=True,
            misfire_grace_time=60,
        )
        self._scheduler.start()

        if run_immediately:
            loop.run_until_complete(self.run_once())

        try:
            loop.run_forever()
        finally:
            self._scheduler.shutdown(wait=False)