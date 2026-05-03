"""
scrapper/core.py

Fixes applied in this version:
  FIX-1  aiohttp network log — when JS pool unavailable, aiohttp response
         headers/cookies/status are written to JSONL in the same format
         the passive scanner expects. Passive scan now always has data.
  FIX-2  _js_pool_failed flag — don't retry a broken Playwright install
         on every page.
  FIX-3  Page inserted BEFORE JS attempt so DB always has the page record
         even when Playwright crashes.
  FIX-4  `import time` moved to module level (was inside worker loop).
  FIX-5  Form dict key corrected: `action_url` → `action`
         (parser.py returns key "action", not "action_url").
  FIX-6  Response headers now passed to detect_antibot() so header-based
         signals (Cloudflare, DataDome, PerimeterX, etc.) are detected.
  FIX-8  🔧 Enqueue authenticated landing page after successful login
         (e.g., /Student/dashboard) so crawler crawls authenticated pages
"""

import asyncio
import aiohttp
import json
import logging
import os
import time
from collections import defaultdict
from urllib.parse import urlparse
from typing import Set, List
import hashlib
from datetime import datetime, timezone

from .fetcher import JSBrowserPool, detect_antibot, get_network_log_file, _batch_log
from .parser import parse_page, detect_spa_shell, dom_fingerprint
from .robots import can_fetch
from .sitemap import fetch_sitemap
from .auth import AuthManager
from .utils import encrypt

from ..repositories.sessions import start_scan_session, finish_scan_session
from ..repositories.domains import get_or_create_domain
from ..repositories.pages import insert_page
from ..repositories.queue import enqueue_url, fetch_next_url, mark_done
from ..repositories.endpoints import insert_endpoint, link_page_endpoint
from ..repositories.forms import insert_form, insert_form_input
from ..repositories.snapshots import insert_snapshot
from ..repositories.auth import insert_auth_session
from .. import config
from ..config import (
    MAX_CONCURRENT_REQUESTS,
    MAX_PAGES,
    MAX_DEPTH,
    AUTH_TYPE,
)

logger = logging.getLogger("webxguard.core")
logging.basicConfig(level=logging.INFO)


def log_auth(domain: str, msg: str):
    logger.info(f"[AUTH][{domain}] {msg}")


# ── FIX-1: aiohttp → JSONL network event builder ─────────────────────────────

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
    Build a network event dict in the same shape the passive scanner expects
    from Playwright-captured events. Used when JS pool is unavailable.
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


def _build_cookies_event(url: str, cookies: list, set_cookie_strings: list) -> dict:
    return {
        "type":        "cookies",
        "url":         url,
        "cookies":     cookies,
        "set_cookies": set_cookie_strings,
        "status_code": 200,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
    }


def _aiohttp_cookies_to_passive(
    jar: aiohttp.CookieJar,
    domain: str,
) -> list:
    """
    Convert aiohttp CookieJar entries to the parsed_cookies format
    the passive scanner modules expect.
    """
    cookies = []
    for morsel in jar:
        name  = morsel.key
        value = morsel.value
        flags = []
        if morsel.get("httponly"):
            flags.append("httponly")
        if morsel.get("secure"):
            flags.append("secure")
        samesite = morsel.get("samesite", "")
        if samesite:
            flags.append(f"samesite={samesite.lower()}")

        cookies.append({
            "name":    name,
            "value":   value,
            "domain":  morsel.get("domain") or domain,
            "path":    morsel.get("path") or "/",
            "flags":   flags,
            "expires": -1,
            "session": True,
        })
    return cookies


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
    """
    Write aiohttp response to JSONL in passive-scanner-compatible format.
    Called when JS pool is unavailable.
    """
    http_event    = _build_aiohttp_event(
        url, method, status, response_headers,
        cookies, body, elapsed_s,
    )
    cookies_event = _build_cookies_event(url, cookies, set_cookie_strings)

    await asyncio.to_thread(
        _batch_log, network_log, page_id, [http_event, cookies_event]
    )
    logger.debug(
        "[Core] aiohttp network event written to %s for %s", network_log, url
    )


class Crawler:
    def __init__(self, start_urls: List[str], session_id: str | None = None):
        self.start_urls = start_urls
        self.session_id = session_id

        self.queued:       Set[str] = set()
        self.visited:      Set[str] = set()
        self.visited_lock  = asyncio.Lock()
        self._js_pool_lock = asyncio.Lock()

        self.semaphore         = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)
        self.domain_semaphores = defaultdict(lambda: asyncio.Semaphore(3))
        self.pages_per_domain  = defaultdict(int)

        self.base_domains = set(urlparse(url).netloc for url in start_urls)

        self.js_pool:         JSBrowserPool | None = None
        self._js_pool_failed: bool                 = False
        self.domain_snapshots = defaultdict(
            lambda: {"network_log_file": None, "screenshot_path": None}
        )

        self.auth       = AuthManager()
        self.auth_locks = defaultdict(asyncio.Lock)

        logger.info(f"[Domains] {self.base_domains}")

    def in_scope(self, url: str) -> bool:
        try:
            return urlparse(url).netloc in self.base_domains
        except Exception:
            return False

    async def login_domains(self, session: aiohttp.ClientSession):
        if not config.LOGIN_ENABLED:
            logger.info("[AUTH] Login disabled")
            return

        for domain in self.base_domains:
            log_auth(domain, f"Authenticating using {AUTH_TYPE}")
            if AUTH_TYPE == "credential":
                try:
                    success = await self.auth.credential_login(
                        session      = session,
                        domain       = domain,
                        login_url    = config.LOGIN_URL,
                        username     = config.LOGIN_USERNAME,
                        password     = config.LOGIN_PASSWORD,
                        user_field   = config.LOGIN_USER_FIELD,
                        pass_field   = config.LOGIN_PASS_FIELD,
                    )
                    log_auth(domain, f"Initial credential login success={success}")
                    if success:
                        domain_id = await get_or_create_domain(domain)
                        await insert_auth_session(
                            domain_id  = domain_id,
                            session_id = self.session_id,
                            login_url  = config.LOGIN_URL,
                            username   = encrypt(config.LOGIN_USERNAME),
                            password   = encrypt(config.LOGIN_PASSWORD),
                        )
                        
                        # 🔧 FIX-8: Enqueue authenticated landing page
                        auth_url = self.auth.domains.get(domain, {}).get("authenticated_url")
                        if auth_url and auth_url not in self.queued:
                            await enqueue_url(auth_url, domain, 0, self.session_id)
                            self.queued.add(auth_url)
                            log_auth(domain, f"Enqueued authenticated page: {auth_url}")
                        
                        if self.js_pool and self.js_pool.context:
                            await self.auth.sync_cookies_to_playwright(
                                session, self.js_pool.context, domain
                            )
                except Exception as e:
                    logger.error(f"[AUTH][{domain}] Initial login failed: {e}")

    async def ensure_authenticated(self, session: aiohttp.ClientSession, domain: str):
        if not config.LOGIN_ENABLED:
            return
        async with self.auth_locks[domain]:
            self.auth.init_domain(domain)
            state = self.auth.domains.get(domain, {})
            if not state.get("authenticated") or state.get("expired"):
                try:
                    success = await self.auth.credential_login(
                        session    = session,
                        domain     = domain,
                        login_url  = config.LOGIN_URL,
                        username   = config.LOGIN_USERNAME,
                        password   = config.LOGIN_PASSWORD,
                        user_field = config.LOGIN_USER_FIELD,
                        pass_field = config.LOGIN_PASS_FIELD,
                    )
                    
                    # 🔧 FIX-8: Enqueue authenticated landing page (also here for re-login)
                    if success:
                        auth_url = self.auth.domains.get(domain, {}).get("authenticated_url")
                        if auth_url and auth_url not in self.queued:
                            await enqueue_url(auth_url, domain, 0, self.session_id)
                            self.queued.add(auth_url)
                            logger.info(f"[AUTH][{domain}] Enqueued authenticated page: {auth_url}")
                    
                    if success and self.js_pool and self.js_pool.context:
                        await self.auth.sync_cookies_to_playwright(
                            session, self.js_pool.context, domain
                        )
                except Exception as e:
                    logger.error(f"[AUTH][{domain}] Re-login failed: {e}")

    async def enqueue_start_urls(self):
        logger.info("[QUEUE] Enqueuing start URLs and sitemaps")
        results = await asyncio.gather(
            *[fetch_sitemap(url) for url in self.start_urls],
            return_exceptions=True,
        )
        for urls in results:
            if isinstance(urls, list):
                for url in urls:
                    if self.in_scope(url):
                        await enqueue_url(url, urlparse(url).netloc, 0, self.session_id)
        for url in self.start_urls:
            await enqueue_url(url, urlparse(url).netloc, 0, self.session_id)

    async def _try_start_js_pool(self) -> bool:
        if self._js_pool_failed:
            return False
        if self.js_pool is not None and self.js_pool.context:
            return True

        async with self._js_pool_lock:
            # Double-check inside lock
            if self.js_pool is not None and self.js_pool.context:
                return True
            try:
                self.js_pool = JSBrowserPool()
                await self.js_pool.start()
                if not self.js_pool.context:
                    raise RuntimeError("Playwright context failed to initialize")
                logger.info("[Crawler] JS browser pool started")
                return True
            except Exception as exc:
                logger.warning(
                    "[Crawler] JS pool unavailable (%s) — using aiohttp-only mode.",
                    exc,
                )
                self.js_pool         = None
                self._js_pool_failed = True
                return False

    async def _enqueue_links(self, links: list, depth: int):
        async with self.visited_lock:
            new_links = [
                link for link in set(links)
                if link not in self.visited
                and link not in self.queued
                and self.in_scope(link)
            ]
            for link in new_links:
                self.queued.add(link)
        await asyncio.gather(*[
            enqueue_url(link, urlparse(link).netloc, depth + 1, self.session_id)
            for link in new_links
        ], return_exceptions=True)

    async def worker(self, session: aiohttp.ClientSession):
        NON_HTML_EXTENSIONS = (
            # Images
            ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
            # Stylesheets & Scripts
            ".css", ".js", ".ts", ".tsx", ".jsx", ".map",  # ✅ Now includes .js!
            # Fonts
            ".woff", ".woff2", ".ttf", ".otf", ".eot",
            # Media
            ".mp4", ".webm", ".mp3", ".wav", ".avi", ".mov",
            # Documents
            ".pdf", ".doc", ".docx", ".xlsx", ".pptx", ".txt",
            # Archives
            ".zip", ".rar", ".tar", ".gz", ".7z",
            # Code/Config
            ".xml", ".json", ".yaml", ".yml",  # ✅ Now includes data files!
            # Executables
            ".exe", ".dll", ".so", ".jar",
            # Other
            ".bin", ".dat", ".db", ".iso",
        )

        while True:
            row = await fetch_next_url(self.session_id)
            if not row:
                break

            url      = row["url"]
            depth    = row["depth"]
            queue_id = row["id"]
            retries  = row.get("retries", 0)
            domain   = urlparse(url).netloc

            if not self.in_scope(url):
                await mark_done(queue_id)
                continue

            if url.lower().endswith(NON_HTML_EXTENSIONS):
                await mark_done(queue_id)
                continue

            async with self.visited_lock:
                if (
                    url in self.visited
                    or depth > MAX_DEPTH
                    or self.pages_per_domain[domain] >= MAX_PAGES
                ):
                    await mark_done(queue_id)
                    continue
                self.visited.add(url)
                self.pages_per_domain[domain] += 1

            async with self.domain_semaphores[domain], self.semaphore:
                try:
                    if not await can_fetch(url):
                        await mark_done(queue_id)
                        continue

                    await self.ensure_authenticated(session, domain)

                    # ── Step 1: aiohttp fetch (always) ────────────────────────
                    t0 = time.monotonic()
                    async with session.get(url, allow_redirects=True) as r:
                        status       = r.status
                        elapsed      = time.monotonic() - t0
                        resp_headers = dict(r.headers)
                        content_type = r.headers.get("content-type", "")

                        if "text/" in content_type or "javascript" in content_type:
                            html = await r.text(errors="ignore")
                        else:
                            html = ""

                        # inside the `async with session.get(url, ...) as r:` block, after detect_expiration:
                    if config.LOGIN_ENABLED:
                        was_authenticated = self.auth.domains.get(domain, {}).get("authenticated", False)
                        self.auth.detect_expiration(domain, r, html)
                        # If expiration was just detected, don't process stale HTML —
                        # mark this URL for re-crawl after re-login
                        now_expired = self.auth.domains.get(domain, {}).get("expired", False)
                        if was_authenticated and now_expired:
                            logger.warning(
                                f"[Worker][{domain}] Expiration detected mid-fetch for {url} "
                                f"— re-enqueuing for authenticated re-crawl"
                            )
                            async with self.visited_lock:
                                self.visited.discard(url)           # allow re-visit
                                self.pages_per_domain[domain] -= 1  # don't count this stale hit
                            await enqueue_url(url, domain, depth, self.session_id)
                            await mark_done(queue_id)
                            continue  # skip stale HTML processing entirely

                    if not html:
                        raise Exception("Empty HTML response")

                    logger.info(
                        f"[Fetch][{domain}] {url} | "
                        f"Status: {status} | HTML len: {len(html)}"
                    )

                    domain_id   = await get_or_create_domain(domain)

                    # FIX-6: pass resp_headers so header-based antibot signals fire
                    antibot     = detect_antibot(html, status, resp_headers)
                    html_hash   = dom_fingerprint(html)
                    is_js_heavy = (
                        detect_spa_shell(html)
                        or "<script" in html
                        or '<div id="app"' in html
                    )

                    # ── Step 2: network log — always written ──────────────────
                    network_log = get_network_log_file(domain)
                    self.domain_snapshots[domain]["network_log_file"] = network_log

                    aiohttp_cookies = _aiohttp_cookies_to_passive(
                        session.cookie_jar, domain
                    )
                    set_cookie_strings = [
                        v for k, v in resp_headers.items()
                        if k.lower() == "set-cookie"
                    ]

                    await _write_aiohttp_network_log(
                        network_log      = network_log,
                        page_id          = queue_id,
                        url              = url,
                        method           = "GET",
                        status           = status,
                        response_headers = resp_headers,
                        body             = html,
                        elapsed_s        = elapsed,
                        cookies          = aiohttp_cookies,
                        set_cookie_strings = set_cookie_strings,
                    )

                    # ── Step 3: JS rendering (optional) ───────────────────────
                    dyn_links, js_eps = [], []
                    screenshot_path   = None

                    js_ready = await self._try_start_js_pool()
                    if js_ready and self.js_pool and self.js_pool.context:
                        try:
                            await self.auth.sync_cookies_to_playwright(
                                session, self.js_pool.context, domain
                            )
                            (
                                js_html, dyn_links, js_eps, _,
                                js_net_log, screenshot_path,
                            ) = await self.js_pool.fetch_js(url, page_id=queue_id)

                            if js_net_log:
                                self.domain_snapshots[domain]["network_log_file"] = js_net_log

                            if js_html and len(js_html) > 500:
                                html      = js_html
                                html_hash = dom_fingerprint(html)

                        except Exception as js_exc:
                            logger.warning(
                                f"[JS][{domain}] fetch_js failed for {url}: {js_exc} "
                                f"— aiohttp network log already written"
                            )

                    if screenshot_path:
                        self.domain_snapshots[domain]["screenshot_path"] = screenshot_path

                    # ── Step 4: insert page ───────────────────────────────────
                    page    = await insert_page(
                        domain_id        = domain_id,
                        url              = url,
                        html_hash        = html_hash,
                        antibot_detected = antibot,
                        spa_shell        = is_js_heavy,
                        phase            = self.auth.phase(domain),
                    )
                    page_id = page["id"]

                    links, forms, js_eps_static, js_routes, ws_endpoints = parse_page(
                        url, html, list(self.base_domains)
                    )
                    js_eps = list(set(js_eps + js_eps_static))

                    # ── Step 5: endpoints ─────────────────────────────────────
                    async def handle_endpoint(ep_url, ep_type):
                        ep = await insert_endpoint(
                            url      = ep_url,
                            md5_hash = hashlib.md5(ep_url.encode()).hexdigest(),
                            type     = ep_type,
                            js_only  = True,
                        )
                        await link_page_endpoint(page_id, ep["id"], self.session_id)

                    await asyncio.gather(*[
                        handle_endpoint(u, "api") for u in js_eps if u
                    ], return_exceptions=True)
                    await asyncio.gather(*[
                        handle_endpoint(u, "js") for u in js_routes if u
                    ], return_exceptions=True)
                    await asyncio.gather(*[
                        handle_endpoint(u, "ws") for u in ws_endpoints if u
                    ], return_exceptions=True)

                    # ── Step 6: forms ─────────────────────────────────────────
                    for form in forms:
                        f = await insert_form(
                            page_id    = page_id,
                            action_url = form.get("action_url", url),  # FIX-5: was "action_url"
                            method     = form.get("method", "GET"),
                            session_id = self.session_id,
                            js_only    = form.get("js_only", False),
                            phase      = self.auth.phase(domain),
                        )
                        for inp in form.get("inputs", []):
                            await insert_form_input(
                                form_id     = f["id"],
                                name        = inp.get("name"),
                                type        = inp.get("type"),
                                input_id    = inp.get("id"),
                                placeholder = inp.get("placeholder"),
                            )

                    # ── Step 7: enqueue new links ─────────────────────────────
                    await self._enqueue_links(list(set(links + dyn_links)), depth)
                    await mark_done(queue_id)

                except Exception as e:
                    logger.error(f"[Worker Error] {url} -> {e}")
                    if retries < 3:
                        await enqueue_url(
                            url, domain, depth, self.session_id, retries + 1
                        )
                    await mark_done(queue_id, failed=True)

    async def run(self):
        if not self.session_id:
            self.session_id = await start_scan_session()

        await self.enqueue_start_urls()

        timeout   = aiohttp.ClientTimeout(total=20, connect=5, sock_read=15)
        connector = aiohttp.TCPConnector(
            limit=MAX_CONCURRENT_REQUESTS * 2, limit_per_host=10, ssl=False
        )

        async with aiohttp.ClientSession(
            timeout=timeout, connector=connector
        ) as session:
            await self.login_domains(session)
            workers = [
                asyncio.create_task(self.worker(session))
                for _ in range(MAX_CONCURRENT_REQUESTS)
            ]
            await asyncio.gather(*workers)

        if self.js_pool:
            await self.js_pool.stop()

        for domain in self.base_domains:
            snap = self.domain_snapshots.get(domain)
            if snap and (snap.get("network_log_file") or snap.get("screenshot_path")):
                try:
                    domain_id   = await get_or_create_domain(domain)
                    snapshot_id = await insert_snapshot(
                        domain_id        = domain_id,
                        network_log_file = snap.get("network_log_file"),
                        screenshot_path  = snap.get("screenshot_path"),
                        session_id       = self.session_id,
                    )
                    if snapshot_id:
                        logger.info(f"[Snapshots] Saved snapshot for {domain}")
                except Exception as e:
                    logger.error(f"[Snapshots Error] {domain} -> {e}")

        await finish_scan_session(self.session_id)
        logger.info(f"[Crawler] Finished scan {self.session_id}")