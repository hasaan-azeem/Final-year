import asyncio
import logging
import os
import re
import json
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlparse
from datetime import datetime, timezone

from playwright.async_api import async_playwright, Browser, Page, BrowserContext

from ..monitoring_config import USER_AGENT, MAX_JS_BROWSERS
from .utils import normalize_url

logger = logging.getLogger("webxguard.monitor.fetcher")

# ─────────────────────────────────────────────────────────────────────────────
# ANTI-BOT DETECTION — comprehensive signal lists
# ─────────────────────────────────────────────────────────────────────────────

_CLOUDFLARE = [
    "checking your browser",
    "cf-browser-verification",
    "cdn-cgi/challenge-platform",
    "jschl_vc",
    "jschl-answer",
    "__cf_chl_jschl_tk__",
    "__cf_chl_f_tk",
    "cf-spinner",
    "cloudflare ray id",
    "enable javascript and cookies",
    "one more step",
    "attention required! | cloudflare",
    "cf_clearance",
    "turnstile",
]

_IMPERVA = [
    "incapsula", "imperva",
    "_incap_ses_", "visid_incap_",
    "/_Incapsula_Resource",
    "incap_ses_",
    "reese84",
]

_DATADOME = [
    "datadome",
    "dd_cookie_test_",
    "datadome.co/captcha",
    "datadome.co/js/",
]

_PERIMETERX = [
    "perimeterx", "px-captcha",
    "pxchallenge", "human.px-cdn",
    "/_pxCaptcha", "px_uuid",
]

_OTHER_WAFS = [
    "akamai ghost",
    "f5 big-ip",
    "radware",
    "barracuda",
    "sucuri",
    "sitelock",
    "wordfence firewall",
    "mod_security",
    "fortiweb",
    "aws waf",
    "shape security",
    "signal sciences",
]

_GENERIC_BOT = [
    "captcha", "recaptcha", "hcaptcha",
    "verify you are human",
    "verify you're not a robot",
    "i'm not a robot",
    "access denied",
    "ddos protection",
    "bot protection",
    "automated access", "automated request",
    "bot detected", "robot detected",
    "human verification", "browser check",
    "security check",
    "please enable javascript",
    "please enable cookies",
    "suspicious activity", "unusual traffic",
    "too many requests", "rate limit exceeded",
    "your ip has been blocked", "ip blocked",
    "temporarily blocked",
    "are you a human",
    "prove you are human",
    "anti-ddos",
    "press & hold",
    "just a moment",
]

# All signals combined at module level
_ALL_ANTIBOT_SIGNALS = (
    _CLOUDFLARE + _IMPERVA + _DATADOME
    + _PERIMETERX + _OTHER_WAFS + _GENERIC_BOT
)

_WAF_SERVER_VALUES = [
    "cloudflare", "imperva", "incapsula",
    "akamai", "sucuri", "ddos-guard",
]


def detect_antibot(
    html: str,
    status: Optional[int] = None,
    headers: Optional[Dict[str, str]] = None,
) -> bool:
    """
    Detect anti-bot / WAF protection on a page.

    Checks (in order):
      1. HTTP status codes that signal blocking (403, 429, 503)
      2. 40+ HTML body signals across all major WAF/CAPTCHA providers
      3. Response header signals (cf-mitigated, server, x-datadome-cid, x-px-*)
      4. JS-only redirect challenge pages
      5. Meta-refresh pointing to CDN challenge URLs

    Returns True if bot protection detected — page cannot be scraped normally.
    Never raises.
    """
    try:
        # ── 1. Status-code signals ──────────────────────────────────────────
        if status in (403, 429, 503):
            return True

        if not html:
            return False

        html_lower = html.lower()

        # ── 2. HTML body signals ────────────────────────────────────────────
        if any(signal in html_lower for signal in _ALL_ANTIBOT_SIGNALS):
            return True

        # ── 3. Response header signals ──────────────────────────────────────
        if headers:
            h: Dict[str, str] = {
                k.lower(): (v.lower() if isinstance(v, str) else str(v).lower())
                for k, v in headers.items()
            }

            # Cloudflare: explicit challenge mitigated header
            if "challenge" in h.get("cf-mitigated", ""):
                return True

            # Server header hints
            server = h.get("server", "")
            if any(w in server for w in _WAF_SERVER_VALUES):
                if len(html) < 5000 or any(s in html_lower for s in _CLOUDFLARE):
                    return True

            # DataDome
            if "x-datadome-cid" in h:
                return True

            # Incapsula
            if "x-iinfo" in h:
                return True

            # PerimeterX
            if any(k.startswith("x-px-") for k in h):
                return True

        # ── 4. JS-only challenge page ───────────────────────────────────────
        has_body    = "<body" in html_lower
        has_js_redir = (
            "window.location" in html_lower
            or "document.location" in html_lower
        )
        if len(html) < 3000 and has_js_redir and not has_body:
            return True

        # ── 5. Meta-refresh to CDN challenge ───────────────────────────────
        if (
            'meta http-equiv="refresh"' in html_lower
            and "cdn-cgi" in html_lower
        ):
            return True

        return False

    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
# DIRECTORY SETUP
# ─────────────────────────────────────────────────────────────────────────────
NETWORK_LOG_DIR = "network_logs"
os.makedirs(NETWORK_LOG_DIR, exist_ok=True)

domain_network_files: dict = {}


# ─────────────────────────────────────────────────────────────────────────────
# FILE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _batch_log(path: str, page_id: int, events: list) -> None:
    """Write network events to JSONL file."""
    try:
        with open(path, "a", encoding="utf-8") as f:
            for evt in events:
                record = {
                    "page_id":   page_id,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    **evt,
                }
                f.write(json.dumps(record) + "\n")
    except Exception as e:
        logger.error(f"Batch log failed: {e}")


def get_network_log_file(domain: str, session_id: Optional[str] = None) -> str:
    """Return the JSONL log path for a domain."""
    filename = f"{domain}_{session_id}.jsonl" if session_id else f"{domain}.jsonl"
    path     = os.path.join(NETWORK_LOG_DIR, filename)
    if not os.path.exists(path):
        open(path, "w").close()
    domain_network_files[(domain, session_id)] = path
    return path


# ─────────────────────────────────────────────────────────────────────────────
# COOKIE HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_cookie_flags(cookie: dict) -> list:
    """Convert Playwright cookie object into scanner-expected flags list."""
    flags = []
    if cookie.get("httpOnly"):
        flags.append("httponly")
    if cookie.get("secure"):
        flags.append("secure")
    same_site = cookie.get("sameSite", "")
    if same_site:
        flags.append(f"samesite={same_site.lower()}")
    return flags


def _reconstruct_set_cookie_string(c: dict) -> str:
    """
    Reconstruct a Set-Cookie header string from a Playwright cookie object.
    Used as fallback when Set-Cookie headers are not captured at network level.
    """
    parts = [f"{c.get('name', '')}={c.get('value', '')}"]
    if c.get("domain"):
        parts.append(f"Domain={c['domain']}")
    if c.get("path"):
        parts.append(f"Path={c['path']}")
    if c.get("httpOnly"):
        parts.append("HttpOnly")
    if c.get("secure"):
        parts.append("Secure")
    same_site = c.get("sameSite", "")
    if same_site:
        parts.append(f"SameSite={same_site.capitalize()}")
    expires = c.get("expires", -1)
    if expires and expires != -1:
        try:
            dt = datetime.fromtimestamp(expires, tz=timezone.utc)
            parts.append(f"Expires={dt.strftime('%a, %d %b %Y %H:%M:%S GMT')}")
        except Exception:
            pass
    return "; ".join(parts)


# ─────────────────────────────────────────────────────────────────────────────
# JS BROWSER POOL
# ─────────────────────────────────────────────────────────────────────────────

class JSBrowserPool:

    WS_REGEX = re.compile(r"(wss?://[^\s'\"<>]+)")

    def __init__(self, max_browsers: int = MAX_JS_BROWSERS, headless: bool = True):
        self.max_browsers = max_browsers
        self.headless     = headless
        self.playwright   = None
        self.browser: Optional[Browser]        = None
        self.context: Optional[BrowserContext] = None
        self.semaphore = asyncio.Semaphore(max_browsers)

    async def start(self) -> None:
        try:
            self.playwright = await async_playwright().start()
            self.browser    = await self.playwright.chromium.launch(
                headless=self.headless,
                args=["--disable-blink-features=AutomationControlled", "--no-sandbox"],
            )
            self.context = await self.browser.new_context(
                user_agent=USER_AGENT,
                locale="en-US",
                extra_http_headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma":        "no-cache",
                },
            )
            logger.info("JSBrowserPool started successfully.")
        except Exception as e:
            logger.exception(f"[Monitor] Browser start failed: {e}")

    async def stop(self) -> None:
        try:
            if self.context:
                await self.context.close()
            if self.browser:
                await self.browser.close()
            if self.playwright:
                await self.playwright.stop()
            logger.info("JSBrowserPool stopped.")
        except Exception as e:
            logger.error(f"[Monitor] Browser shutdown error: {e}")

    async def fetch_js(
        self,
        url:               str,
        page_id:           int,
        max_retries:       int           = 2,
        js_wait:           int           = 3000,
        goto_timeout:      int           = 30000,
        wait_for_selector: Optional[str] = None,
        network_log_path:  Optional[str] = None,
    ) -> Tuple[Optional[str], List[str], List[str], List[str], Optional[str]]:
        """
        Fetch a URL using a real browser and write network events to log.

        Returns:
            (html, dynamic_links, js_endpoints, ws_endpoints, network_log_path)

        Network events written per URL:
            type="http"           — one per HTTP response (headers, body, cookies)
            type="cookies"        — one per page load (full jar + set_cookies)
            type="client_storage" — one per page load (localStorage + sessionStorage)
            type="redirect_chain" — one if redirects occurred
        """
        if not self.context:
            logger.error("Browser context not initialized.")
            return None, [], [], [], None

        domain      = urlparse(url).netloc
        network_log = network_log_path or get_network_log_file(domain)

        async with self.semaphore:
            for attempt in range(1, max_retries + 1):
                page: Optional[Page] = None
                try:
                    page = await asyncio.wait_for(
                        self.context.new_page(), timeout=10
                    )

                    # Snapshot cookie jar BEFORE this page load for jar-diff
                    cookies_before = {
                        c["name"]: c
                        for c in await page.context.cookies()
                    }

                    network_events: list = []
                    dynamic_links:  list = []
                    js_eps:         list = []
                    ws_eps:         list = []
                    redirect_chain: list = []
                    request_map:    dict = {}

                    # ── Request handler ───────────────────────────────────
                    async def handle_request(req):
                        try:
                            request_map[f"{req.method}::{req.url}"] = {
                                "method":        req.method,
                                "url":           req.url,
                                "headers":       dict(req.headers),
                                "body":          req.post_data or None,
                                "resource_type": req.resource_type,
                                "timestamp":     datetime.now(timezone.utc).isoformat(),
                            }
                            if req.redirected_from:
                                redirect_chain.append({
                                    "from": req.redirected_from.url,
                                    "to":   req.url,
                                })
                        except Exception:
                            pass

                    # ── Response handler ──────────────────────────────────
                    async def handle_response(resp):
                        try:
                            key      = f"{resp.request.method}::{resp.request.url}"
                            req_info = request_map.pop(key, None)

                            headers_array = []
                            try:
                                headers_array = await resp.headers_array()
                            except Exception:
                                try:
                                    raw           = await resp.all_headers()
                                    headers_array = [
                                        {"name": k, "value": v}
                                        for k, v in raw.items()
                                    ]
                                except Exception:
                                    pass

                            headers_dict = {
                                h["name"].lower(): h["value"]
                                for h in headers_array
                            }
                            set_cookies = [
                                h["value"] for h in headers_array
                                if h["name"].lower() == "set-cookie"
                            ]

                            security_headers = {
                                "content-security-policy":          headers_dict.get("content-security-policy"),
                                "strict-transport-security":         headers_dict.get("strict-transport-security"),
                                "x-content-type-options":           headers_dict.get("x-content-type-options"),
                                "x-frame-options":                   headers_dict.get("x-frame-options"),
                                "referrer-policy":                   headers_dict.get("referrer-policy"),
                                "permissions-policy":                headers_dict.get("permissions-policy"),
                                "access-control-allow-origin":       headers_dict.get("access-control-allow-origin"),
                                "access-control-allow-credentials":  headers_dict.get("access-control-allow-credentials"),
                                "cache-control":                     headers_dict.get("cache-control"),
                                "vary":                              headers_dict.get("vary"),
                            }

                            body_text = None
                            ct        = headers_dict.get("content-type", "")
                            if any(t in ct for t in (
                                "text/", "application/json",
                                "application/javascript", "application/xml",
                                "+json", "+xml",
                            )):
                                try:
                                    body_text = (await resp.body()).decode(
                                        "utf-8", errors="ignore"
                                    )
                                except Exception:
                                    pass

                            network_events.append({
                                "type":             "http",
                                "url":              resp.request.url,
                                "method":           resp.request.method,
                                "status_code":      resp.status,
                                "headers":          headers_dict,
                                "request_headers":  req_info.get("headers", {}) if req_info else {},
                                "request_body":     req_info.get("body") if req_info else None,
                                "set_cookies":      set_cookies,
                                "cookies":          [],     # injected in post-processing
                                "security_headers": security_headers,
                                "body":             body_text,
                                "resource_type":    resp.request.resource_type,
                                "timestamp":        datetime.now(timezone.utc).isoformat(),
                            })

                        except Exception as e:
                            logger.debug(f"[Monitor Fetcher] handle_response error: {e}")

                    page.on("request",  handle_request)
                    page.on("response", handle_response)

                    # ── Navigate ──────────────────────────────────────────
                    await asyncio.wait_for(
                        page.goto(
                            url, wait_until="domcontentloaded", timeout=goto_timeout
                        ),
                        timeout=goto_timeout / 1000 + 5,
                    )

                    # ── Anti-bot check with header context ─────────────────
                    initial_html = await page.content()

                    # Find headers & status from main document network event
                    main_headers: Dict[str, str] = {}
                    main_status:  Optional[int]  = None
                    for evt in network_events:
                        if evt.get("type") == "http" and evt.get("url") == url:
                            main_headers = evt.get("headers", {})
                            main_status  = evt.get("status_code")
                            break

                    if detect_antibot(initial_html, main_status, main_headers):
                        logger.warning(
                            f"[Monitor Fetcher] Anti-bot detected on {url} "
                            f"(status={main_status}), aborting."
                        )
                        return None, [], [], [], None

                    # ── Wait for JS to render ─────────────────────────────
                    if wait_for_selector:
                        try:
                            await page.wait_for_selector(wait_for_selector, timeout=js_wait)
                        except Exception:
                            await page.wait_for_timeout(js_wait)
                    else:
                        await page.wait_for_timeout(js_wait)

                    # ── Extract links & scripts ───────────────────────────
                    try:
                        raw_links     = await page.evaluate(
                            "Array.from(document.querySelectorAll('a[href]')).map(a => a.href)"
                        )
                        dynamic_links = list({
                            normalize_url(url, l) for l in raw_links
                            if normalize_url(url, l)
                        })
                    except Exception:
                        dynamic_links = []

                    try:
                        scripts = await page.evaluate(
                            "Array.from(document.scripts).map(s => s.src).filter(Boolean)"
                        )
                        js_eps = list({
                            normalize_url(url, s) for s in scripts
                            if normalize_url(url, s)
                        })
                    except Exception:
                        js_eps = []

                    try:
                        html_preview = await page.content()
                        ws_eps       = list(set(self.WS_REGEX.findall(html_preview)))
                    except Exception:
                        ws_eps = []

                    # ════════════════════════════════════════════════════════
                    # POST-PROCESSING — runs after full page load,
                    # before anything is written to disk
                    # ════════════════════════════════════════════════════════

                    # STEP 1: Build parsed cookie jar
                    raw_cookies    = await page.context.cookies()
                    parsed_cookies = [
                        {
                            "name":    c.get("name"),
                            "value":   c.get("value", ""),
                            "domain":  c.get("domain"),
                            "path":    c.get("path"),
                            "flags":   _parse_cookie_flags(c),
                            "expires": c.get("expires"),
                            "session": c.get("expires", -1) == -1,
                        }
                        for c in raw_cookies
                    ]

                    # STEP 2: Inject full cookie jar into every HTTP event
                    for evt in network_events:
                        if evt.get("type") == "http":
                            evt["cookies"] = parsed_cookies

                    # STEP 3: Find cookies newly set this page load via diff
                    newly_set = [
                        c for c in raw_cookies
                        if c["name"] not in cookies_before
                        or cookies_before[c["name"]].get("value") != c.get("value")
                    ]

                    # STEP 4: Aggregate Set-Cookie strings from all HTTP events
                    all_set_cookies = []
                    for evt in network_events:
                        if evt.get("type") == "http" and evt.get("set_cookies"):
                            all_set_cookies.extend(evt["set_cookies"])

                    # STEP 5: Fallback — reconstruct from jar diff if network
                    # capture missed them (e.g. cookies set on redirects)
                    if not all_set_cookies and newly_set:
                        logger.debug(
                            f"[Monitor Fetcher] Reconstructing {len(newly_set)} "
                            f"Set-Cookie strings from jar diff for {url}"
                        )
                        all_set_cookies = [
                            _reconstruct_set_cookie_string(c) for c in newly_set
                        ]

                    # STEP 5b: Final fallback — reconstruct from domain jar
                    if not all_set_cookies and parsed_cookies:
                        page_domain    = urlparse(url).netloc.lstrip("www.")
                        domain_cookies = [
                            c for c in raw_cookies
                            if page_domain in (c.get("domain") or "").lstrip(".")
                        ]
                        if domain_cookies:
                            logger.debug(
                                f"[Monitor Fetcher] Reconstructing {len(domain_cookies)} "
                                f"cookies from domain jar for {url}"
                            )
                            all_set_cookies = [
                                _reconstruct_set_cookie_string(c)
                                for c in domain_cookies
                            ]

                    logger.info(
                        f"[Monitor Fetcher] Cookies for {url}: "
                        f"{len(parsed_cookies)} in jar, "
                        f"{len(newly_set)} newly set, "
                        f"{len(all_set_cookies)} Set-Cookie strings"
                    )

                    # STEP 6: Append cookies event
                    network_events.append({
                        "type":        "cookies",
                        "url":         url,
                        "cookies":     parsed_cookies,
                        "set_cookies": all_set_cookies,
                        "status_code": 200,
                        "timestamp":   datetime.now(timezone.utc).isoformat(),
                    })

                    # STEP 7: Extract localStorage + sessionStorage
                    try:
                        client_storage = await page.evaluate("""() => ({
                            localStorage:   Object.fromEntries(Object.entries(localStorage)),
                            sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
                        })""")
                    except Exception:
                        client_storage = {}

                    network_events.append({
                        "type":           "client_storage",
                        "url":            url,
                        "client_storage": client_storage,
                        "timestamp":      datetime.now(timezone.utc).isoformat(),
                    })

                    # STEP 8: Append redirect chain
                    if redirect_chain:
                        network_events.append({
                            "type":      "redirect_chain",
                            "url":       url,
                            "chain":     redirect_chain,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })

                    # STEP 9: Write to disk LAST — after cookies injected
                    if network_events:
                        await asyncio.to_thread(
                            _batch_log, network_log, page_id, network_events
                        )

                    html = await page.content()
                    logger.info(
                        f"[Monitor Fetcher] Done: {url} — "
                        f"{len(network_events)} events, "
                        f"{len(dynamic_links)} links"
                    )
                    return html, dynamic_links, js_eps, ws_eps, network_log

                except Exception as e:
                    logger.warning(f"[Monitor Fetcher] Attempt {attempt} failed for {url}: {e}")
                    await asyncio.sleep(1.5 * attempt)

                finally:
                    if page:
                        try:
                            await page.close()
                        except Exception:
                            pass

        return None, [], [], [], None