"""
scanner_engine/passive_scanner/scanner.py
Production-grade passive scanner (optimized, concurrent, safe)
"""

import json
import aiofiles
import asyncio
import logging
from urllib.parse import urlparse
import tldextract

from ...config import START_URLS
from .reporter import Reporter

# Core modules
from .core.headers import analyze_headers
from .core.cookies import analyze_cookies
from .core.secrets import scan_secrets
from .core.csp import analyze_csp
from .core.comments import analyze_comments
from .core.cms import detect_and_scan_cms
from .core.access_control import detect_admin_exposure
from .core.error_status import analyze_status
from .core.http_headers_extra import analyze_http_headers_extra
from .core.robots_analysis import analyze_robots
from .core.sitemap_analysis import analyze_sitemap
from .core.external_links import analyze_external_links
from .core.cors import analyze_cors
from .core.ssl_tls import analyze_ssl_tls
from .core.cache import analyze_cache
from .core.javascript import analyze_javascript
from .core.forms import analyze_forms
from .core.mixed_content import analyze_mixed_content
from .core.versioning import analyze_versioning
from .core.storage import analyze_client_storage

logger = logging.getLogger("webxguard.scanner")
logging.basicConfig(level=logging.INFO)

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

MAX_CONCURRENT_MODULES = 10
MODULE_TIMEOUT = 5  # seconds
SEM = asyncio.Semaphore(MAX_CONCURRENT_MODULES)

HTTP_MODULES = [
    analyze_headers,
    scan_secrets,
    analyze_csp,
    analyze_comments,
    detect_and_scan_cms,
    detect_admin_exposure,
    analyze_status,
    analyze_http_headers_extra,
    analyze_robots,
    analyze_external_links,
    analyze_sitemap,
    analyze_cors,
    analyze_ssl_tls,
    analyze_cache,
    analyze_javascript,
    analyze_forms,
    analyze_mixed_content,
    analyze_versioning,
    analyze_client_storage,
]

COOKIE_MODULES = [
    analyze_cookies,
]

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi",
    ".pdf", ".zip", ".tar", ".gz",
    ".css", ".map", ".webp",
}

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def extract_scope_host(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def is_in_scope(url: str, scope_host: str) -> bool:
    hostname = urlparse(url).hostname or ""
    return hostname == scope_host or hostname.endswith("." + scope_host)


def is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(ext in path for ext in STATIC_EXTENSIONS)


async def safe_run(coro):
    async with SEM:
        try:
            return await asyncio.wait_for(coro, timeout=MODULE_TIMEOUT)
        except asyncio.TimeoutError:
            logger.warning("[Timeout] Module exceeded execution time")
        except Exception as e:
            logger.exception(f"[Module Error] {e}")


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCAN
# ─────────────────────────────────────────────────────────────────────────────

async def passive_scan_snapshot(
    snapshot: dict,
    session_id: str,
    scope_url: str | None = None,
):
    # Resolve scope safely
    if scope_url is None:
        if START_URLS:
            scope_url = START_URLS[0]
        else:
            scope_url = snapshot.get("domain_name", "")
            if not scope_url:
                logger.error("[Passive] Cannot determine scope URL")
                return

    reporter = Reporter(session_id=session_id, domain_id=snapshot["domain_id"])
    scope_host = extract_scope_host(scope_url)

    logger.info(f"[Scope] scope_url={scope_url}, scope_host={scope_host}")

    seen_urls_http = set()
    seen_urls_cookies = set()

    entry_count = 0
    skipped = 0

    try:
        async with aiofiles.open(snapshot["network_log_file"], "r") as f:
            async for line in f:
                if not line.strip():
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("Skipping invalid JSON line")
                    continue

                url = entry.get("url")
                if not url:
                    continue

                entry_type = entry.get("type")
                phase = entry.get("phase", "guest")

                # ── COOKIE HANDLING ─────────────────────────────────────
                if entry_type == "cookies":
                    key = (url, phase)
                    if key in seen_urls_cookies:
                        skipped += 1
                        continue
                    seen_urls_cookies.add(key)

                    await run_modules(entry, reporter, COOKIE_MODULES)
                    entry_count += 1
                    continue

                # ── HTTP HANDLING ───────────────────────────────────────
                if entry_type != "http":
                    skipped += 1
                    continue

                if not is_in_scope(url, scope_host) or is_static_asset(url):
                    skipped += 1
                    continue

                status = entry.get("status_code")
                key = (url, status, phase)

                if key in seen_urls_http:
                    skipped += 1
                    continue

                seen_urls_http.add(key)

                await run_modules(entry, reporter, HTTP_MODULES)
                entry_count += 1

                # Progress logging
                if entry_count % 100 == 0:
                    logger.info(f"[Progress] {entry_count} entries processed...")

    except FileNotFoundError:
        logger.error(f"Snapshot file not found: {snapshot['network_log_file']}")
    except Exception as e:
        logger.exception(f"Scan error: {e}")

    logger.info(
        f"[Scan Completed] Processed={entry_count}, Skipped={skipped}, "
        f"Reported={reporter.reported_count}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# MODULE RUNNER (CONCURRENT)
# ─────────────────────────────────────────────────────────────────────────────

async def run_modules(entry: dict, reporter: Reporter, modules: list):
    tasks = []

    for module in modules:
        try:
            coro = module(entry, reporter)
            if asyncio.iscoroutine(coro):
                tasks.append(safe_run(coro))
        except Exception as e:
            logger.exception(f"[Module Init Error] {module.__name__}: {e}")

    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)