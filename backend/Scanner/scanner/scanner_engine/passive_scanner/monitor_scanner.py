import json
import sys
import aiofiles
import asyncio
import logging
from urllib.parse import urlparse

from .monitor_reporter import Reporter

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
from .core.content_change import analyze_page_changes

logger = logging.getLogger("webxguard.monitor.scanner")

# ─────────────────────────────────────────────────────────────────────────────
# MODULE LISTS
# ─────────────────────────────────────────────────────────────────────────────

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
    analyze_page_changes,
]

COOKIE_MODULES = [
    analyze_cookies,
]

# analyze_client_storage runs on its own event type — not in HTTP_MODULES
CLIENT_STORAGE_MODULES = [
    analyze_client_storage,
]

# ─────────────────────────────────────────────────────────────────────────────
# SCOPE / STATIC HELPERS  (identical to main scanner)
# ─────────────────────────────────────────────────────────────────────────────

PUBLIC_SUFFIX_EXCEPTIONS = [
    "netlify.app",
    "github.io",
    "vercel.app",
    "azurewebsites.net",
]

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".avi",
    ".pdf", ".zip", ".tar", ".gz",
    ".css", ".map", ".webp",
    "/theme/styles.php", "/theme/yui_combo.php", "/lib/javascript.php",
}


def extract_scope_host(url: str) -> str:
    hostname = urlparse(url).hostname or ""
    for suffix in PUBLIC_SUFFIX_EXCEPTIONS:
        if hostname.endswith(suffix):
            return hostname
    parts = hostname.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else hostname


def is_in_scope(url: str, scope_host: str) -> bool:
    hostname = urlparse(url).hostname or ""
    return hostname == scope_host or hostname.endswith("." + scope_host)


def is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXTENSIONS)


# ─────────────────────────────────────────────────────────────────────────────
# MODULE STATE RESET
# Clears all module-level dedup sets/dicts/lists between monitoring cycles
# so URLs processed in cycle N are not silently skipped in cycle N+1.
# ─────────────────────────────────────────────────────────────────────────────

_CACHE_KEYWORDS = (
    "seen", "cache", "check", "visit", "done",
    "scan", "process", "report", "result", "find",
    "analyz", "detect", "record", "track",
    "host", "url", "domain", "cert", "ssl", "tls",
)


def _reset_module_state() -> None:
    import types as _types

    all_modules = HTTP_MODULES + COOKIE_MODULES + CLIENT_STORAGE_MODULES
    seen_mods   = set()
    reset_count = 0

    for fn in all_modules:
        mod_name = fn.__module__
        if mod_name in seen_mods:
            continue
        seen_mods.add(mod_name)

        mod = sys.modules.get(mod_name)
        if mod is None:
            continue

        for attr_name, obj in list(vars(mod).items()):
            if attr_name.startswith("__"):
                continue
            if obj is None:
                continue
            if isinstance(obj, (_types.ModuleType, type)) or callable(obj):
                continue

            try:
                if isinstance(obj, set):
                    obj.clear()
                    reset_count += 1
                    logger.debug(f"[Scanner] Cleared set  {mod_name}.{attr_name}")

                elif isinstance(obj, dict):
                    if any(kw in attr_name.lower() for kw in _CACHE_KEYWORDS):
                        obj.clear()
                        reset_count += 1
                        logger.debug(f"[Scanner] Cleared dict {mod_name}.{attr_name}")

                elif isinstance(obj, list):
                    if any(kw in attr_name.lower() for kw in _CACHE_KEYWORDS):
                        obj.clear()
                        reset_count += 1
                        logger.debug(f"[Scanner] Cleared list {mod_name}.{attr_name}")

            except Exception:
                pass

    logger.info(f"[Scanner] Module state reset — {reset_count} cache(s) cleared")


# ─────────────────────────────────────────────────────────────────────────────
# PASSIVE SCAN ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

async def passive_scan_snapshot(snapshot: dict, monitor_session_id: str) -> None:
    """
    Run all passive scanner modules over one monitoring cycle's network log.

    Parameters
    ──────────
    snapshot           — dict with key: network_log_file
    monitor_session_id — UUID string of the current monitor_sessions row

    scope_host is derived lazily from the first URL seen in the log so no
    domain value is needed in the snapshot dict at all.
    """
    reporter   = Reporter(session_id=monitor_session_id)
    scope_host: str = ""   # set from first URL encountered in the log

    logger.info(f"[Monitor] Starting scan — log={snapshot['network_log_file']}")

    # Reset all module-level dedup caches before this cycle
    _reset_module_state()

    # Per-scan session cache passed into ssl_tls module
    ssl_session_cache: set[str] = set()

    # Per-scan dedup sets — shared across ALL module calls so domain-level
    # dedup fires correctly when the same URL appears in multiple log events
    http_seen:   set = set()
    cookie_seen: set = set()

    # Log-level dedup — prevents running modules twice on the exact same event
    seen_urls_http:    set = set()
    seen_urls_cookies: set = set()

    entry_count = 0
    skipped     = 0

    try:
        async with aiofiles.open(snapshot["network_log_file"], "r") as f:
            async for raw_line in f:
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    logger.warning("[Monitor] Skipping invalid JSON line")
                    continue

                url        = entry.get("url")
                entry_type = entry.get("type")
                phase      = entry.get("phase", "guest")
                page_id    = entry.get("page_id")   # forwarded to modules if present

                if not url:
                    continue

                # ── Derive scope_host from first URL seen ─────────────────
                if not scope_host:
                    scope_host = extract_scope_host(url)
                    logger.info(f"[Monitor] scope_host={scope_host}")

                # ── Cookie events ─────────────────────────────────────────
                if entry_type == "cookies":
                    dedup_key = (url, phase)
                    if dedup_key in seen_urls_cookies:
                        skipped += 1
                        continue
                    seen_urls_cookies.add(dedup_key)

                    await _run_cookie_modules(
                        entry, reporter, cookie_seen, page_id=page_id
                    )
                    entry_count += 1
                    continue

                # ── Client storage events ─────────────────────────────────
                if entry_type == "client_storage":
                    await _run_client_storage_modules(
                        entry, reporter, page_id=page_id
                    )
                    entry_count += 1
                    continue

                # ── Skip non-HTTP events ──────────────────────────────────
                if entry_type != "http":
                    skipped += 1
                    continue

                # ── Scope + static filtering ──────────────────────────────
                if not is_in_scope(url, scope_host) or is_static_asset(url):
                    skipped += 1
                    continue

                # ── HTTP event dedup ──────────────────────────────────────
                status_code = entry.get("status_code")
                dedup_key   = (url, status_code, phase)
                if dedup_key in seen_urls_http:
                    skipped += 1
                    continue
                seen_urls_http.add(dedup_key)

                entry_count += 1
                await _run_http_modules(
                    entry, reporter, http_seen,
                    page_id          = page_id,
                    ssl_session_cache = ssl_session_cache,
                )

    except FileNotFoundError:
        logger.error(
            f"[Monitor] Network log not found: {snapshot['network_log_file']}"
        )
    except Exception as e:
        logger.exception(f"[Monitor] Error reading network log: {e}")

    logger.info(
        f"[Monitor] Scan complete — scope={scope_host} "
        f"processed={entry_count} skipped={skipped} "
        f"reported={reporter.reported_count}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# MODULE RUNNERS
# ─────────────────────────────────────────────────────────────────────────────

async def _run_http_modules(
    entry:             dict,
    reporter:          Reporter,
    http_seen:         set,
    page_id:           int | None = None,
    ssl_session_cache: set | None = None,
) -> None:
    """
    Run all HTTP scanner modules sequentially on a single flat fetcher event.

    Modules that accept `session_cache` (ssl_tls) receive the per-scan
    SSL hostname cache so one SSL probe fires per hostname per cycle.

    Modules that don't yet accept optional kwargs fall back gracefully
    via TypeError catch.
    """
    for module in HTTP_MODULES:
        try:
            # ssl_tls accepts session_cache — pass it explicitly
            if module is analyze_ssl_tls:
                result = module(
                    entry, reporter,
                    page_id        = page_id,
                    session_cache  = ssl_session_cache,
                )
            else:
                result = module(entry, reporter, page_id=page_id)

            if asyncio.iscoroutine(result):
                await result

        except TypeError as te:
            # Module signature does not accept page_id — running OLD version.
            # This means build_ai_scores() is never called → scores stay NULL.
            # FIX: replace the old module file with the rewritten version.
            logger.warning(
                f"[HTTP Module] OLD SIGNATURE detected — scores will be NULL: "
                f"{module.__name__} ({te})"
            )
            try:
                result = module(entry, reporter)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.exception(f"[HTTP Module Error] {module.__name__}: {e}")

        except Exception as e:
            logger.exception(f"[HTTP Module Error] {module.__name__}: {e}")



async def _run_cookie_modules(
    entry:       dict,
    reporter:    Reporter,
    cookie_seen: set,
    page_id:     int | None = None,
) -> None:
    """
    Run cookie scanner modules on a flat fetcher cookies event.
    Passes the event directly — no snapshot wrapper.
    """
    for module in COOKIE_MODULES:
        try:
            result = module(entry, reporter, page_id=page_id)
            if asyncio.iscoroutine(result):
                await result
        except TypeError:
            try:
                result = module(entry, reporter)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.exception(f"[Cookie Module Error] {module.__name__}: {e}")
        except Exception as e:
            logger.exception(f"[Cookie Module Error] {module.__name__}: {e}")


async def _run_client_storage_modules(
    entry:    dict,
    reporter: Reporter,
    page_id:  int | None = None,
) -> None:
    """
    Run client storage modules on a flat fetcher client_storage event.
    These are kept separate from HTTP_MODULES because they fire on a
    different event type and would be a no-op on http events.
    """
    for module in CLIENT_STORAGE_MODULES:
        try:
            result = module(entry, reporter, page_id=page_id)
            if asyncio.iscoroutine(result):
                await result
        except TypeError:
            try:
                result = module(entry, reporter)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as e:
                logger.exception(f"[Storage Module Error] {module.__name__}: {e}")
        except Exception as e:
            logger.exception(f"[Storage Module Error] {module.__name__}: {e}")