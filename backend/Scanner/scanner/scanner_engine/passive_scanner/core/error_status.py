import asyncio
import logging
import re
from typing import Optional
from urllib.parse import urlparse

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.status")

MAX_SNIPPET_LEN = 150

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

INFO_DISCLOSURE_CODES = {400, 401, 403, 404, 500, 501, 502, 503, 504}

# Backup files may return 200 — checked independently of the error-code set
BACKUP_CHECK_CODES = {200, *INFO_DISCLOSURE_CODES}

VERSION_PATTERNS = [
    re.compile(r"apache/\d+\.\d+(\.\d+)?", re.I),
    re.compile(r"nginx/\d+\.\d+(\.\d+)?",  re.I),
    re.compile(r"iis/\d+\.\d+",            re.I),
    re.compile(r"php/\d+\.\d+(\.\d+)?",    re.I),
]

DIR_LISTING_PATTERNS = [
    re.compile(r"<title>Index of", re.I),
    re.compile(r"<h1>Index of",    re.I),
]

STACK_TRACE_PATTERNS = [
    re.compile(r"Exception in thread",               re.I),
    re.compile(r"Traceback \(most recent call last\)", re.I),
    re.compile(r"at .*\.java:\d+",                   re.I),
]

BACKUP_FILE_RE = re.compile(
    r"\.(bak|old|backup|orig|save|swp|tmp|copy|dist)$|~$", re.I
)

# ─────────────────────────────────────────────────────────────────────────────
# DETECTION HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    return (text or "")[:MAX_SNIPPET_LEN]

def _domain_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def detect_versions(body: str) -> list[str]:
    return [m.group(0) for p in VERSION_PATTERNS if (m := p.search(body))]

def detect_directory_listing(body: str) -> bool:
    return any(p.search(body) for p in DIR_LISTING_PATTERNS)

def detect_stack_trace(body: str) -> bool:
    return any(p.search(body) for p in STACK_TRACE_PATTERNS)

def detect_backup_file(url: str) -> bool:
    return bool(BACKUP_FILE_RE.search(urlparse(url).path))


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_status(
    entry:       dict,
    reporter,
    page_id:     Optional[int] = None,
    _seen:       Optional[set] = None,
) -> None:
    """
    Inspect a single HTTP network event for status-code-level information
    disclosure and report findings through reporter.report().

    Parameters
    ──────────
    entry    — one "http"-type event.  Keys: url, status_code, body, headers.
    reporter — Reporter instance.
    page_id  — pages.id FK forwarded to reporter.
    _seen    — per-scan dedup set (caller-owned).  Pass the same set for all
               events in a scan session.

    Dedup strategy
    ──────────────
    Version disclosure  → DOMAIN-level:
      The server version string comes from the same process on every error
      page — one finding per origin is enough. First hit inserts; subsequent
      hits append the page URL via reporter.append_evidence_page().

    Directory listing, stack trace, backup file → URL-level:
      Each URL exposes distinct content; report every occurrence separately.

    All four checks are collected into a task list and run concurrently via
    asyncio.gather.  _seen is mutated synchronously before any await so
    concurrent tasks for the same key cannot double-insert.
    """
    if _seen is None:
        _seen = set()

    try:
        url         = entry.get("url", "")
        status_code = entry.get("status_code")
        body        = entry.get("body") or ""
        headers     = entry.get("headers", {})

        if not url or status_code is None:
            return

        snippet = _snippet(body)
        domain  = _domain_root(url)
        tasks   = []

        # ── Dedup helpers ──────────────────────────────────────────────────
        # _seen is mutated synchronously (before any await) so asyncio.gather
        # tasks for different checks are safe — they each read/write _seen in
        # the synchronous head of the coroutine before yielding.

        def _first(scope: str, tag: str) -> bool:
            return (scope, tag) not in _seen

        def _mark(scope: str, tag: str):
            _seen.add((scope, tag))

        # ── 1. Server Version Disclosure ───────────────────────────────────
        # DOMAIN-level: the server binary is the same for every error page on
        # an origin — one finding per domain, subsequent pages appended.
        if status_code in INFO_DISCLOSURE_CODES:
            versions = detect_versions(body)
            if versions:
                tag = "server_version_disclosure"
                is_first = _first(domain, tag)
                _mark(domain, tag)

                async def _version_check(is_first=is_first, versions=versions):
                    if not is_first:
                        await reporter.append_evidence_page(domain, "Server Version Disclosure in Error Page", url)
                        return
                    scores = build_ai_scores("server_header_version", url)
                    meta   = scores.pop("_meta", {})
                    await reporter.report(
                        page_url=domain,
                        title="Server Version Disclosure in Error Page",
                        category="information_disclosure",
                        confidence="high",
                        page_id=page_id,
                        evidence={
                            "status_code": status_code,
                            "versions":    versions,
                            "snippet":     snippet,
                            "affected_pages": [url],
                        },
                        raw_data={
                            "detected_versions": versions,
                            "response_headers":  headers,
                            **meta,
                        },
                        cwe="CWE-200",
                        wasc="WASC-13",
                        reference=(
                            "https://owasp.org/www-project-web-security-testing-guide"
                            "/latest/4-Web_Application_Security_Testing"
                            "/01-Information_Gathering/02-Fingerprint_Web_Server"
                        ),
                        dedup_key=(domain, "Server Version Disclosure in Error Page", "information_disclosure"),
                        **scores,
                    )
                    logger.info(f"[Status] Version disclosure at {domain}: {versions}")

                tasks.append(_version_check())

        # ── 2. Directory Listing ───────────────────────────────────────────
        # URL-level: each directory URL exposes different file listings.
        if status_code in INFO_DISCLOSURE_CODES and detect_directory_listing(body):
            tag      = "directory_listing"
            is_first = _first(url, tag)
            _mark(url, tag)

            if is_first:
                async def _dir_listing():
                    scores = build_ai_scores("directory_listing", url)
                    meta   = scores.pop("_meta", {})
                    await reporter.report(
                        page_url=url,
                        title="Directory Listing Detected",
                        category="information_disclosure",
                        confidence="medium",
                        page_id=page_id,
                        evidence={"status_code": status_code, "snippet": snippet},
                        raw_data={"response_headers": headers, **meta},
                        cwe="CWE-548",
                        wasc="WASC-13",
                        reference=(
                            "https://owasp.org/www-project-web-security-testing-guide"
                            "/latest/4-Web_Application_Security_Testing"
                            "/02-Configuration_and_Deployment_Management_Testing"
                            "/09-Test_File_Permission"
                        ),
                        dedup_key=(url, "Directory Listing Detected", "information_disclosure"),
                        **scores,
                    )
                    logger.info(f"[Status] Directory listing at {url}")

                tasks.append(_dir_listing())

        # ── 3. Stack Trace / Debug Info ────────────────────────────────────
        # URL-level: different error pages may expose different stack frames.
        if status_code in INFO_DISCLOSURE_CODES and detect_stack_trace(body):
            tag      = "stack_trace_exposed"
            is_first = _first(url, tag)
            _mark(url, tag)

            if is_first:
                async def _stack_trace():
                    scores = build_ai_scores("stack_trace_exposed", url)
                    meta   = scores.pop("_meta", {})
                    await reporter.report(
                        page_url=url,
                        title="Stack Trace / Debug Info Disclosed",
                        category="information_disclosure",
                        confidence="high",
                        page_id=page_id,
                        evidence={"status_code": status_code, "snippet": snippet},
                        raw_data={"response_headers": headers, **meta},
                        cwe="CWE-209",
                        wasc="WASC-13",
                        reference=(
                            "https://owasp.org/www-project-web-security-testing-guide"
                            "/latest/4-Web_Application_Security_Testing"
                            "/08-Testing_for_Error_Handling"
                            "/01-Testing_For_Improper_Error_Handling"
                        ),
                        dedup_key=(url, "Stack Trace / Debug Info Disclosed", "information_disclosure"),
                        **scores,
                    )
                    logger.info(f"[Status] Stack trace disclosed at {url}")

                tasks.append(_stack_trace())

        # ── 4. Backup / Old File ───────────────────────────────────────────
        # URL-level: each backup URL is a distinct file exposure.
        # 200 → confirmed exposure (backup_file_exposed, high)
        # 4xx/5xx → detected but blocked (sensitive_file_restricted, medium)
        if status_code in BACKUP_CHECK_CODES and detect_backup_file(url):
            tag      = "backup_file"
            is_first = _first(url, tag)
            _mark(url, tag)

            if is_first:
                exposed    = status_code == 200
                profile    = "backup_file_exposed" if exposed else "sensitive_file_restricted"
                confidence = "high"               if exposed else "medium"
                title      = (
                    "Backup / Old File Exposed"
                    if exposed else
                    "Backup / Old File Detected (Access Restricted)"
                )

                async def _backup(profile=profile, confidence=confidence, title=title, exposed=exposed):
                    scores = build_ai_scores(profile, url)
                    meta   = scores.pop("_meta", {})
                    await reporter.report(
                        page_url=url,
                        title=title,
                        category="information_disclosure",
                        confidence=confidence,
                        page_id=page_id,
                        evidence={
                            "status_code": status_code,
                            "snippet":     snippet,
                            "exposed":     exposed,
                        },
                        raw_data={"response_headers": headers, **meta},
                        cwe="CWE-530",
                        wasc="WASC-13",
                        reference=(
                            "https://owasp.org/www-project-web-security-testing-guide"
                            "/latest/4-Web_Application_Security_Testing"
                            "/02-Configuration_and_Deployment_Management_Testing"
                            "/04-Review_Old_Backup_and_Unreferenced_Files"
                        ),
                        dedup_key=(url, title, "information_disclosure"),
                        **scores,
                    )
                    logger.info(
                        f"[Status] Backup file at {url} — HTTP {status_code} "
                        f"({'EXPOSED' if exposed else 'restricted'})"
                    )

                tasks.append(_backup())

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"[Status] Check failed for {url}: {r}", exc_info=False)

    except Exception as e:
        logger.error(
            f"[Status Analyzer] Error on {entry.get('url', '?')}: {e}",
            exc_info=True,
        )