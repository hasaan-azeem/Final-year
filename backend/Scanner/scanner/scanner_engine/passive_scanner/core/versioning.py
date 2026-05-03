import re
import asyncio
import logging
from urllib.parse import urlparse, urlunparse

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.versioning")

MAX_SNIPPET_LEN = 120
MAX_BODY_SIZE = 2_000_000  # 2MB safety cap


# ─────────────────────────────────────────────────────────────────────────────
# PATTERNS (Optimized)
# ─────────────────────────────────────────────────────────────────────────────

CMS_META_PATTERN = re.compile(
    r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']{1,200})["\']',
    re.I,
)

JS_LIB_PATTERN = re.compile(
    r'/([a-zA-Z0-9_\-]{2,50})[.-]v?(\d+\.\d+(?:\.\d+)?)\.js\b',
    re.I,
)

JS_QUERY_VERSION_PATTERN = re.compile(
    r'\.js\?ver=(\d+\.\d+(?:\.\d+)?)',
    re.I,
)

HTML_COMMENT_VERSION_PATTERN = re.compile(
    r'<!--\s*version[: ]*([^\s]{1,50})\s*-->',
    re.I,
)

SERVER_VERSION_PATTERN = re.compile(
    r'(apache|nginx|iis|express|php)[/\s]?(\d+\.\d+(?:\.\d+)?)',
    re.I,
)


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _truncate(text: str) -> str:
    return text[:MAX_SNIPPET_LEN] + ("..." if len(text) > MAX_SNIPPET_LEN else "")


def _normalize_url(url: str) -> str:
    p = urlparse(url)
    return urlunparse(p._replace(
        path=p.path.rstrip("/"),
        query="",
        fragment=""
    ))


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_versioning(entry: dict, reporter, page_id=None, endpoint_id=None, _seen: set = None):
    if _seen is None:
        _seen = set()

    url = entry.get("url")
    if not url:
        return

    normalized_url = _normalize_url(url)
    parsed = urlparse(normalized_url)
    domain = parsed.netloc
    scheme = parsed.scheme
    domain_url = f"{scheme}://{domain}"

    headers = {k.lower(): str(v) for k, v in (entry.get("headers") or {}).items()}
    body = entry.get("body") or ""
    resource_type = entry.get("resource_type", "")

    # ─────────────────────────────────────────────────────────────────────────
    # FAST FAILS (Performance)
    # ─────────────────────────────────────────────────────────────────────────
    if resource_type not in ("document", "html", ""):
        return

    if len(body) > MAX_BODY_SIZE:
        logger.debug(f"[Versioning] Skipped large body: {normalized_url}")
        return

    tasks = []

    try:
        # ─────────────────────────────────────────────────────────────────────
        # 1. SERVER HEADERS (DOMAIN-LEVEL)
        # ─────────────────────────────────────────────────────────────────────
        for header_name in ("server", "x-powered-by"):
            value = headers.get(header_name)
            if not value:
                continue

            for tech, version in SERVER_VERSION_PATTERN.findall(value):
                title = f"{header_name.title()} Version Disclosure"

                seen_key = (domain, title, tech.lower())
                if seen_key in _seen:
                    if normalized_url != domain_url:
                        tasks.append(
                            reporter.append_evidence_page(
                                page_url=domain_url,
                                title=title,
                                append_url=normalized_url,
                            )
                        )
                    continue

                _seen.add(seen_key)

                scores = build_ai_scores("server_header_version", domain_url)
                meta = scores.pop("_meta")

                tasks.append(
                    reporter.report(
                        page_url=domain_url,
                        title=title,
                        category="versioning",
                        confidence="medium",
                        parameter_name=header_name,
                        evidence={
                            "header": header_name,
                            "technology": tech,
                            "version": version,
                            "raw_value": _truncate(value),
                            "affected_pages": [normalized_url],
                        },
                        raw_data=meta,
                        cwe="CWE-200",
                        wasc="WASC-15",
                        reference="https://owasp.org/www-community/vulnerabilities/Information_Leak_Through_Headers",
                        page_id=page_id,
                        endpoint_id=endpoint_id,
                        **scores,
                    )
                )

        # ─────────────────────────────────────────────────────────────────────
        # 2. CMS GENERATOR (PAGE-LEVEL)
        # ─────────────────────────────────────────────────────────────────────
        for generator in CMS_META_PATTERN.findall(body):
            title = "CMS Generator Meta Tag Detected"
            seen_key = (normalized_url, title, generator)

            if seen_key in _seen:
                continue
            _seen.add(seen_key)

            scores = build_ai_scores("cms_generator_exposed", normalized_url)
            meta = scores.pop("_meta")

            tasks.append(
                reporter.report(
                    page_url=normalized_url,
                    title=title,
                    category="versioning",
                    confidence="medium",
                    evidence={
                        "meta_generator": _truncate(generator),
                    },
                    raw_data=meta,
                    cwe="CWE-200",
                    wasc="WASC-15",
                    reference="https://owasp.org/www-community/vulnerabilities/Information_Leak_Through_Meta_Tags",
                    page_id=page_id,
                    endpoint_id=endpoint_id,
                    **scores,
                )
            )

        # ─────────────────────────────────────────────────────────────────────
        # 3. JS LIB VERSION (PAGE-LEVEL)
        # ─────────────────────────────────────────────────────────────────────
        for lib_name, lib_version in JS_LIB_PATTERN.findall(body):
            title = "JavaScript Library Version Disclosure"
            seen_key = (normalized_url, title, lib_name, lib_version)

            if seen_key in _seen:
                continue
            _seen.add(seen_key)

            scores = build_ai_scores("js_lib_version_exposed", normalized_url)
            meta = scores.pop("_meta")

            tasks.append(
                reporter.report(
                    page_url=normalized_url,
                    title=title,
                    category="versioning",
                    confidence="medium",
                    evidence={
                        "library": lib_name,
                        "version": lib_version,
                    },
                    raw_data=meta,
                    cwe="CWE-200",
                    wasc="WASC-15",
                    reference="https://owasp.org/www-community/vulnerabilities/Information_Leak_Through_Filenames",
                    page_id=page_id,
                    endpoint_id=endpoint_id,
                    **scores,
                )
            )

        # ─────────────────────────────────────────────────────────────────────
        # 4. JS QUERY VERSION (PAGE-LEVEL)
        # ─────────────────────────────────────────────────────────────────────
        for version in JS_QUERY_VERSION_PATTERN.findall(body):
            title = "JavaScript Version Query Parameter Detected"
            seen_key = (normalized_url, title, version)

            if seen_key in _seen:
                continue
            _seen.add(seen_key)

            scores = build_ai_scores("js_query_version_exposed", normalized_url)
            meta = scores.pop("_meta")

            tasks.append(
                reporter.report(
                    page_url=normalized_url,
                    title=title,
                    category="versioning",
                    confidence="low",
                    evidence={
                        "version": version,
                    },
                    raw_data=meta,
                    cwe="CWE-200",
                    wasc="WASC-15",
                    reference="https://owasp.org/www-community/vulnerabilities/Information_Leak_Through_Query_Params",
                    page_id=page_id,
                    endpoint_id=endpoint_id,
                    **scores,
                )
            )

        # ─────────────────────────────────────────────────────────────────────
        # 5. HTML COMMENT VERSION (PAGE-LEVEL) ✅ (previously unused)
        # ─────────────────────────────────────────────────────────────────────
        for version in HTML_COMMENT_VERSION_PATTERN.findall(body):
            title = "HTML Comment Version Disclosure"
            seen_key = (normalized_url, title, version)

            if seen_key in _seen:
                continue
            _seen.add(seen_key)

            scores = build_ai_scores("html_comment_version", normalized_url)
            meta = scores.pop("_meta")

            tasks.append(
                reporter.report(
                    page_url=normalized_url,
                    title=title,
                    category="versioning",
                    confidence="low",
                    evidence={
                        "comment_version": version,
                    },
                    raw_data=meta,
                    cwe="CWE-200",
                    wasc="WASC-15",
                    reference="https://owasp.org/www-community/vulnerabilities/Information_Leak",
                    page_id=page_id,
                    endpoint_id=endpoint_id,
                    **scores,
                )
            )

        # ─────────────────────────────────────────────────────────────────────
        # EXECUTE ALL TASKS CONCURRENTLY ⚡
        # ─────────────────────────────────────────────────────────────────────
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    except Exception as e:
        logger.error(f"[Versioning] Failed on {normalized_url}: {str(e)[:120]}")