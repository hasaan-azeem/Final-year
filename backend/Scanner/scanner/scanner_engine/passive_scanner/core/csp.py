import re
import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.csp")

MAX_SNIPPET_LEN = 100


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _truncate(text: str) -> str:
    return text[:MAX_SNIPPET_LEN] if text else ""

def _domain_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def _is_html_response(event: dict) -> bool:
    content_type = event.get("headers", {}).get("content-type", "").lower()
    return "text/html" in content_type

def _boost_confidence(base: str, sensitive: bool) -> str:
    return "high" if sensitive and base == "medium" else base

def _is_sensitive_path(path: str) -> bool:
    from ..scoring import _TIERS
    path = path.lower()
    for multiplier, prefixes in _TIERS:
        if multiplier >= 1.30 and any(path.startswith(p) for p in prefixes):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# CSP PARSERS
# ─────────────────────────────────────────────────────────────────────────────

def _parse_csp(csp: str) -> dict:
    """Return dict of directive → value string."""
    directives = {}
    for part in csp.split(";"):
        part = part.strip()
        if not part:
            continue
        if " " in part:
            key, value = part.split(None, 1)
            directives[key.lower()] = value.strip()
        else:
            directives[part.lower()] = ""
    return directives

def _check_unsafe(directives: dict) -> list[tuple[str, str]]:
    """Returns list of (profile_key, description) for unsafe-inline/eval."""
    found = []
    for directive, value in directives.items():
        if "unsafe-inline" in value:
            found.append(("csp_unsafe_inline", f"{directive}: 'unsafe-inline'"))
        if "unsafe-eval" in value:
            found.append(("csp_unsafe_eval", f"{directive}: 'unsafe-eval'"))
    return found

def _check_wildcards(directives: dict) -> list[tuple[str, str]]:
    """Returns list of (profile_key, description) for wildcard sources."""
    found = []
    for directive in [
        "script-src", "style-src", "img-src", "connect-src",
        "font-src", "media-src", "default-src",
    ]:
        if "*" in directives.get(directive, ""):
            found.append(("csp_wildcard", f"{directive}: *"))
    return found

def _check_missing_directives(directives: dict) -> list[tuple[str, str, str]]:
    """Returns list of (profile_key, directive_name, title) for missing critical directives."""
    missing = []
    checks = [
        ("frame-ancestors", "csp_missing_directives", "Content-Security-Policy Missing frame-ancestors (Clickjacking Risk)"),
        ("object-src",      "csp_missing_directives", "Content-Security-Policy Missing object-src"),
        ("base-uri",        "csp_missing_directives", "Content-Security-Policy Missing base-uri"),
    ]
    for directive, profile_key, title in checks:
        if directive not in directives:
            missing.append((profile_key, directive, title))
    return missing

def _check_nonce_hash_absence(directives: dict) -> list[str]:
    """Inline scripts/styles using unsafe-inline without a nonce or hash."""
    issues = []
    for src_type in ["script-src", "style-src"]:
        value = directives.get(src_type, "")
        if "'unsafe-inline'" in value and not re.search(r"'nonce-|'sha\d+-", value):
            issues.append(src_type)
    return issues

def _check_sandbox_issues(directives: dict) -> list[tuple[str, str, str]]:
    """
    Check the sandbox directive value for dangerous allowances.

    FIX: original checks 7 and 8 both had bugs:
      - Check 7 iterated over ["allow-forms", "allow-scripts", "allow-same-origin"]
        testing `if value in directives` — i.e. checking TOP-LEVEL directive keys.
        These are sandbox values, not top-level directives, so check 7 NEVER fired.
      - Check 8 correctly read directives.get("sandbox") but only tested
        allow-same-origin, which overlapped with the (broken) check 7.

    Fixed: one combined function that reads the sandbox value and returns a
    finding per dangerous flag it contains.  allow-same-origin gets a higher
    confidence than allow-forms/allow-scripts because it breaks the sandbox's
    origin isolation entirely.
    """
    sandbox_value = directives.get("sandbox", "")
    if not sandbox_value:
        return []

    issues = []
    # allow-same-origin in a sandbox defeats origin isolation — treat as high.
    if "allow-same-origin" in sandbox_value:
        issues.append((
            "csp_wildcard",
            "allow-same-origin",
            "CSP sandbox Allows Same-Origin (Breaks Sandbox Isolation)",
        ))
    # allow-scripts lets injected code run inside the sandboxed context.
    if "allow-scripts" in sandbox_value:
        issues.append((
            "csp_unsafe_inline",
            "allow-scripts",
            "CSP sandbox Allows Script Execution",
        ))
    # allow-forms enables form submission from the sandboxed context.
    if "allow-forms" in sandbox_value:
        issues.append((
            "csp_missing_directives",
            "allow-forms",
            "CSP sandbox Allows Form Submission",
        ))
    return issues


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_csp(
    event: dict,
    reporter,
    page_id: Optional[int] = None,
    endpoint_id: Optional[int] = None,
    _seen: Optional[set] = None,
):
    """
    Analyze Content-Security-Policy header from a flat fetcher HTTP event.

    DEDUP: Domain-level.
      - First hit  → reporter.report(page_url=domain_root,
                         evidence={..., "affected_pages": [url]})
      - Subsequent → reporter.append_evidence_page(domain_root, title, url)

    All checks (2-8) are independent and run concurrently via asyncio.gather.
    Check 1 (missing CSP) short-circuits with an early return because there
    is nothing to parse if no header is present.

    Checks:
      1. Missing CSP entirely
      2. unsafe-inline / unsafe-eval per directive
      3. Wildcard sources in fetch directives
      4. Missing critical directives (frame-ancestors, object-src, base-uri)
      5. Missing report-uri / report-to
      6. unsafe-inline without nonce or hash
      7+8. Dangerous sandbox values (allow-same-origin, allow-scripts, allow-forms)
           FIX: merged from two broken checks into one correct function
    """
    if _seen is None:
        _seen = set()

    try:
        url         = event.get("url")
        raw_headers = event.get("headers", {})
        status_code = event.get("status_code")

        if not url or not isinstance(raw_headers, dict) or status_code != 200:
            return
        if not _is_html_response(event):
            return

        parsed      = urlparse(url)
        path        = parsed.path.lower() or "/"
        sensitive   = _is_sensitive_path(path)
        domain_root = _domain_root(url)

        headers    = {k.lower(): str(v) for k, v in raw_headers.items()}
        csp_header = headers.get("content-security-policy", "")

        raw_event = {
            "url":         url,
            "status_code": status_code,
            "path":        path,
        }

        # ── Dedup helpers ──────────────────────────────────────────────────
        # _mark() runs synchronously before any await so concurrent gather()
        # tasks for different checks cannot double-insert the same key.

        def _is_first(title: str) -> bool:
            return (domain_root, title) not in _seen

        def _mark(title: str):
            _seen.add((domain_root, title))

        async def _report_first(title, confidence, profile_key, evidence, cwe, wasc, ref):
            scores = build_ai_scores(profile_key, url)
            meta   = scores.pop("_meta", {})
            await reporter.report(
                page_url=domain_root,
                title=title,
                category="security_headers",
                confidence=confidence,
                page_id=page_id,
                endpoint_id=endpoint_id,
                evidence={**evidence, "affected_pages": [url]},
                raw_data={**raw_event, **meta},
                dedup_key=(domain_root, title, "security_headers"),
                cwe=cwe,
                wasc=wasc,
                reference=ref,
                **scores,
            )

        async def _fire(title, confidence, profile_key, evidence, cwe, wasc, ref):
            """Route to first insert or JSONB append; _mark before first await."""
            if _is_first(title):
                _mark(title)
                await _report_first(title, confidence, profile_key, evidence, cwe, wasc, ref)
            else:
                await reporter.append_evidence_page(domain_root, title, url)

        REF = (
            "https://owasp.org/www-project-web-security-testing-guide/latest/"
            "4-Web_Application_Security_Testing/10-HTTP_Headers_Testing/"
            "03-Test_Content_Security_Policy"
        )

        # ── 1. Missing CSP — early return, nothing left to parse ───────────
        # Domain-level: absence of CSP is a site-wide posture.
        if not csp_header:
            conf    = _boost_confidence("medium", sensitive)
            profile = "missing_csp_high" if conf == "high" else "missing_csp_medium"
            await _fire(
                title="Missing Content-Security-Policy",
                confidence=conf,
                profile_key=profile,
                evidence={"content-security-policy": "absent"},
                cwe="CWE-693",
                wasc="WASC-14",
                ref=REF,
            )
            logger.info(f"[CSP] Missing CSP: {url}")
            return

        directives = _parse_csp(csp_header)
        tasks = []

        # ── 2. unsafe-inline / unsafe-eval ────────────────────────────────
        for profile_key, description in _check_unsafe(directives):
            title = f"Weak CSP: {description}"
            tasks.append(_fire(
                title=title,
                confidence=_boost_confidence("medium", sensitive),
                profile_key=profile_key,
                evidence={"csp_issue": description, "csp_snippet": _truncate(csp_header)},
                cwe="CWE-079",
                wasc="WASC-08",
                ref=REF,
            ))

        # ── 3. Wildcard sources ────────────────────────────────────────────
        for profile_key, description in _check_wildcards(directives):
            directive_name = description.split(":")[0].strip()
            title = f"Weak CSP: Wildcard in {directive_name}"
            tasks.append(_fire(
                title=title,
                confidence=_boost_confidence("medium", sensitive),
                profile_key=profile_key,
                evidence={"csp_issue": description, "csp_snippet": _truncate(csp_header)},
                cwe="CWE-693",
                wasc="WASC-14",
                ref=REF,
            ))

        # ── 4. Missing critical directives ────────────────────────────────
        for profile_key, directive_name, title in _check_missing_directives(directives):
            tasks.append(_fire(
                title=title,
                confidence=_boost_confidence("medium", sensitive),
                profile_key=profile_key,
                evidence={"missing_directive": directive_name, "csp_snippet": _truncate(csp_header)},
                cwe="CWE-1021" if directive_name == "frame-ancestors" else "CWE-693",
                wasc="WASC-20" if directive_name == "frame-ancestors" else "WASC-14",
                ref=REF,
            ))

        # ── 5. Missing report-uri / report-to ─────────────────────────────
        if "report-uri" not in directives and "report-to" not in directives:
            tasks.append(_fire(
                title="Content-Security-Policy Missing report-uri / report-to",
                confidence=_boost_confidence("low", sensitive),
                profile_key="csp_missing_directives",
                evidence={"missing_directive": "report-uri/report-to", "csp_snippet": _truncate(csp_header)},
                cwe="CWE-693",
                wasc="WASC-14",
                ref=REF,
            ))

        # ── 6. unsafe-inline without nonce/hash ───────────────────────────
        for src_type in _check_nonce_hash_absence(directives):
            title = f"CSP {src_type} Allows Inline Without Nonce or Hash"
            tasks.append(_fire(
                title=title,
                confidence=_boost_confidence("medium", sensitive),
                profile_key="csp_unsafe_inline",
                evidence={"directive": src_type, "value": _truncate(directives.get(src_type, ""))},
                cwe="CWE-693",
                wasc="WASC-14",
                ref=REF,
            ))

        # ── 7+8. Sandbox issues (merged) ──────────────────────────────────
        # FIX: original check 7 tested sandbox values as top-level directive
        # keys — it never fired.  Check 8 only caught allow-same-origin.
        # Now: _check_sandbox_issues() reads the sandbox value correctly and
        # returns a distinct finding per dangerous flag present.
        for profile_key, flag, title in _check_sandbox_issues(directives):
            tasks.append(_fire(
                title=title,
                confidence=_boost_confidence("medium", sensitive),
                profile_key=profile_key,
                evidence={"sandbox": _truncate(directives.get("sandbox", "")), "flag": flag},
                cwe="CWE-693",
                wasc="WASC-14",
                ref=REF,
            ))

        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"[CSP] Check failed for {url}: {r}", exc_info=False)

    except Exception as e:
        logger.error(
            f"[CSP] Failed to analyze {event.get('url', 'unknown')}: "
            f"{str(e)[:MAX_SNIPPET_LEN]}",
            exc_info=True,
        )