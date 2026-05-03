import re
import asyncio
import logging
from typing import Optional
from urllib.parse import urlparse, urljoin

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.forms")

MAX_SNIPPET_LEN   = 100
MAX_INPUTS_LOGGED = 10
MAX_BODY_SCAN     = 200_000

SESSION_KEYWORDS       = {"session", "auth", "token", "jwt", "sid"}
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# ─────────────────────────────────────────────────────────────────────────────
# PRECOMPILED REGEX
# ─────────────────────────────────────────────────────────────────────────────

FORM_REGEX  = re.compile(r"<form\b(.*?)>(.*?)</form>", re.I | re.S)
INPUT_REGEX = re.compile(r"<input\b(.*?)>",            re.I | re.S)

_ATTR_CACHE: dict[str, re.Pattern] = {}   # FIX: was dict[tuple[str,str], ...]; key is str not tuple

def _attr_re(attr_name: str) -> re.Pattern:
    key = attr_name.lower()
    if key not in _ATTR_CACHE:
        # Use lowercased name so the cached pattern is consistent with the key.
        _ATTR_CACHE[key] = re.compile(
            rf'{re.escape(key)}\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s>]*))',
            re.I,
        )
    return _ATTR_CACHE[key]


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snippet(text: str) -> str:
    return (text or "")[:MAX_SNIPPET_LEN]

def _domain_root(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"

def extract_attr(attrs: str, attr_name: str) -> str:
    m = _attr_re(attr_name).search(attrs)
    if not m:
        return ""
    return (m.group(1) or m.group(2) or m.group(3) or "").strip()

def has_session_cookie(entry: dict) -> bool:
    for cookie in entry.get("cookies", []):
        if any(k in cookie.get("name", "").lower() for k in SESSION_KEYWORDS):
            return True
    return False

def likely_csrf_field(name: str, input_type: str) -> bool:
    """Detect common CSRF token fields used by frameworks."""
    if input_type != "hidden" or not name:
        return False
    n = name.lower()
    CSRF_NAMES = (
        "csrf",
        "xsrf",
        "token",
        "_token",
        "authenticity",
        "nonce",
        "sesskey",                     # Moodle
        "__requestverificationtoken",  # ASP.NET
        "_wpnonce",                    # WordPress
    )
    return any(x in n for x in CSRF_NAMES)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ANALYZER
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_forms(
    entry:   dict,
    reporter,
    page_id: Optional[int] = None,
    _seen:   Optional[set] = None,
) -> None:
    """
    Parse HTML forms from a rendered page and report:
      1. Password fields submitted over plain HTTP.
      2. Forms that POST to an external domain.
      3. State-changing forms (POST/PUT/PATCH/DELETE) with a session cookie
         but no CSRF token field.

    Parameters
    ──────────
    entry    — one "http"-type event.  Keys: url, body, status_code, cookies.
    reporter — Reporter instance.
    page_id  — pages.id FK forwarded to reporter.
    _seen    — per-scan dedup set (caller-owned).

    Dedup strategy
    ──────────────
    Check 1 (password over HTTP)  → PAGE-level.
      The specific page URL is needed to direct the fix; different login pages
      are distinct findings.

    Check 2 (external submission) → DOMAIN-level.
      Whether a site submits data to external-evil.com is a site-wide concern;
      which page the form lives on is secondary evidence.  First hit inserts
      with affected_pages=[url]; subsequent hits call append_evidence_page.
      Dedup key includes the external domain so each distinct external target
      gets its own finding.

    Check 3 (CSRF missing)        → PAGE-level.
      Individual forms on individual pages may or may not include a CSRF
      token; each unprotected (page, action) pair is a distinct finding.

    All checks per form are collected into a task list and flushed with
    asyncio.gather.  _seen is mutated synchronously before any await so
    concurrent tasks cannot double-insert the same key.
    """
    if _seen is None:
        _seen = set()

    try:
        url         = entry.get("url", "")
        body        = entry.get("body") or ""
        status_code = entry.get("status_code")

        if not url or not body or status_code != 200:
            return

        body = body[:MAX_BODY_SCAN]

        parsed_page     = urlparse(url)
        domain          = _domain_root(url)
        session_present = has_session_cookie(entry)
        forms           = FORM_REGEX.findall(body)

        if not forms:
            return

        all_tasks: list = []

        for form_attrs, form_inner in forms:

            # ── Parse form metadata ───────────────────────────────────────
            method        = extract_attr(form_attrs, "method").upper() or "GET"
            raw_action    = extract_attr(form_attrs, "action")
            action_full   = urljoin(url, raw_action) if raw_action else url
            parsed_action = urlparse(action_full)

            # ── Parse inputs ──────────────────────────────────────────────
            inputs         = INPUT_REGEX.findall(form_inner)
            input_evidence = []
            has_password   = False
            csrf_found     = False

            for input_attrs in inputs:
                input_type = extract_attr(input_attrs, "type").lower() or "text"
                input_name = extract_attr(input_attrs, "name")

                if len(input_evidence) < MAX_INPUTS_LOGGED:
                    input_evidence.append({"name": input_name, "type": input_type})

                if input_type == "password":
                    has_password = True
                if input_name and likely_csrf_field(input_name, input_type):
                    csrf_found = True

            form_tasks: list = []

            # ── 1. Password field over HTTP ───────────────────────────────
            # Page-level: the specific page URL tells devs where to fix it.
            if has_password and (
                parsed_page.scheme   == "http" or
                parsed_action.scheme == "http"
            ):
                reasons = []
                if parsed_page.scheme   == "http":
                    reasons.append("page served over HTTP")
                if parsed_action.scheme == "http":
                    reasons.append("form action targets HTTP endpoint")

                seen_key = (url, "Password Form Submitted Over HTTP")
                if seen_key not in _seen:
                    _seen.add(seen_key)

                    async def _password_http(reasons=reasons, action_full=action_full, method=method):
                        scores = build_ai_scores("http_no_https", url)
                        meta   = scores.pop("_meta", {})
                        await reporter.report(
                            page_url=url,
                            title="Password Form Submitted Over HTTP",
                            category="forms",
                            confidence="high",
                            page_id=page_id,
                            evidence={
                                "action":  _snippet(action_full),
                                "reasons": reasons,
                                "inputs":  input_evidence,
                            },
                            raw_data={"method": method, "action_full": action_full, **meta},
                            cwe="CWE-319",
                            wasc="WASC-8",
                            reference=(
                                "https://owasp.org/www-project-top-ten/"
                                "2017/A3_2017-Sensitive_Data_Exposure.html"
                            ),
                            dedup_key=(url, "Password Form Submitted Over HTTP", "forms"),
                            **scores,
                        )
                        logger.info(f"[Forms] Password over HTTP: {url}")

                    form_tasks.append(_password_http())

            # ── 2. Form submits to external domain ────────────────────────
            # Domain-level: that THIS SITE submits to external-evil.com is the
            # finding; the individual pages are secondary evidence.
            # A distinct finding per external target domain is preserved by
            # including parsed_action.netloc in the dedup key.
            if (
                parsed_action.netloc and
                parsed_action.netloc != parsed_page.netloc
            ):
                ext_domain = parsed_action.netloc
                profile    = "form_external_submission_pw" if has_password else "form_external_submission"
                confidence = "high"                        if has_password else "medium"
                title      = "Form Submits Data to External Domain"
                domain_key = (domain, f"{title}::{ext_domain}")
                is_first   = domain_key not in _seen
                _seen.add(domain_key)

                async def _external_submit(
                    is_first=is_first, ext_domain=ext_domain,
                    profile=profile, confidence=confidence,
                    action_full=action_full, method=method,
                ):
                    if not is_first:
                        await reporter.append_evidence_page(domain, title, url)
                        return
                    scores = build_ai_scores(profile, url)
                    meta   = scores.pop("_meta", {})
                    await reporter.report(
                        page_url=domain,
                        title=title,
                        category="forms",
                        confidence=confidence,
                        page_id=page_id,
                        evidence={
                            "form_action":        _snippet(action_full),
                            "external_domain":    ext_domain,
                            "has_password_field": has_password,
                            "inputs":             input_evidence,
                            "affected_pages":     [url],
                        },
                        raw_data={"method": method, "action_full": action_full, **meta},
                        cwe="CWE-200",
                        wasc="WASC-13",
                        reference=(
                            "https://owasp.org/www-project-web-security-testing-guide/"
                            "latest/4-Web_Application_Security_Testing"
                            "/11-Client_Side_Testing/01-Testing_for_DOM-Based_Cross_Site_Scripting"
                        ),
                        dedup_key=(domain, f"{title}::{ext_domain}", "forms"),
                        **scores,
                    )
                    logger.info(f"[Forms] External form → {ext_domain}: {url}")

                form_tasks.append(_external_submit())

            # ── 3. CSRF token missing on state-changing form ───────────────
            # FIX: this check was fully documented and set up (STATE_CHANGING_METHODS,
            # session_present, csrf_found) but never implemented — both session_present
            # and csrf_found were dead variables that triggered no report.
            #
            # Page-level: individual forms on individual pages may vary; each
            # unprotected (url, action) pair is a distinct finding.
            # Dedup key includes action_full so multiple forms on the same page
            # each get their own row if they independently lack a CSRF token.
            if (
                method in STATE_CHANGING_METHODS and
                session_present and
                not csrf_found
            ):
                seen_key = (url, f"CSRF Token Missing in Form::{action_full}")
                if seen_key not in _seen:
                    _seen.add(seen_key)

                    async def _csrf_missing(action_full=action_full, method=method):
                        scores = build_ai_scores("csrf_missing", url)
                        meta   = scores.pop("_meta", {})
                        await reporter.report(
                            page_url=url,
                            title="CSRF Token Missing in State-Changing Form",
                            category="forms",
                            confidence="medium",
                            page_id=page_id,
                            evidence={
                                "form_action":  _snippet(action_full),
                                "method":       method,
                                "inputs":       input_evidence,
                                "session_cookie_present": True,
                            },
                            raw_data={"method": method, "action_full": action_full, **meta},
                            cwe="CWE-352",
                            wasc="WASC-9",
                            reference=(
                                "https://owasp.org/www-project-web-security-testing-guide/"
                                "latest/4-Web_Application_Security_Testing"
                                "/06-Session_Management_Testing"
                                "/05-Testing_for_Cross_Site_Request_Forgery"
                            ),
                            dedup_key=(url, f"CSRF Token Missing in State-Changing Form::{action_full}", "forms"),
                            **scores,
                        )
                        logger.info(f"[Forms] CSRF missing — {method} {action_full} on {url}")

                    form_tasks.append(_csrf_missing())

            all_tasks.extend(form_tasks)

        if all_tasks:
            results = await asyncio.gather(*all_tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.error(f"[Forms] Check failed for {url}: {r}", exc_info=False)

    except Exception as e:
        logger.error(
            f"[Forms] Error on {entry.get('url', '?')}: {e}",
            exc_info=True,
        )