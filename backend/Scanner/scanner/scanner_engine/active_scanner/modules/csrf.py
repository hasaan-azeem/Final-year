"""
modules/csrf.py
"""
from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

from ..request_sender   import RequestSender, ScanResponse
from ..response_checker import build_evidence, build_raw_data
from ..utils.helpers    import (
    load_payloads, SEVERITY_MAP, LIKELIHOOD_MAP,
    compute_cvss, severity_level,
)

logger = logging.getLogger("webxguard.active_scanner.csrf")

_META: dict | None = None

# ── CSRF token field name patterns ────────────────────────────────────────────
_TOKEN_FIELD_RE = re.compile(
    r"^(csrf|_csrf|csrftoken|csrf_token|xsrf|xsrftoken|xsrf_token"
    r"|authenticity_token|requestverificationtoken|__requestverificationtoken"
    r"|antiforgerytoken|nonce|sesskey|logintoken)$",
    re.IGNORECASE,
)

_BODY_TOKEN_RE = re.compile(
    r'(?:sesskey|csrf[_\-]?token|xsrf[_\-]?token|authenticity_token'
    r'|requestverificationtoken|logintoken)'
    r'\s*[=:"\',\s]*([A-Za-z0-9_\-]{8,})',
    re.IGNORECASE,
)

_STATE_CHANGE_RE = re.compile(
    r"(delete|remove|update|edit|transfer|purchase|confirm|approve"
    r"|revoke|disable|enable|reset|submit|send)",
    re.IGNORECASE,
)

_REJECTED_STATUSES = frozenset({401, 403, 419, 422, 500, 501, 502, 503, 504})

_AUTH_FORM_URL_RE = re.compile(
    r"(login|signin|sign-in|register|signup|sign-up|logon|authenticate)",
    re.IGNORECASE,
)

_AUTH_INPUT_NAMES = frozenset({
    "tfuname", "tfupass", "username", "password",
    "email", "passwd", "pass", "pwd", "user",
})

_INLINE_META = {
    "meta": {
        "name":      "CSRF",
        "category":  "CSRF",
        "cwe":       "CWE-352",
        "wasc":      "WASC-9",
        "reference": "https://owasp.org/www-community/attacks/csrf",
    }
}

_TYPE_PLACEHOLDERS: dict[str, str] = {
    "email":    "probe@example.com",
    "password": "Probe1337!",
    "number":   "1",
    "tel":      "5550001234",
    "url":      "https://example.com",
    "date":     "2000-01-01",
    "text":     "test",
    "search":   "test",
    "hidden":   "test",
    "":         "test",
}


def _get_meta() -> dict:
    global _META
    if _META is None:
        try:
            _META = load_payloads("csrf")
        except Exception:
            logger.debug("[CSRF] csrf.json not found — using inline meta")
            _META = _INLINE_META
    return _META


def _url_path(url: str) -> str:
    return urlparse(url).path or "/"


def _form_has_token(inputs: list[dict], page_body: str) -> bool:
    for inp in inputs:
        name   = (inp.get("name")                          or "").strip()
        inp_id = (inp.get("input_id") or inp.get("id")    or "").strip()
        if (name   and _TOKEN_FIELD_RE.match(name)) or \
           (inp_id and _TOKEN_FIELD_RE.match(inp_id)):
            logger.debug("[CSRF] Token field found: name=%r id=%r", name, inp_id)
            return True
    if _BODY_TOKEN_RE.search(page_body):
        logger.debug("[CSRF] Body-embedded token found")
        return True
    return False


def _is_auth_form(url: str, inputs: list[dict]) -> bool:
    if _AUTH_FORM_URL_RE.search(url):
        return True
    names    = {(i.get("name") or "").lower() for i in inputs if i.get("name")}
    has_user = bool(names & {"tfuname", "username", "email", "user"})
    has_pass = bool(names & {"tfupass", "password", "passwd", "pass", "pwd"})
    return has_user and has_pass


def _is_state_changing_get(url: str) -> bool:
    return bool(_STATE_CHANGE_RE.search(url))


def _cross_origin_was_processed(resp: ScanResponse) -> bool:
    if resp.status in _REJECTED_STATUSES:
        logger.debug("[CSRF] Rejected — status %d", resp.status)
        return False

    if resp.redirected:
        final = resp.final_url.lower()
        if any(kw in final for kw in
               ("login", "signin", "sign-in", "auth", "sso", "cas")):
            logger.debug("[CSRF] Redirected to auth page: %s", resp.final_url)
            return False

    # ✅ FIX-8: use pre-computed body_lower — no repeated .lower() allocation
    body = resp.body_lower[:4000]
    login_hits = sum(body.count(kw) for kw in (
        "log in", "login", "sign in", "password", "username",
        "forgot password", "remember me",
    ))
    if login_hits >= 4:
        logger.debug("[CSRF] Response looks like login page (hits=%d)", login_hits)
        return False

    if re.search(r"(invalid.token|csrf.token|session.expired|forbidden)", body):
        logger.debug("[CSRF] Response body indicates token validation failure")
        return False

    return True


def _probe_data(inputs: list[dict]) -> dict:
    result = {}
    for inp in inputs:
        name = inp.get("name", "")
        if not name:
            continue
        inp_type    = (inp.get("type") or "text").lower()
        result[name] = _TYPE_PLACEHOLDERS.get(inp_type, _TYPE_PLACEHOLDERS["text"])
    return result


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  MODULE
# ╚══════════════════════════════════════════════════════════════════════════════

class CSRFModule:
    name     = "csrf"
    category = "CSRF"

    def __init__(self, sender: RequestSender, oob_host: str = "") -> None:
        self.sender   = sender
        self.oob_host = oob_host
        self._seen: set[tuple[str, str]] = set()
        # ✅ FIX-10: removed self._samesite_reported — it was declared but never
        #            read or written (cookie dedup used self._seen throughout).

    def reset(self) -> None:
        self._seen.clear()

    def _already_seen(self, url: str, check: str) -> bool:
        key = (_url_path(url), check)
        if key in self._seen:
            logger.debug("[CSRF] Dedup skip (%s, %s)", *key)
            return True
        self._seen.add(key)
        return False

    # ── Entry points ──────────────────────────────────────────────────────────

    async def scan_endpoint(self, endpoint: dict, session_id: str,
                            domain_id: int) -> list[dict]:
        return []

    async def scan_form(self, form: dict, inputs: list[dict],
                        session_id: str, domain_id: int) -> list[dict]:
        method   = (form.get("method") or "GET").upper()
        url      = form.get("action_url") or form.get("page_url", "")
        page_url = form.get("page_url", url)

        if method == "GET" and not _is_state_changing_get(url):
            return []
        if self._already_seen(url, "csrf_form"):
            return []

        page_resp = await self.sender.get(page_url)
        page_body = page_resp.body if page_resp else ""

        if _form_has_token(inputs, page_body):
            logger.debug("[CSRF] Form at %s is token-protected — skip", url)
            return []

        auth_form = _is_auth_form(url, inputs)
        findings: list[dict] = []

        findings.append(self._missing_token_finding(
            url, page_url, domain_id, form.get("id"), auth_form,
        ))

        if method == "POST":
            data = _probe_data(inputs)
            resp = await self.sender.post(
                url, data=data,
                extra_headers={
                    "Origin":  "https://attacker.evil.com",
                    "Referer": "https://attacker.evil.com/csrf.html",
                },
            )
            if resp and _cross_origin_was_processed(resp):
                logger.info(
                    "[CSRF] Cross-origin POST processed url=%s status=%d auth=%s",
                    url, resp.status, auth_form,
                )
                findings.append(self._cross_origin_finding(
                    url, page_url, resp, domain_id, form.get("id"), auth_form,
                ))
            else:
                logger.debug("[CSRF] Cross-origin POST rejected for %s", url)

        return findings

    async def scan_page(self, page: dict, session_id: str,
                        domain_id: int) -> list[dict]:
        findings: list[dict] = []
        url  = page.get("url", "")
        resp = await self.sender.get(url)
        if resp is None:
            return findings

        # ✅ FIX-9: iterate headers_lower (keys already lowercase) — no per-key
        #           .lower() call needed, and no new dict allocation per request
        for header_name, header_val in resp.headers_lower.items():
            if header_name != "set-cookie":
                continue

            val_lower = header_val.lower()
            is_session_cookie = any(kw in val_lower for kw in
                                    ("session", "sess", "auth", "token", "sid"))
            has_samesite_none = "samesite=none" in val_lower
            missing_samesite  = "samesite" not in val_lower

            if not is_session_cookie or not (has_samesite_none or missing_samesite):
                continue

            cookie_name = header_val.split("=")[0].strip()
            key = (_url_path(url), f"samesite:{cookie_name}")
            if key in self._seen:
                continue
            self._seen.add(key)

            reason = ("SameSite=None set explicitly"
                      if has_samesite_none else "SameSite attribute missing")
            logger.info("[CSRF] SameSite issue cookie=%s url=%s", cookie_name, url)

            f = self._base(domain_id, url,
                           "CSRF — Session Cookie Missing SameSite Protection",
                           "firm")
            f.update({
                "vuln_type":      "csrf",
                "url":            url,
                "parameter_name": "Set-Cookie",
                "payload":        None,
                "evidence":       {
                    "check":  reason,
                    "cookie": cookie_name,
                    "header": header_val[:200],
                },
                "raw_data": {"cookie": cookie_name, "reason": reason},
            })
            findings.append(f)

        return findings

    # ── Finding factories ─────────────────────────────────────────────────────

    def _base(self, domain_id: int, page_url: str, title: str,
              confidence: str, form_id=None) -> dict:
        cvss = compute_cvss(vuln_type="csrf")
        sev  = SEVERITY_MAP["csrf"]
        lh   = LIKELIHOOD_MAP.get(confidence, 0.4)
        meta = _get_meta()["meta"]
        return {
            "domain_id":         domain_id,
            "page_url":          page_url,
            "title":             title,
            "category":          self.category,
            "confidence":        confidence,
            "cwe":               meta["cwe"],
            "wasc":              meta["wasc"],
            "reference":         meta["reference"],
            "form_id":           form_id,
            "severity":          sev,
            "likelihood":        lh,
            "impact":            sev,
            "cvss_score":        cvss,
            "exploit_available": False,
            "severity_level":    severity_level(cvss),
        }

    def _missing_token_finding(self, url: str, page_url: str, domain_id: int,
                                form_id, auth_form: bool) -> dict:
        if auth_form:
            title = "CSRF — Missing Anti-CSRF Token (Login/Register Form)"
            check = ("No CSRF token found in authentication form. "
                     "Allows login CSRF: an attacker can force a victim to "
                     "log in as the attacker's account.")
        else:
            title = "CSRF — Missing Anti-CSRF Token"
            check = "No CSRF token field found in POST form."

        f = self._base(domain_id, page_url, title, "certain", form_id)
        f.update({
            "vuln_type":      "csrf",
            "url":            url,
            "parameter_name": None,
            "payload":        None,
            "evidence":       {"check": check, "form_action": url},
            "raw_data":       {"form_action": url},
        })
        return f

    def _cross_origin_finding(self, url: str, page_url: str,
                               resp: ScanResponse, domain_id: int,
                               form_id, auth_form: bool) -> dict:
        if auth_form:
            title = "CSRF — Cross-Origin POST Accepted (Login/Register Form)"
            note  = ("Authentication form accepted a cross-origin POST without "
                     "a CSRF token. Enables login CSRF — forcing a victim to "
                     "authenticate as the attacker's account.")
        else:
            title = "CSRF — Cross-Origin POST Accepted Without Token"
            note  = "Server processed a cross-origin POST with no CSRF token."

        f = self._base(domain_id, page_url, title, "certain", form_id)
        f.update({
            "vuln_type":         "csrf",
            "url":               url,
            "parameter_name":    "Origin",
            "payload":           "Origin: https://attacker.evil.com",
            "evidence":          build_evidence(
                                     "POST", url,
                                     {"Origin": "https://attacker.evil.com"},
                                     resp,
                                     f"Response: {resp.status} — {note}"),
            "raw_data":          build_raw_data("cross-origin", "Origin", resp),
            "exploit_available": True,
        })
        return f