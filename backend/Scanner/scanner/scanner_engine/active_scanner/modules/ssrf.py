"""
modules/ssrf.py
Improved SSRF detector
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse
import re as _re

from ..request_sender   import RequestSender, ScanResponse
from ..response_checker import build_evidence, build_raw_data, contains_any
from ..utils.helpers    import (
    load_payloads, inject_param, get_query_params,
    SEVERITY_MAP, LIKELIHOOD_MAP, compute_cvss, severity_level,
)

logger = logging.getLogger("webxguard.active_scanner.ssrf")


# ------------------------------------------------------------------
# Reflection stripping
# ------------------------------------------------------------------

_HREF_PATTERN = _re.compile(
    r"""(?:href|src|action|data-url|data-href)\s*=\s*["'][^"']*["']""",
    _re.IGNORECASE
)

_URL_ATTR_PATTERN = _re.compile(
    r"""(?:url|location|redirect)\s*[:=]\s*["'][^"']*["']""",
    _re.IGNORECASE
)


def _strip_url_contexts(body: str) -> str:
    body = _HREF_PATTERN.sub('href=""', body)
    body = _URL_ATTR_PATTERN.sub('url=""', body)
    return body


SAFE_VALUE = "https://example.com"

_SIZE_DIFF_MIN_BYTES = 200
_SIZE_DIFF_MIN_RATIO = 1.5

_META = None


def _get_meta():
    global _META
    if _META is None:
        _META = load_payloads("ssrf")
    return _META


def _url_path(url: str):
    return urlparse(url).path or "/"


def _is_internal_payload(value: str):
    return any(kw in value for kw in (
        "127.0.0.1",
        "169.254",
        "localhost",
        "0.0.0.0",
        "::1",
        "metadata.google",
        "169.254.169.254",
    ))


def _substitute_oob(value: str, oob_host: str):
    if "OOB_HOST" in value:
        if not oob_host:
            return None
        return value.replace("OOB_HOST", oob_host)
    return value


# ------------------------------------------------------------------
# param filtering (speed + FP reduction)
# ------------------------------------------------------------------

_NON_URL_PARAMS = frozenset({
    "password","passwd","pass","pwd",
    "username","user","email",
    "token","otp","pin",
    "phone","tel",
    "name","firstname","lastname",
    "search","query","q",
})


def _is_likely_url_param(param: str):
    p = param.lower().strip("[]")

    if p in _NON_URL_PARAMS:
        return False

    return any(x in p for x in (
        "url","uri","href","src","link",
        "redirect","return","next",
        "callback","target","dest",
        "endpoint","api","host",
        "path","file","page"
    ))


# ------------------------------------------------------------------
# SSRF module
# ------------------------------------------------------------------

class SSRFModule:

    name = "ssrf"
    category = "SSRF"

    def __init__(self, sender: RequestSender, oob_host: str = ""):
        self.sender = sender
        self.oob_host = oob_host
        self._seen = set()

    def _mark_seen(self, url, param):
        key = (_url_path(url), param)
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def _unmark(self, url, param):
        self._seen.discard((_url_path(url), param))

    # ---------------------------------------------------------

    async def scan_endpoint(self, endpoint, session_id, domain_id):

        meta = _get_meta()
        url = endpoint["url"]

        params = get_query_params(url)
        findings = []

        if not params:
            return findings

        ssrf_keys = {p.lower() for p in meta.get("ssrf_params", [])}

        priority = [p for p in params if p.lower() in ssrf_keys]
        remaining = [p for p in params if p.lower() not in ssrf_keys]

        for param in priority + remaining:

            if param.lower() not in ssrf_keys and not _is_likely_url_param(param):
                continue

            if self._mark_seen(url, param):
                continue

            f = await self._probe_param(
                url,
                param,
                meta,
                domain_id,
                endpoint.get("id")
            )

            if f:
                findings.extend(f)
            else:
                self._unmark(url, param)

        return findings
    
    async def scan_page(self, page, session_id, domain_id):
        """Server side Request Forgery is endpoint-based only — no page scanning."""
        return []
    
    async def scan_form(self, form, inputs, session_id, domain_id):
        """Server Side Request Forgery is endpoint-based only — no form scanning."""
        return []

    # ---------------------------------------------------------

    async def _probe_param(self, url, param, meta, domain_id, endpoint_id):

        baseline = await self.sender.get(
            inject_param(url, param, SAFE_VALUE)
        )

        baseline_body = baseline.body if baseline else ""

        findings = []

        for p in meta["payloads"]:

            payload = _substitute_oob(p["value"], self.oob_host)
            if payload is None:
                continue

            test_url = inject_param(url, param, payload)

            resp = await self.sender.get(test_url)
            if resp is None:
                continue

            f = self._check(
                resp=resp,
                baseline_body=baseline_body,
                test_url=test_url,
                page_url=url,
                param=param,
                payload=payload,
                meta=meta,
                domain_id=domain_id,
                endpoint_id=endpoint_id
            )

            if f:
                findings.append(f)

        return findings

    # ---------------------------------------------------------

    def _check(self,
               *,
               resp,
               baseline_body,
               test_url,
               page_url,
               param,
               payload,
               meta,
               domain_id,
               method="GET",
               endpoint_id=None,
               form_id=None):

        stripped_body = _strip_url_contexts(resp.body)
        stripped_base = _strip_url_contexts(baseline_body)

        match = contains_any(stripped_body, meta["indicators"])

        if match:

            if contains_any(stripped_base, meta["indicators"]):
                return None

            return self._build(
                url=test_url,
                page_url=page_url,
                param=param,
                payload=payload,
                resp=resp,
                match=str(match),
                confidence="certain",
                domain_id=domain_id,
                method=method,
                endpoint_id=endpoint_id,
                form_id=form_id,
            )

        # blind size diff

        if _is_internal_payload(payload) and resp.status == 200:

            base_len = len(baseline_body)
            resp_len = len(resp.body)

            diff = resp_len - base_len
            ratio = resp_len / max(base_len, 1)

            if diff >= _SIZE_DIFF_MIN_BYTES and ratio >= _SIZE_DIFF_MIN_RATIO:

                return self._build(
                    url=test_url,
                    page_url=page_url,
                    param=param,
                    payload=payload,
                    resp=resp,
                    match=f"Response size diff {diff} bytes",
                    confidence="tentative",
                    domain_id=domain_id,
                    method=method,
                    endpoint_id=endpoint_id,
                    form_id=form_id,
                )

        return None

    # ---------------------------------------------------------
    # BUILD FINDING
    # ---------------------------------------------------------

    def _build(self,
               *,
               url,
               page_url,
               param,
               payload,
               resp,
               match,
               confidence,
               domain_id,
               method="GET",
               endpoint_id=None,
               form_id=None):

        cvss = compute_cvss(vuln_type="ssrf")
        sev = SEVERITY_MAP["ssrf"]
        lh = LIKELIHOOD_MAP.get(confidence, 0.4)

        meta = _get_meta()["meta"]

        # JSONB payload
        payload_json = {
            "value": payload,
            "param": param,
            "type": "ssrf"
        }

        return {
            "vuln_type": "ssrf",
            "domain_id": domain_id,

            "page_url": page_url,
            "url": url,

            # PARAM IN TITLE
            "title": f"Server-Side Request Forgery (SSRF) - param: {param}",

            "category": self.category,
            "confidence": confidence,

            "parameter_name": param,

            # JSONB payload
            "payload": payload_json,

            "evidence": build_evidence(
                method,
                url,
                {param: payload},
                resp,
                match
            ),

            "raw_data": build_raw_data(payload, param, resp),

            "cwe": meta["cwe"],
            "wasc": meta["wasc"],
            "reference": meta["reference"],

            "endpoint_id": endpoint_id,
            "form_id": form_id,

            "severity": sev,
            "likelihood": lh,
            "impact": 9.0,

            "cvss_score": cvss,
            "exploit_available": True,
            "severity_level": severity_level(cvss),
        }