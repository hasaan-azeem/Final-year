from __future__ import annotations

import html
import logging
import urllib.parse
from urllib.parse import urlparse

from ..request_sender   import RequestSender, ScanResponse
from ..response_checker import build_evidence, build_raw_data
from ..utils.helpers    import (
    load_payloads, inject_param, get_query_params,
    SEVERITY_MAP, LIKELIHOOD_MAP, compute_cvss, severity_level,
)

logger = logging.getLogger("webxguard.active_scanner.xss")

SAFE_VALUE = "wxg_xss_probe_1337"

_INJECTABLE_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "Accept-Language",
]

_META = None


def _get_meta():
    global _META
    if _META is None:
        _META = load_payloads("xss")
    return _META


def _url_path(url: str):
    return urlparse(url).path or "/"


# ------------------------------
# Reflection detection (robust)
# ------------------------------

def _raw_reflected(payload: str, body: str):
    if not body:
        return False
    return payload in body


def _encoded_reflected(payload: str, body: str):
    if not body:
        return False

    if payload in body:
        return False

    html_enc = html.escape(payload, quote=True)
    url_enc  = urllib.parse.quote(payload)

    return html_enc in body or url_enc in body


# ------------------------------
# Module
# ------------------------------

class XSSModule:
    name = "xss"
    category = "XSS"

    def __init__(self, sender: RequestSender, oob_host: str = ""):
        self.sender = sender
        self.oob_host = oob_host
        self._seen: set[tuple[str, str]] = set()

    # --------------------------------

    def _mark_seen(self, url, param):
        key = (_url_path(url), param)
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def _unmark(self, url, param):
        self._seen.discard((_url_path(url), param))

    # --------------------------------
    # Endpoint scan
    # --------------------------------

    async def scan_endpoint(self, endpoint, session_id, domain_id):
        url = endpoint["url"]

        findings = []

        # header XSS
        findings += await self.scan_headers(url, domain_id)

        params = get_query_params(url)

        for param in params:
            if self._mark_seen(url, param):
                continue

            res = await self._test_param(
                url,
                param,
                domain_id,
                endpoint.get("id"),
            )

            if res:
                findings.extend(res)
            else:
                self._unmark(url, param)

        return findings

    # --------------------------------
    # Form scan
    # --------------------------------

    async def scan_form(self, form, inputs, session_id, domain_id):

        url = form.get("action_url") or form.get("page_url")
        method = (form.get("method") or "GET").upper()

        findings = []

        for inp in inputs:
            param = inp.get("name")
            if not param:
                continue

            if self._mark_seen(url, param):
                continue

            res = await self._test_form_input(
                url,
                method,
                param,
                inputs,
                domain_id,
                form.get("id"),
                form.get("page_url", url),
            )

            if res:
                findings.extend(res)
            else:
                self._unmark(url, param)

        return findings

    # --------------------------------
    # Page scan
    # --------------------------------

    async def scan_page(self, page, session_id, domain_id):

        findings = []

        findings += await self.scan_endpoint(
            {"url": page["url"]},
            session_id,
            domain_id,
        )

        for entry in page.get("forms", []):
            findings += await self.scan_form(
                entry.get("form"),
                entry.get("inputs"),
                session_id,
                domain_id,
            )

        return findings

    # --------------------------------
    # Header XSS
    # --------------------------------

    async def scan_headers(self, url, domain_id):

        findings = []

        baseline = await self.sender.get(url)
        baseline_body = baseline.body if baseline else ""

        for header in _INJECTABLE_HEADERS:

            param = f"header:{header}"

            if self._mark_seen(url, param):
                continue

            for p in _get_meta()["payloads"]:

                payload = p["value"]

                if _raw_reflected(payload, baseline_body):
                    continue

                resp = await self.sender.get(
                    url,
                    extra_headers={header: payload},
                )

                if not resp:
                    continue

                if _raw_reflected(payload, resp.body):

                    findings.append(
                        self._build(
                            url=url,
                            page_url=url,
                            param=param,
                            payload=p,
                            resp=resp,
                            technique=f"Reflected Header ({header})",
                            confidence="certain",
                            domain_id=domain_id,
                        )
                    )

                elif _encoded_reflected(payload, resp.body):

                    findings.append(
                        self._build(
                            url=url,
                            page_url=url,
                            param=param,
                            payload=p,
                            resp=resp,
                            technique=f"Reflected Encoded Header ({header})",
                            confidence="firm",
                            domain_id=domain_id,
                        )
                    )

        return findings

    # --------------------------------
    # Param test
    # --------------------------------

    async def _test_param(self, url, param, domain_id, endpoint_id):

        findings = []

        baseline = await self.sender.get(
            inject_param(url, param, SAFE_VALUE)
        )

        baseline_body = baseline.body if baseline else ""

        for p in _get_meta()["payloads"]:

            payload = p["value"]

            if _raw_reflected(payload, baseline_body):
                continue

            test_url = inject_param(url, param, payload)

            resp = await self.sender.get(test_url)

            if not resp:
                continue

            if _raw_reflected(payload, resp.body):

                findings.append(
                    self._build(
                        url=test_url,
                        page_url=url,
                        param=param,
                        payload=p,
                        resp=resp,
                        technique="Reflected URL Parameter",
                        confidence="certain",
                        domain_id=domain_id,
                        endpoint_id=endpoint_id,
                    )
                )

            elif _encoded_reflected(payload, resp.body):

                findings.append(
                    self._build(
                        url=test_url,
                        page_url=url,
                        param=param,
                        payload=p,
                        resp=resp,
                        technique="Reflected Encoded URL Parameter",
                        confidence="firm",
                        domain_id=domain_id,
                        endpoint_id=endpoint_id,
                    )
                )

        return findings

    # --------------------------------
    # Form test
    # --------------------------------

    async def _test_form_input(
        self,
        url,
        method,
        param,
        inputs,
        domain_id,
        form_id,
        page_url,
    ):

        findings = []

        def build_data(val):
            return {
                i["name"]: (val if i["name"] == param else "test")
                for i in inputs
                if i.get("name")
            }

        async def send(val):
            data = build_data(val)
            if method == "POST":
                return await self.sender.post(url, data=data)
            return await self.sender.get(url, params=data)

        baseline = await send(SAFE_VALUE)
        baseline_body = baseline.body if baseline else ""

        for p in _get_meta()["payloads"]:

            payload = p["value"]

            if _raw_reflected(payload, baseline_body):
                continue

            resp = await send(payload)

            if not resp:
                continue

            if _raw_reflected(payload, resp.body):

                findings.append(
                    self._build(
                        url=url,
                        page_url=page_url,
                        param=param,
                        payload=p,
                        resp=resp,
                        technique="Reflected Form Input",
                        confidence="certain",
                        domain_id=domain_id,
                        form_id=form_id,
                        method=method,
                    )
                )

            elif _encoded_reflected(payload, resp.body):

                findings.append(
                    self._build(
                        url=url,
                        page_url=page_url,
                        param=param,
                        payload=p,
                        resp=resp,
                        technique="Reflected Encoded Form Input",
                        confidence="firm",
                        domain_id=domain_id,
                        form_id=form_id,
                        method=method,
                    )
                )

        return findings

    # --------------------------------
    # Finding builder
    # --------------------------------

    def _build(
        self,
        *,
        url,
        page_url,
        param,
        payload,
        resp,
        technique,
        confidence,
        domain_id,
        method="GET",
        endpoint_id=None,
        form_id=None,
    ):

        meta = _get_meta()["meta"]

        cvss = compute_cvss(vuln_type="xss")

        return {
            "vuln_type": "xss",
            "domain_id": domain_id,
            "page_url": page_url,
            "url": url,

            # title includes param (FIX)
            "title": f"Cross-Site Scripting ({param}) — {technique}",

            "category": self.category,
            "confidence": confidence,
            "parameter_name": param,

            # JSONB payload (FIX)
            "payload": payload,

            "evidence": build_evidence(
                method,
                url,
                {param: payload["value"]},
                resp,
                payload["value"],
            ),

            "raw_data": build_raw_data(
                payload["value"],
                param,
                resp,
            ),

            "cwe": meta["cwe"],
            "wasc": meta["wasc"],
            "reference": meta["reference"],

            "endpoint_id": endpoint_id,
            "form_id": form_id,

            "severity": SEVERITY_MAP["xss"],
            "likelihood": LIKELIHOOD_MAP.get(confidence, 0.4),
            "impact": 7.0,

            "cvss_score": cvss,
            "exploit_available": True,
            "severity_level": severity_level(cvss),
        }