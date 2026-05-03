# (trimmed header omitted for brevity — keep yours)

from __future__ import annotations

import logging
import re
import urllib.parse
from urllib.parse import urlparse

from ..request_sender   import RequestSender, ScanResponse
from ..response_checker import build_evidence, build_raw_data
from ..utils.helpers    import (
    load_payloads, inject_param, get_query_params,
    SEVERITY_MAP, LIKELIHOOD_MAP, compute_cvss, severity_level,
)

logger = logging.getLogger("webxguard.active_scanner.ssti")

SAFE_VALUE = "plaintext_probe"

_META = None


def _get_meta():
    global _META
    if _META is None:
        _META = load_payloads("ssti")
    return _META


# -------------------------------
# helpers
# -------------------------------

def _expected_valid(expected: str):
    if not expected:
        return False

    if len(expected) == 0:
        return False

    return True


def _expected_matches(expected: str, body: str):

    if not expected:
        return False

    if len(expected) > 6:
        return expected in body

    pattern = r"(?<!\w)" + re.escape(expected) + r"(?!\w)"
    return bool(re.search(pattern, body))


def _is_reflected(payload: str, body: str):

    if payload in body:
        return True

    encoded = urllib.parse.quote(payload, safe="")
    if encoded in body:
        return True

    encoded_plus = encoded.replace("%20", "+")
    if encoded_plus in body:
        return True

    return False


def _url_key(url, param):
    p = urlparse(url)
    return (p.scheme, p.netloc, p.path or "/", param)


# -------------------------------
# SSTI MODULE
# -------------------------------

class SSTIModule:

    name = "ssti"
    category = "SSTI"

    def __init__(self, sender: RequestSender, oob_host: str = ""):
        self.sender = sender
        self.oob_host = oob_host
        self._seen = set()

    def _mark_seen(self, url, param):
        key = _url_key(url, param)
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    # ----------------------------------------------------

    async def scan_endpoint(self, endpoint, session_id, domain_id):

        url = endpoint["url"]
        params = get_query_params(url)

        findings = []

        for param in params:

            if self._mark_seen(url, param):
                continue

            findings += await self._probe_param(
                url,
                param,
                domain_id,
                endpoint.get("id")
            )

        return findings
    
    async def scan_page(self, page, session_id, domain_id):
        """Server Side Template Injection is endpoint-based only — no page scanning."""
        return []
    
    async def scan_form(self, form, inputs, session_id, domain_id):
        """Server Side Template Injection is endpoint-based only — no form scanning."""
        return []

    # ----------------------------------------------------

    async def _probe_param(self, url, param, domain_id, endpoint_id):

        meta = _get_meta()

        baseline = await self.sender.get(
            inject_param(url, param, SAFE_VALUE)
        )

        baseline_body = baseline.body if baseline else ""

        findings = []

        for p in meta["payloads"]:

            payload = p["value"]
            expected = p.get("expected")

            # skip bad payloads
            if not _expected_valid(expected):
                continue

            # baseline guard
            if _expected_matches(expected, baseline_body):
                continue

            test_url = inject_param(url, param, payload)

            resp = await self.sender.get(test_url)
            if not resp:
                continue

            # reflection guard
            if _is_reflected(payload, resp.body):
                continue

            if not _expected_matches(expected, resp.body):
                continue

            findings.append(
                self._build(
                    url=test_url,
                    page_url=url,
                    param=param,
                    payload_meta=p,
                    resp=resp,
                    domain_id=domain_id,
                    endpoint_id=endpoint_id
                )
            )

        return findings

    # ----------------------------------------------------

    def _build(self,
               *,
               url,
               page_url,
               param,
               payload_meta,
               resp,
               domain_id,
               endpoint_id=None,
               form_id=None,
               confidence="certain"):

        meta = _get_meta()["meta"]

        payload = payload_meta["value"]
        expected = payload_meta.get("expected")
        engine = payload_meta.get("engine", "generic")

        cvss = compute_cvss(vuln_type="ssti")
        sev = SEVERITY_MAP["ssti"]
        lh = LIKELIHOOD_MAP.get(confidence, 1.0)

        # JSONB payload
        payload_json = {
            "value": payload,
            "expected": expected,
            "engine": engine,
            "param": param
        }

        return {
            "vuln_type": "ssti",
            "domain_id": domain_id,

            "page_url": page_url,
            "url": url,

            # PARAM IN TITLE
            "title": f"Server-Side Template Injection (SSTI) - {param} - {engine}",

            "category": self.category,
            "confidence": confidence,

            "parameter_name": param,

            # JSONB payload
            "payload": payload_json,

            "evidence": build_evidence(
                "GET",
                url,
                {param: payload},
                resp,
                expected,
                extra={
                    "engine": engine,
                    "expected": expected
                }
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