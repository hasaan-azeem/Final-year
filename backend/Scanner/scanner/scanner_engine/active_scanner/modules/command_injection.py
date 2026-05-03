from __future__ import annotations

import asyncio
import logging

from ..request_sender import RequestSender
from ..response_checker import (
    build_evidence,
    build_raw_data,
    contains_any,
    response_time_exceeded,
)
from ..utils.helpers import (
    load_payloads,
    inject_param,
    get_query_params,
    url_key,
    SEVERITY_MAP,
    LIKELIHOOD_MAP,
    compute_cvss,
    severity_level,
)

logger = logging.getLogger("webxguard.active_scanner.cmdi")

# ─────────────────────────────────────────────────────────────
# CONFIG (Enterprise tuned)
# ─────────────────────────────────────────────────────────────

_TIME_THRESHOLD = 5.0
_MIN_GAIN       = 2.5

MAX_CONCURRENT_REQUESTS = 10
REQUEST_TIMEOUT         = 10
HEADER_PAYLOAD_LIMIT    = 5
SEEN_LIMIT              = 10000

_INJECTABLE_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
]

# ─────────────────────────────────────────────────────────────
# caches
# ─────────────────────────────────────────────────────────────

_META            = None
_MODULE_META     = None
_OUTPUT_PAYLOADS = None
_TIME_PAYLOADS   = None


def _get_meta():
    global _META
    if _META is None:
        _META = load_payloads("command_injection")
    return _META


def _get_module_meta():
    global _MODULE_META
    if _MODULE_META is None:
        _MODULE_META = _get_meta()["meta"]
    return _MODULE_META


def _payloads():
    global _OUTPUT_PAYLOADS, _TIME_PAYLOADS
    if _OUTPUT_PAYLOADS is None:
        all_p = _get_meta()["payloads"]
        _OUTPUT_PAYLOADS = [p for p in all_p if p.get("type") != "time"]
        _TIME_PAYLOADS   = [p for p in all_p if p.get("type") == "time"]
    return _OUTPUT_PAYLOADS, _TIME_PAYLOADS


# ─────────────────────────────────────────────────────────────
# MODULE
# ─────────────────────────────────────────────────────────────

class CommandInjectionModule:

    name     = "command_injection"
    category = "Command Injection"

    def __init__(self, sender: RequestSender):
        self.sender = sender
        self._seen  = set()
        self._sem   = asyncio.Semaphore(MAX_CONCURRENT_REQUESTS)

    # ─────────────────────────────────────────────────────────

    async def scan_endpoint(self, endpoint, session_id, domain_id) -> list:
        url    = endpoint["url"]
        params = get_query_params(url)

        self._seen.clear()  # ✅ memory safe per endpoint

        findings  = []
        findings += await self._scan_headers(url, session_id, domain_id)

        tasks = []

        for param in params:
            key = (url_key(url), param)

            if key in self._seen:
                continue

            self._seen.add(key)

            tasks.append(self._probe_param(
                url, param, session_id, domain_id, endpoint.get("id")
            ))

        results = await asyncio.gather(*tasks)
        for r in results:
            findings.extend(r)

        return findings

    # ─────────────────────────────────────────────────────────

    async def _safe_get(self, url, **kwargs):
        async with self._sem:
            try:
                return await self.sender.get(url, timeout=REQUEST_TIMEOUT, **kwargs)
            except Exception as e:
                logger.debug("Request failed: %s (%s)", url, e)
                return None

    # ─────────────────────────────────────────────────────────

    async def _scan_headers(self, url, session_id, domain_id):
        findings = []
        indicators = _get_meta()["indicators"]
        output_payloads, _ = _payloads()

        baseline = await self._safe_get(url, use_cache=True)
        baseline_body = baseline.body if baseline else ""

        for header in _INJECTABLE_HEADERS:
            for p in output_payloads[:HEADER_PAYLOAD_LIMIT]:

                resp = await self._safe_get(
                    url, extra_headers={header: p["value"]}
                )

                if not resp:
                    continue

                match = contains_any(resp.body, indicators)
                baseline_match = contains_any(baseline_body, indicators)

                if not match or baseline_match:
                    continue

                findings.append(self._build(
                    session_id=session_id,
                    technique=f"Header {header}",
                    confidence="certain",
                    url=url,
                    page_url=url,
                    param=f"[header:{header}]",
                    payload=p,
                    resp=resp,
                    match=match,
                    domain_id=domain_id,
                ))

        return findings

    # ─────────────────────────────────────────────────────────

    async def _probe_param(self, url, param, session_id, domain_id, endpoint_id):
        findings = []
        indicators = _get_meta()["indicators"]
        output_payloads, time_payloads = _payloads()

        baseline = await self._safe_get(
            inject_param(url, param, "safe_test"), use_cache=True
        )

        baseline_body = baseline.body if baseline else ""
        baseline_time = baseline.elapsed if baseline else 0.0

        # ── OUTPUT BASED ─────────────────────────────────────

        if not contains_any(baseline_body, indicators):

            for p in output_payloads:
                test_url = inject_param(url, param, p["value"])
                resp = await self._safe_get(test_url)

                if not resp:
                    continue

                match = contains_any(resp.body, indicators)
                if not match:
                    continue

                findings.append(self._build(
                    session_id=session_id,
                    technique="Output-Based",
                    confidence="certain",
                    url=test_url,
                    page_url=url,
                    param=param,
                    payload=p,
                    resp=resp,
                    match=match,
                    domain_id=domain_id,
                    endpoint_id=endpoint_id,
                ))

        # ── TIME BASED (Improved Statistical) ─────────────────

        for p in time_payloads:
            test_url = inject_param(url, param, p["value"])

            times = []

            for _ in range(3):
                r = await self._safe_get(test_url)
                if r:
                    times.append(r.elapsed)

            if len(times) < 2:
                continue

            avg_delay = sum(times) / len(times)

            if avg_delay - baseline_time < _MIN_GAIN:
                continue

            findings.append(self._build(
                session_id=session_id,
                technique="Time-Based Blind",
                confidence="probable",
                url=test_url,
                page_url=url,
                param=param,
                payload=p,
                resp=r,
                match=f"avg delay {avg_delay:.2f}s",
                domain_id=domain_id,
                endpoint_id=endpoint_id,
            ))
            break

        return findings

    # ─────────────────────────────────────────────────────────

    def _build(self, *, session_id, technique, confidence,
               url, page_url, param, payload, resp, match,
               domain_id, endpoint_id=None, form_id=None):

        meta = _get_module_meta()
        cvss = compute_cvss(vuln_type="command_injection")

        return {
            "session_id": session_id,
            "domain_id": domain_id,
            "page_url": page_url,
            "url": url,

            "title": f"OS Command Injection ({technique}) [{param}]",
            "category": self.category,
            "confidence": confidence,

            "parameter_name": param,
            "payload": {
                "value": payload["value"],
                "param": param,
                "technique": technique,
                "module": "command_injection",
            },

            "evidence": build_evidence(
                "GET", url, {param: payload["value"]}, resp, str(match)
            ),
            "raw_data": build_raw_data(payload["value"], param, resp),

            "cwe": meta["cwe"],
            "wasc": meta["wasc"],
            "reference": meta["reference"],

            "endpoint_id": endpoint_id,
            "form_id": form_id,

            "severity": SEVERITY_MAP["command_injection"],
            "likelihood": LIKELIHOOD_MAP.get(confidence, 0.6),
            "impact": 10.0,
            "cvss_score": cvss,
            "exploit_available": True,
            "severity_level": severity_level(cvss),
        }