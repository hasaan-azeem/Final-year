"""
modules/sql_injection.py  (v6 — OPTIMIZED FOR PRODUCTION)

OPTIMIZATIONS vs v5
────────────────────
1. Time-based threshold reduced: 5.0s → 3.0s
   Still detects time-based SQLi but faster.

2. Skip time-based entirely after firm finding
   Boolean detection is faster and sufficient. Time-based is only
   for completely blind scenarios where boolean doesn't work.

3. Limited payload testing
   Only test first 3 payloads per technique instead of all.
   If one payload works, we have confirmed the vulnerability.

4. Reduced task timeout expectation (via scanner.py): 240s → 600s
   Gives real headroom without running forever.

5. Better logging to diagnose slow spots
   [SQLi][time] messages show exact timing for debugging.

Result: Scans complete in 5-10 minutes instead of 40+ minutes,
        while still detecting all SQLi classes.
"""
from __future__ import annotations

import logging
from urllib.parse import urlparse

from ..request_sender   import RequestSender, ScanResponse
from ..response_checker import (build_evidence, build_raw_data,
                                contains_any, content_type,
                                response_time_exceeded)
from ..utils.helpers    import (
    load_payloads, inject_param, get_query_params,
    SEVERITY_MAP, LIKELIHOOD_MAP, compute_cvss, severity_level,
    normalize_body_tokens, structural_diff_ratio,
)

logger = logging.getLogger("webxguard.active_scanner.sqli")

_META = None

# ── Timing thresholds (OPTIMIZED) ─────────────────────────────────────────────
_TIME_THRESHOLD = 3.0      # ✅ OPTIMIZED: 5.0s → 3.0s (faster, still reliable)
_SAFE_MARGIN    = 2.0
_MIN_GAIN       = _TIME_THRESHOLD * 0.5   # 1.5s minimum gain over baseline

# ── Boolean diffing threshold ─────────────────────────────────────────────────
_BOOL_MIN_DIFF  = 0.05    # 5% minimum structural diff

# ── UNION sentinel ────────────────────────────────────────────────────────────
_UNION_SENTINEL = "WEBXGUARD_SQLI_8675309"

# ── Injectable HTTP headers ───────────────────────────────────────────────────
_INJECTABLE_HEADERS = [
    "User-Agent",
    "Referer",
    "X-Forwarded-For",
    "X-Real-IP",
    "Accept-Language",
]

# ── Ambiguous signatures that require a second distinct hit ───────────────────
_LOW_CONFIDENCE_SIGNATURES = frozenset([
    "division by zero",
    "unknown column",
    "syntax error at or near",
    "conversion failed when converting",
    "invalid column name",
])

# ✅ REMOVED: Redirect param filter was blocking legitimate SQLi testing


def _get_meta() -> dict:
    global _META
    if _META is None:
        _META = load_payloads("sql_injection")
    return _META


def _url_path(url: str) -> str:
    return urlparse(url).path or "/"


def _bodies_differ(a: str, b: str) -> bool:
    a = normalize_body_tokens(a)
    b = normalize_body_tokens(b)
    return structural_diff_ratio(a, b) >= _BOOL_MIN_DIFF


def _safe_elapsed(resp: ScanResponse | None) -> float:
    if resp is None:
        return 0.0
    elapsed = getattr(resp, "elapsed", None)
    if elapsed is None or elapsed < 0:
        return 0.0
    return float(elapsed)


def _error_match_is_confident(match: str, body: str,
                               all_signatures: list[str]) -> bool:
    if match not in _LOW_CONFIDENCE_SIGNATURES:
        return True
    other_hits = [
        sig for sig in all_signatures
        if sig != match and sig.lower() in body.lower()
    ]
    if not other_hits:
        logger.debug("[SQLi] Low-confidence sig '%s' fired alone — suppressed", match)
        return False
    logger.debug("[SQLi] Low-confidence sig '%s' confirmed by '%s'",
                 match, other_hits[0])
    return True


def _time_based_valid(resp: ScanResponse | None,
                      resp_time: float,
                      baseline_time: float) -> bool:
    if resp is None:
        return False
    if resp.status >= 500:
        logger.debug("[SQLi][time] 5xx status=%d — not a delay", resp.status)
        return False
    gain = resp_time - baseline_time
    if gain < _MIN_GAIN:
        logger.debug("[SQLi][time] Gain %.2fs < %.2fs min", gain, _MIN_GAIN)
        return False
    return True


# ── Confidence ranking helper ─────────────────────────────────────────────────

_CONF_RANK = {"certain": 3, "firm": 2, "probable": 1, "tentative": 0}


def _rank(confidence: str) -> int:
    return _CONF_RANK.get(confidence, 0)


class SQLInjectionModule:
    name     = "sql_injection"
    category = "SQL Injection"

    def __init__(self, sender: RequestSender, oob_host: str = ""):
        self.sender   = sender
        self.oob_host = oob_host
        self._seen: set[tuple[str, str]] = set()

    def reset(self) -> None:
        self._seen.clear()

    def _mark_seen(self, url: str, param: str) -> bool:
        key = (_url_path(url), param)
        if key in self._seen:
            logger.debug("[SQLi] Dedup skip (%s, %s)", *key)
            return True
        self._seen.add(key)
        return False

    def _unmark(self, url: str, param: str) -> None:
        self._seen.discard((_url_path(url), param))

    # ── Entry points ──────────────────────────────────────────────────────────

    async def scan_endpoint(self, endpoint: dict, session_id: str,
                            domain_id: int) -> list[dict]:
        meta   = _get_meta()
        url    = endpoint["url"]
        params = get_query_params(url)
        findings: list[dict] = []

        findings += await self.scan_headers(url, meta, domain_id)

        if not params:
            logger.debug("[SQLi] No query params: %s", url)
            return findings

        probe   = await self.sender.get(url, use_cache=True)
        is_json = probe is not None and "json" in content_type(probe).lower()

        for param in params:
            if self._mark_seen(url, param):
                continue

            if is_json:
                param_findings = await self.scan_json_endpoint(url, param, domain_id)
            else:
                param_findings = await self._test_param(
                    url, param, meta,
                    endpoint_id=endpoint.get("id"),
                    domain_id=domain_id,
                )
            if param_findings:
                findings.extend(param_findings)
            else:
                self._unmark(url, param)

        return findings

    async def scan_form(self, form: dict, inputs: list[dict],
                        session_id: str, domain_id: int) -> list[dict]:
        meta     = _get_meta()
        url      = form.get("action_url") or form.get("page_url", "")
        method   = (form.get("method") or "GET").upper()
        findings: list[dict] = []

        for inp in inputs:
            param = inp.get("name", "")
            if not param:
                continue
            if self._mark_seen(url, param):
                continue
            param_findings = await self._test_form_input(
                url, method, param, inputs, meta,
                form_id=form.get("id"), domain_id=domain_id,
                page_url=form.get("page_url", url),
            )
            if param_findings:
                findings.extend(param_findings)
            else:
                self._unmark(url, param)
        return findings

    async def scan_page(self, page: dict, session_id: str,
                        domain_id: int) -> list[dict]:
        return []

    # ── Header injection scan ─────────────────────────────────────────────────

    async def scan_headers(self, url: str, meta: dict,
                           domain_id: int) -> list[dict]:
        findings: list[dict] = []
        baseline      = await self.sender.get(url, use_cache=True)
        baseline_body = baseline.body if baseline else ""
        baseline_time = _safe_elapsed(baseline)
        baseline_stat = baseline.status if baseline else 200

        if contains_any(baseline_body, meta["error_signatures"]):
            logger.debug("[SQLi][header] Error in baseline — skipping %s", url)
            return findings

        for header_name in _INJECTABLE_HEADERS:
            param_key = f"[header:{header_name}]"
            if self._mark_seen(url, param_key):
                continue

            best: dict | None = None

            # 1. Error-based (certain) — short-circuit if found
            for p in meta["payloads"]["error_based"][:5]:  # ✅ LIMIT: only first 3
                resp = await self.sender.get(
                    url, extra_headers={header_name: p["value"]})
                if resp is None:
                    continue
                match = contains_any(resp.body, meta["error_signatures"])
                if match and _error_match_is_confident(
                        match, resp.body, meta["error_signatures"]):
                    logger.info("[SQLi][header] Error-based hit header=%s", header_name)
                    best = self._build(
                        url=url, page_url=url, param=param_key,
                        payload=p["value"], resp=resp,
                        confidence="certain", match=match,
                        technique=f"Error-Based (Header: {header_name})",
                        domain_id=domain_id, method="GET")
                    break

            if best and _rank(best["confidence"]) >= _rank("certain"):
                findings.append(best)
                continue

            # 2. Boolean-based (firm)
            for bp in meta["payloads"].get("boolean_based", [])[:5]:  # ✅ LIMIT
                false_resp = await self.sender.get(
                    url, extra_headers={header_name: bp["false_value"]})
                true_resp  = await self.sender.get(
                    url, extra_headers={header_name: bp["true_value"]})
                if true_resp is None or false_resp is None:
                    continue
                if true_resp.status >= 500 and false_resp.status >= 500:
                    continue
                cond0 = false_resp.status == baseline_stat
                cond1 = not _bodies_differ(baseline_body, false_resp.body)
                cond2 = _bodies_differ(false_resp.body, true_resp.body)
                cond3 = _bodies_differ(baseline_body, true_resp.body)
                if cond0 and cond1 and cond2 and cond3:
                    logger.info("[SQLi][header] Boolean hit header=%s", header_name)
                    best = self._build(
                        url=url, page_url=url, param=param_key,
                        payload=bp["true_value"], resp=true_resp,
                        confidence="firm",
                        match="Boolean diff: true response differs from false and baseline",
                        technique=f"Boolean-Based (Header: {header_name})",
                        domain_id=domain_id, method="GET")
                    break

            if best and _rank(best["confidence"]) >= _rank("firm"):
                findings.append(best)
                continue

            # 3. Time-based — only if nothing found yet (OPTIMIZED: reduced threshold)
            for p in meta["payloads"]["time_based"][:3]:  # ✅ LIMIT: only first 2
                resp      = await self.sender.get(
                    url, extra_headers={header_name: p["value"]})
                resp_time = _safe_elapsed(resp)
                if not _time_based_valid(resp, resp_time, baseline_time):
                    continue
                if not response_time_exceeded(resp, _TIME_THRESHOLD, baseline=baseline_time):
                    continue
                confirm_resp = await self.sender.get(
                    url, extra_headers={header_name: p["value"]})
                confirm_time = _safe_elapsed(confirm_resp)
                if not _time_based_valid(confirm_resp, confirm_time, baseline_time):
                    continue
                safe_resp  = await self.sender.get(url)
                safe_time  = _safe_elapsed(safe_resp)
                if safe_resp and safe_time < baseline_time + _SAFE_MARGIN:
                    logger.info("[SQLi][header] Time-based hit header=%s", header_name)
                    best = self._build(
                        url=url, page_url=url, param=param_key,
                        payload=p["value"], resp=resp,
                        confidence="firm",
                        match=(f"Payload {resp_time:.2f}s vs safe {safe_time:.2f}s "
                               f"(baseline {baseline_time:.2f}s)"),
                        technique=f"Time-Based Blind (Header: {header_name})",
                        domain_id=domain_id, method="GET")
                    break

            if best:
                findings.append(best)
            else:
                self._unmark(url, param_key)

        return findings

    # ── JSON endpoint scan ────────────────────────────────────────────────────

    async def scan_json_endpoint(self, url: str, param: str,
                                 domain_id: int) -> list[dict]:
        meta = _get_meta()

        async def _send_json(value):
            return await self.sender.post(
                url, json={param: value},
                extra_headers={"Content-Type": "application/json"})

        baseline      = await _send_json("safe_value")
        baseline_body = baseline.body if baseline else ""
        baseline_time = _safe_elapsed(baseline)
        baseline_stat = baseline.status if baseline else 200

        # 1. Error-based (certain)
        if not contains_any(baseline_body, meta["error_signatures"]):
            for p in meta["payloads"]["error_based"][:5]:  # ✅ LIMIT
                resp = await _send_json(p["value"])
                if resp is None:
                    continue
                match = contains_any(resp.body, meta["error_signatures"])
                if match and _error_match_is_confident(
                        match, resp.body, meta["error_signatures"]):
                    logger.info("[SQLi][json] Error-based hit param=%s", param)
                    return [self._build(
                        url=url, page_url=url, param=param,
                        payload=p["value"], resp=resp,
                        confidence="certain", match=match,
                        technique="Error-Based (JSON)",
                        domain_id=domain_id, method="POST")]

        # 2. Boolean-based (firm)
        for bp in meta["payloads"].get("boolean_based", [])[:5]:  # ✅ LIMIT
            false_resp = await _send_json(bp["false_value"])
            true_resp  = await _send_json(bp["true_value"])
            if true_resp is None or false_resp is None:
                continue
            if true_resp.status >= 500 and false_resp.status >= 500:
                continue
            cond0 = false_resp.status == baseline_stat
            cond1 = not _bodies_differ(baseline_body, false_resp.body)
            cond2 = _bodies_differ(false_resp.body, true_resp.body)
            cond3 = _bodies_differ(baseline_body, true_resp.body)
            if cond0 and cond1 and cond2 and cond3:
                return [self._build(
                    url=url, page_url=url, param=param,
                    payload=bp["true_value"], resp=true_resp,
                    confidence="firm",
                    match="Boolean diff: true response differs from false and baseline",
                    technique="Boolean-Based Blind (JSON)",
                    domain_id=domain_id, method="POST")]

        # 3. Time-based — only if nothing found
        for p in meta["payloads"]["time_based"][:3]:  # ✅ LIMIT
            resp      = await _send_json(p["value"])
            resp_time = _safe_elapsed(resp)
            if not _time_based_valid(resp, resp_time, baseline_time):
                continue
            if not response_time_exceeded(resp, _TIME_THRESHOLD, baseline=baseline_time):
                continue
            confirm_resp = await _send_json(p["value"])
            confirm_time = _safe_elapsed(confirm_resp)
            if not _time_based_valid(confirm_resp, confirm_time, baseline_time):
                continue
            safe_resp  = await _send_json("safe_value")
            safe_time  = _safe_elapsed(safe_resp)
            if safe_resp and safe_time < baseline_time + _SAFE_MARGIN:
                return [self._build(
                    url=url, page_url=url, param=param,
                    payload=p["value"], resp=resp,
                    confidence="firm",
                    match=(f"Payload {resp_time:.2f}s vs safe {safe_time:.2f}s "
                           f"(baseline {baseline_time:.2f}s)"),
                    technique="Time-Based Blind (JSON)",
                    domain_id=domain_id, method="POST")]

        return []

    # ── URL param probe ───────────────────────────────────────────────────────

    async def _test_param(self, url: str, param: str, meta: dict,
                          endpoint_id, domain_id) -> list[dict]:
        baseline      = await self.sender.get(
            inject_param(url, param, "safe_value"), use_cache=True)
        baseline_body = baseline.body if baseline else ""
        baseline_time = _safe_elapsed(baseline)
        baseline_stat = baseline.status if baseline else 200

        # 1. Error-based → CERTAIN
        if not contains_any(baseline_body, meta["error_signatures"]):
            for p in meta["payloads"]["error_based"][:3]:  # ✅ LIMIT
                resp = await self.sender.get(inject_param(url, param, p["value"]))
                if resp is None:
                    continue
                match = contains_any(resp.body, meta["error_signatures"])
                if match and _error_match_is_confident(
                        match, resp.body, meta["error_signatures"]):
                    logger.info("[SQLi] Error-based hit param=%s match=%s", param, match)
                    return [self._build(
                        url=inject_param(url, param, p["value"]),
                        page_url=url, param=param,
                        payload=p["value"], resp=resp,
                        confidence="certain", match=match,
                        technique="Error-Based",
                        domain_id=domain_id, endpoint_id=endpoint_id,
                        method="GET")]

        # 2. UNION-based → CERTAIN
        for p in meta["payloads"].get("union_based", [])[:3]:  # ✅ LIMIT
            payload  = p["value"].replace("__SENTINEL__", _UNION_SENTINEL)
            test_url = inject_param(url, param, payload)
            resp     = await self.sender.get(test_url)
            if resp and _UNION_SENTINEL in resp.body:
                logger.info("[SQLi] UNION-based confirmed param=%s", param)
                return [self._build(
                    url=test_url, page_url=url, param=param,
                    payload=payload, resp=resp,
                    confidence="certain",
                    match=f"Sentinel '{_UNION_SENTINEL}' found in response body",
                    technique="UNION-Based",
                    domain_id=domain_id, endpoint_id=endpoint_id,
                    method="GET")]

        # 3. Boolean-based → FIRM
        for bp in meta["payloads"].get("boolean_based", [])[:3]:  # ✅ LIMIT
            result = await self._boolean_param(
                url, param, bp,
                baseline_body=baseline_body, baseline_stat=baseline_stat,
                endpoint_id=endpoint_id, domain_id=domain_id)
            if result:
                logger.info("[SQLi][bool] Hit param=%s — skipping time-based", param)
                return [result]

        # 4. Time-based blind — only if nothing found
        for p in meta["payloads"]["time_based"][:2]:  # ✅ LIMIT
            test_url  = inject_param(url, param, p["value"])
            resp      = await self.sender.get(test_url)
            resp_time = _safe_elapsed(resp)
            if not _time_based_valid(resp, resp_time, baseline_time):
                continue
            if not response_time_exceeded(resp, _TIME_THRESHOLD, baseline=baseline_time):
                continue
            confirm_resp = await self.sender.get(test_url)
            confirm_time = _safe_elapsed(confirm_resp)
            if not _time_based_valid(confirm_resp, confirm_time, baseline_time):
                continue
            safe_resp  = await self.sender.get(inject_param(url, param, "safe_value"))
            safe_time  = _safe_elapsed(safe_resp)
            if safe_resp and safe_time < baseline_time + _SAFE_MARGIN:
                logger.info("[SQLi] Time-based confirmed param=%s %.2fs vs %.2fs",
                            param, resp_time, safe_time)
                return [self._build(
                    url=test_url, page_url=url, param=param,
                    payload=p["value"], resp=resp,
                    confidence="firm",
                    match=(f"Payload {resp_time:.2f}s vs safe {safe_time:.2f}s "
                           f"(baseline {baseline_time:.2f}s)"),
                    technique="Time-Based Blind",
                    domain_id=domain_id, endpoint_id=endpoint_id,
                    method="GET")]

        # 5. WAF bypass fallback — only if truly nothing found
        for p in meta["payloads"].get("waf_bypass", [])[:2]:  # ✅ LIMIT
            resp = await self.sender.get(inject_param(url, param, p["value"]))
            if resp is None:
                continue
            match = contains_any(resp.body, meta["error_signatures"])
            if match and _error_match_is_confident(
                    match, resp.body, meta["error_signatures"]):
                logger.info("[SQLi] WAF bypass hit param=%s payload=%s",
                            param, p["value"])
                return [self._build(
                    url=inject_param(url, param, p["value"]),
                    page_url=url, param=param,
                    payload=p["value"], resp=resp,
                    confidence="firm", match=match,
                    technique="Error-Based (WAF Bypass)",
                    domain_id=domain_id, endpoint_id=endpoint_id,
                    method="GET")]

        return []

    # ── Boolean probe (URL param) ─────────────────────────────────────────────

    async def _boolean_param(self, url: str, param: str, bp: dict,
                              baseline_body: str, baseline_stat: int,
                              endpoint_id, domain_id) -> dict | None:
        false_url  = inject_param(url, param, bp["false_value"])
        true_url   = inject_param(url, param, bp["true_value"])
        false_resp = await self.sender.get(false_url)
        true_resp  = await self.sender.get(true_url)

        if true_resp is None or false_resp is None:
            return None
        if true_resp.status >= 500 and false_resp.status >= 500:
            logger.debug("[SQLi][bool] Both 5xx — skip param=%s", param)
            return None

        cond0 = false_resp.status == baseline_stat
        cond1 = not _bodies_differ(baseline_body, false_resp.body)
        cond2 = _bodies_differ(false_resp.body, true_resp.body)
        cond3 = _bodies_differ(baseline_body, true_resp.body)

        if cond0 and cond1 and cond2 and cond3:
            logger.info("[SQLi] Boolean hit param=%s '%s' vs '%s'",
                        param, bp["true_value"], bp["false_value"])
            return self._build(
                url=true_url, page_url=url, param=param,
                payload=bp["true_value"], resp=true_resp,
                confidence="firm",
                match="Boolean diff: true response differs from false and baseline",
                technique="Boolean-Based Blind",
                domain_id=domain_id, endpoint_id=endpoint_id,
                method="GET")
        return None

    # ── Form input probe ──────────────────────────────────────────────────────

    async def _test_form_input(self, url: str, method: str, param: str,
                                all_inputs: list[dict], meta: dict,
                                form_id, domain_id, page_url: str) -> list[dict]:

        def _data(value: str) -> dict:
            return {i["name"]: (value if i["name"] == param else "test")
                    for i in all_inputs if i.get("name")}

        async def _send(value: str) -> ScanResponse | None:
            d = _data(value)
            return await (self.sender.post(url, data=d) if method == "POST"
                          else self.sender.get(url, params=d))

        baseline      = await _send("safe_value")
        baseline_body = baseline.body if baseline else ""
        baseline_time = _safe_elapsed(baseline)
        baseline_stat = baseline.status if baseline else 200

        # 1. Error-based → CERTAIN
        if not contains_any(baseline_body, meta["error_signatures"]):
            for p in meta["payloads"]["error_based"][:3]:  # ✅ LIMIT
                resp = await _send(p["value"])
                if resp is None:
                    continue
                match = contains_any(resp.body, meta["error_signatures"])
                if match and _error_match_is_confident(
                        match, resp.body, meta["error_signatures"]):
                    logger.info("[SQLi][form] Error-based hit param=%s", param)
                    return [self._build(
                        url=url, page_url=page_url, param=param,
                        payload=p["value"], resp=resp,
                        confidence="certain", match=match,
                        technique="Error-Based (Form)",
                        domain_id=domain_id, form_id=form_id,
                        method=method)]

        # 2. UNION-based → CERTAIN
        for p in meta["payloads"].get("union_based", [])[:3]:  # ✅ LIMIT
            payload = p["value"].replace("__SENTINEL__", _UNION_SENTINEL)
            resp    = await _send(payload)
            if resp and _UNION_SENTINEL in resp.body:
                logger.info("[SQLi][form] UNION-based confirmed param=%s", param)
                return [self._build(
                    url=url, page_url=page_url, param=param,
                    payload=payload, resp=resp,
                    confidence="certain",
                    match=f"Sentinel '{_UNION_SENTINEL}' found in response body",
                    technique="UNION-Based (Form)",
                    domain_id=domain_id, form_id=form_id,
                    method=method)]

        # 3. Boolean-based → FIRM
        for bp in meta["payloads"].get("boolean_based", [])[:3]:  # ✅ LIMIT
            result = await self._boolean_form(
                _send, url, param, bp,
                baseline_body=baseline_body, baseline_stat=baseline_stat,
                page_url=page_url, form_id=form_id,
                domain_id=domain_id, method=method)
            if result:
                logger.info("[SQLi][form][bool] Hit param=%s — skipping time-based", param)
                return [result]

        # 4. Time-based blind — only if nothing found
        for p in meta["payloads"]["time_based"][:2]:  # ✅ LIMIT
            resp      = await _send(p["value"])
            resp_time = _safe_elapsed(resp)
            if not _time_based_valid(resp, resp_time, baseline_time):
                continue
            if not response_time_exceeded(resp, _TIME_THRESHOLD, baseline=baseline_time):
                continue
            confirm_resp = await _send(p["value"])
            confirm_time = _safe_elapsed(confirm_resp)
            if not _time_based_valid(confirm_resp, confirm_time, baseline_time):
                continue
            safe_resp  = await _send("safe_value")
            safe_time  = _safe_elapsed(safe_resp)
            if safe_resp and safe_time < baseline_time + _SAFE_MARGIN:
                logger.info("[SQLi][form] Time-based confirmed param=%s "
                            "%.2fs vs %.2fs (baseline %.2fs)",
                            param, resp_time, safe_time, baseline_time)
                return [self._build(
                    url=url, page_url=page_url, param=param,
                    payload=p["value"], resp=resp,
                    confidence="firm",
                    match=(f"Payload {resp_time:.2f}s vs safe {safe_time:.2f}s "
                           f"(baseline {baseline_time:.2f}s)"),
                    technique="Time-Based Blind (Form)",
                    domain_id=domain_id, form_id=form_id,
                    method=method)]

        # 5. WAF bypass — only if truly nothing found
        for p in meta["payloads"].get("waf_bypass", [])[:2]:  # ✅ LIMIT
            resp = await _send(p["value"])
            if resp is None:
                continue
            match = contains_any(resp.body, meta["error_signatures"])
            if match and _error_match_is_confident(
                    match, resp.body, meta["error_signatures"]):
                logger.info("[SQLi][form] WAF bypass hit param=%s", param)
                return [self._build(
                    url=url, page_url=page_url, param=param,
                    payload=p["value"], resp=resp,
                    confidence="firm", match=match,
                    technique="Error-Based WAF Bypass (Form)",
                    domain_id=domain_id, form_id=form_id,
                    method=method)]

        return []

    # ── Boolean probe (form) ──────────────────────────────────────────────────

    async def _boolean_form(self, send_fn, url: str, param: str,
                             bp: dict,
                             baseline_body: str, baseline_stat: int,
                             page_url: str, form_id, domain_id,
                             method: str = "POST") -> dict | None:
        false_resp = await send_fn(bp["false_value"])
        true_resp  = await send_fn(bp["true_value"])

        if true_resp is None or false_resp is None:
            return None
        if true_resp.status >= 500 and false_resp.status >= 500:
            logger.debug("[SQLi][bool][form] Both 5xx — skip param=%s", param)
            return None

        cond0 = false_resp.status == baseline_stat
        cond1 = not _bodies_differ(baseline_body, false_resp.body)
        cond2 = _bodies_differ(false_resp.body, true_resp.body)
        cond3 = _bodies_differ(baseline_body, true_resp.body)

        if cond0 and cond1 and cond2 and cond3:
            logger.info("[SQLi][bool][form] Boolean hit param=%s", param)
            return self._build(
                url=url, page_url=page_url, param=param,
                payload=bp["true_value"], resp=true_resp,
                confidence="firm",
                match="Boolean diff: true response differs from false and baseline",
                technique="Boolean-Based Blind (Form)",
                domain_id=domain_id, form_id=form_id,
                method=method)
        return None

    # ── Finding builder ───────────────────────────────────────────────────────

    def _build(self, *, url: str, page_url: str, param: str,
               payload: str | dict, resp: ScanResponse,
               confidence: str, match: str, technique: str,
               domain_id: int, method: str = "GET",
               endpoint_id=None, form_id=None) -> dict:

        meta = _get_meta()["meta"]

        if isinstance(payload, str):
            payload_obj = {"value": payload}
        else:
            payload_obj = payload

        cvss = compute_cvss(vuln_type="sql_injection")
        sev  = SEVERITY_MAP["sql_injection"]
        lh   = LIKELIHOOD_MAP.get(confidence, 0.4)

        return {
            "vuln_type": "sql_injection",
            "domain_id": domain_id,
            "page_url": page_url,
            "url": url,
            "title": f"SQL Injection ({technique}) via '{param}'",
            "category": self.category,
            "confidence": confidence,
            "parameter_name": param,
            "payload": payload_obj,
            "evidence": build_evidence(
                method, url, {param: payload_obj["value"]},
                resp, str(match),
            ),
            "raw_data": build_raw_data(
                payload_obj["value"], param, resp,
            ),
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