# modules/open_redirect.py
from __future__ import annotations

import logging
from urllib.parse import urlparse, unquote

from ..request_sender import RequestSender, ScanResponse
from ..response_checker import (
    build_evidence,
    build_raw_data,
    is_redirect,
    redirect_location,
)
from ..utils.helpers import (
    load_payloads,
    inject_param,
    get_query_params,
    SEVERITY_MAP,
    LIKELIHOOD_MAP,
    compute_cvss,
    severity_level,
)

logger = logging.getLogger("webxguard.active_scanner.open_redirect")

SAFE_VALUE = "https://example.com"

_META:        dict | None = None
_MODULE_META: dict | None = None


def _get_meta() -> dict:
    global _META
    if _META is None:
        _META = load_payloads("open_redirect")
    return _META


def _get_module_meta() -> dict:
    global _MODULE_META
    if _MODULE_META is None:
        _MODULE_META = _get_meta()["meta"]
    return _MODULE_META


def _url_path(url: str) -> str:
    return urlparse(url).path or "/"


# ── Attacker domain extraction ────────────────────────────────────────────────

def _extract_domain(payload: str) -> str:
    try:
        payload = unquote(payload.strip())
    except Exception:
        pass

    payload = payload.replace("\\", "/")

    if payload.startswith("//"):
        payload = "https:" + payload
    if payload.startswith("/"):
        payload = "https://" + payload.lstrip("/")

    parsed = urlparse(payload)
    host   = parsed.netloc.lower()

    if "@" in host:
        host = host.split("@")[-1]

    return host if "." in host else ""


# ── Redirect detection ────────────────────────────────────────────────────────

def _has_external_redirect(resp: ScanResponse, target: str) -> bool:
    if not is_redirect(resp):
        return False
    loc = redirect_location(resp)   # already uses resp.headers_lower
    if not loc:
        return False
    parsed = urlparse(loc)
    if not parsed.netloc:
        return False
    host = parsed.netloc.lower()
    return host == target or host.endswith("." + target)


def _has_body_injection(resp: ScanResponse, target: str) -> bool:
    # ✅ FIX: use pre-computed body_lower slot — no repeated .lower() allocation
    body = resp.body_lower
    return (
        f"http://{target}"  in body
        or f"https://{target}" in body
        or f"//{target}"       in body
        or f"url={target}"     in body
    )


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  MODULE
# ╚══════════════════════════════════════════════════════════════════════════════

class OpenRedirectModule:
    name     = "open_redirect"
    category = "Open Redirect"

    def __init__(self, sender: RequestSender, oob_host: str = ""):
        self.sender   = sender
        self.oob_host = oob_host
        self._seen: set[tuple[str, str]] = set()

    def _mark_seen(self, url: str, param: str) -> bool:
        key = (_url_path(url), param)
        if key in self._seen:
            return True
        self._seen.add(key)
        return False

    def _unmark(self, url: str, param: str) -> None:
        self._seen.discard((_url_path(url), param))

    # ── Entry points ──────────────────────────────────────────────────────────

    async def scan_page(self, page: dict, session_id: str, domain_id: int) -> list:
        return []

    async def scan_form(self, form: dict, inputs: list, session_id: str,
                        domain_id: int) -> list:
        return []

    async def scan_endpoint(self, endpoint: dict, session_id: str,
                            domain_id: int) -> list[dict]:
        meta   = _get_meta()
        url    = endpoint["url"]
        params = get_query_params(url)

        if not params:
            return []

        redirect_params = set(meta.get("redirect_params", []))
        priority  = [p for p in params if p.lower()     in redirect_params]
        remaining = [p for p in params if p.lower() not in redirect_params]

        findings: list[dict] = []

        for param in priority + remaining:
            if self._mark_seen(url, param):
                continue

            results = await self._probe_param(
                url, param, meta, domain_id, endpoint.get("id"),
            )

            if results:
                findings.extend(results)
            else:
                self._unmark(url, param)

        return findings

    # ── Param probe ───────────────────────────────────────────────────────────

    async def _probe_param(self, url: str, param: str, meta: dict,
                           domain_id: int, endpoint_id) -> list[dict]:
        findings: list[dict] = []

        # ✅ use_cache=True — same safe-value baseline reused across modules
        baseline = await self.sender.get(
            inject_param(url, param, SAFE_VALUE),
            follow_redirects=False,
            use_cache=True,
        )

        for p in meta["payloads"]:
            payload  = p["value"]
            test_url = inject_param(url, param, payload)

            resp = await self.sender.get(test_url, follow_redirects=False)
            if not resp:
                continue

            finding = self._check_response(
                resp, baseline, test_url, url,
                param, payload, p, domain_id, endpoint_id,
            )
            if finding:
                findings.append(finding)

        return findings

    # ── Response checker ──────────────────────────────────────────────────────

    def _check_response(
        self,
        resp:        ScanResponse,
        baseline:    ScanResponse | None,
        test_url:    str,
        page_url:    str,
        param:       str,
        payload:     str,
        payload_obj: dict,
        domain_id:   int,
        endpoint_id,
    ) -> dict | None:
        target = _extract_domain(payload)
        if not target:
            return None

        page_host = urlparse(page_url).netloc.lower()
        if target in page_host:
            return None

        # ── Location-header redirect ──────────────────────────────────────────
        if _has_external_redirect(resp, target):
            if baseline and _has_external_redirect(baseline, target):
                return None
            return self._build(
                "Location Header", test_url, page_url, param,
                payload, payload_obj, resp,
                f"Redirect to {target}", "certain",
                domain_id, endpoint_id,
            )

        # ── Body injection ────────────────────────────────────────────────────
        if _has_body_injection(resp, target):
            if baseline and _has_body_injection(baseline, target):
                return None
            return self._build(
                "Body Redirect", test_url, page_url, param,
                payload, payload_obj, resp,
                f"Body contains {target}",
                # ✅ FIX: "firm" not in CONFIDENCE_LEVELS — was silently dropped
                #         by scanner._process_finding (rank 0 < MIN_CONFIDENCE rank 1)
                "probable",
                domain_id, endpoint_id,
            )

        return None

    # ── Finding builder ───────────────────────────────────────────────────────

    def _build(
        self,
        technique:   str,
        url:         str,
        page_url:    str,
        param:       str,
        payload:     str,
        payload_obj: dict,
        resp:        ScanResponse,
        match:       str,
        confidence:  str,
        domain_id:   int,
        endpoint_id,
    ) -> dict:
        meta = _get_module_meta()
        cvss = compute_cvss(vuln_type="open_redirect")

        return {
            "vuln_type":         "open_redirect",
            "domain_id":         domain_id,
            "endpoint_id":       endpoint_id,
            "page_url":          page_url,
            "url":               url,
            "title":             f"Open Redirect via '{param}' parameter ({technique})",
            "category":          self.category,
            "confidence":        confidence,
            "parameter_name":    param,
            "payload":           payload_obj,
            "evidence":          build_evidence("GET", url, {param: payload}, resp, match),
            "raw_data":          build_raw_data(payload, param, resp),
            "cwe":               meta["cwe"],
            "wasc":              meta["wasc"],
            "reference":         meta["reference"],
            "severity":          SEVERITY_MAP["open_redirect"],
            "likelihood":        LIKELIHOOD_MAP.get(confidence, 0.5),
            "impact":            5.0,
            "cvss_score":        cvss,
            "severity_level":    severity_level(cvss),
            "exploit_available": True,
        }