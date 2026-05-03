# modules/path_traversal.py
from __future__ import annotations

import logging
from urllib.parse import urlparse

from ..request_sender import RequestSender, ScanResponse
from ..response_checker import (
    build_evidence,
    build_raw_data,
    contains_any,
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

logger = logging.getLogger("webxguard.active_scanner.path_traversal")

SAFE_VALUE = "index.html"

_META:        dict | None = None
_MODULE_META: dict | None = None

# Strong-match patterns — presence of any of these in the body means the
# indicator matched real file content, not just a reflection of the payload.
_STRONG_PATTERNS = (
    "root:x:",
    "/bin/bash",
    "[fonts]",
    "[extensions]",
    "localhost",
    "daemon:x:",
)


def _get_meta() -> dict:
    global _META
    if _META is None:
        _META = load_payloads("path_traversal")
    return _META


def _get_module_meta() -> dict:
    global _MODULE_META
    if _MODULE_META is None:
        _MODULE_META = _get_meta()["meta"]
    return _MODULE_META


def _url_path(url: str) -> str:
    return urlparse(url).path or "/"


def _strong_match(match: str, body_lower: str) -> bool:
    """
    Guard against pure payload reflections.

    ✅ FIX: accepts pre-lowercased body_lower (resp.body_lower slot) so no
    repeated .lower() allocation per call.  match is lowercased here once.
    """
    match_lower = match.lower()

    # If the matched pattern appears exactly once it's likely just a reflection
    if match_lower in body_lower and body_lower.count(match_lower) == 1:
        return False

    return any(p in body_lower for p in _STRONG_PATTERNS)


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  MODULE
# ╚══════════════════════════════════════════════════════════════════════════════

class PathTraversalModule:
    name     = "path_traversal"
    category = "Path Traversal"

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

        file_params = set(meta.get("file_params", []))
        priority    = [p for p in params if p.lower()     in file_params]
        remaining   = [p for p in params if p.lower() not in file_params]

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

        # ✅ use_cache=True — baseline reused if another module already fetched it
        baseline = await self.sender.get(
            inject_param(url, param, SAFE_VALUE), use_cache=True,
        )
        baseline_body = baseline.body if baseline else ""

        if contains_any(baseline_body, meta["indicators"]):
            return []

        seen_matches: set[str] = set()

        for p in meta["payloads"]:
            payload  = p["value"]
            test_url = inject_param(url, param, payload)

            resp = await self.sender.get(test_url)
            if not resp:
                continue

            match = contains_any(resp.body, meta["indicators"])
            if not match:
                continue

            # ✅ FIX: pass resp.body_lower (pre-computed slot) — no .lower() inside
            if not _strong_match(match, resp.body_lower):
                continue

            if match in seen_matches:
                continue
            seen_matches.add(match)

            findings.append(self._build(
                test_url, url, param, payload, p, resp, match,
                domain_id, endpoint_id,
            ))

        return findings

    # ── Finding builder ───────────────────────────────────────────────────────

    def _build(
        self,
        url:         str,
        page_url:    str,
        param:       str,
        payload:     str,
        payload_obj: dict,
        resp:        ScanResponse,
        match:       str,
        domain_id:   int,
        endpoint_id,
    ) -> dict:
        meta = _get_module_meta()
        cvss = compute_cvss(vuln_type="path_traversal")

        return {
            "vuln_type":         "path_traversal",
            "domain_id":         domain_id,
            "endpoint_id":       endpoint_id,
            "page_url":          page_url,
            "url":               url,
            "title":             f"Path Traversal via '{param}' parameter",
            "category":          self.category,
            "confidence":        "certain",
            "parameter_name":    param,
            "payload":           payload_obj,
            "evidence":          build_evidence("GET", url, {param: payload}, resp, match),
            "raw_data":          build_raw_data(payload, param, resp),
            "cwe":               meta["cwe"],
            "wasc":              meta["wasc"],
            "reference":         meta["reference"],
            "severity":          SEVERITY_MAP["path_traversal"],
            "likelihood":        1.0,
            "impact":            8.0,
            "cvss_score":        cvss,
            "severity_level":    severity_level(cvss),
            "exploit_available": True,
        }