"""
modules/idor.py
Detects Insecure Direct Object Reference (IDOR).
"""
from __future__ import annotations

import asyncio
import logging
import re
from urllib.parse import urlparse

from ..request_sender import RequestSender, ScanResponse
from ..response_checker import build_evidence, build_raw_data, status_is_success
from ..utils.helpers import (
    load_payloads, extract_path_ids, inject_param,
    get_query_params, SEVERITY_MAP, LIKELIHOOD_MAP,
    compute_cvss, severity_level,
)

logger = logging.getLogger("webxguard.active_scanner.idor")

_META = None

SIMILARITY_THRESHOLD = 0.85

_STATIC_EXTS = {
    ".js", ".mjs", ".css", ".map",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp",
    ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".pdf", ".zip",
}

_VERSION_HASH_MIN_DIGITS = 9
_CONFIG: dict | None = None

# ✅ FIX-14: module-level cache for successful logins only.
#            Failures are NOT cached — a new scan can retry after a transient error.
_AUTH_CACHE: dict[str, dict[str, str]] = {}


def _get_meta() -> dict:
    global _META
    if _META is None:
        _META = load_payloads("idor")
    return _META


def _url_path(url: str) -> str:
    return urlparse(url).path or "/"


def _load_config() -> dict:
    global _CONFIG
    if _CONFIG is not None:
        return _CONFIG
    try:
        from ....config import (
            LOGIN_ENABLED, LOGIN_URL,
            LOGIN_USERNAME, LOGIN_PASSWORD,
            LOGIN_USER_FIELD, LOGIN_PASS_FIELD,
        )
        _CONFIG = {
            "enabled":    LOGIN_ENABLED,
            "url":        LOGIN_URL,
            "username":   LOGIN_USERNAME,
            "password":   LOGIN_PASSWORD,
            "user_field": LOGIN_USER_FIELD or "username",
            "pass_field": LOGIN_PASS_FIELD or "password",
        }
    except ImportError as exc:
        logger.warning("[IDOR] Could not import config: %s", exc)
        _CONFIG = {"enabled": False, "url": ""}
    return _CONFIG


def _is_static_url(url: str) -> bool:
    path = url.split("?")[0].lower()
    return any(path.endswith(ext) for ext in _STATIC_EXTS)


def _is_version_hash(value: int) -> bool:
    return len(str(abs(value))) >= _VERSION_HASH_MIN_DIGITS


async def _login(sender: RequestSender, login_url: str, cfg: dict) -> dict[str, str] | None:
    """
    Attempt to authenticate and return session headers.

    ✅ FIX-14: Does NOT cache failure.  Only a successful login is stored in
    _AUTH_CACHE.  This allows a subsequent scan to retry when the login server
    was temporarily unavailable, rather than caching None indefinitely.
    """
    logger.info("[IDOR] Authenticating at %s as '%s' …", login_url, cfg["username"])

    pre  = await sender.get(login_url, follow_redirects=True)
    data = {cfg["user_field"]: cfg["username"], cfg["pass_field"]: cfg["password"]}

    if pre:
        m = re.search(
            r'<input[^>]+name=["\']'
            r'(logintoken|sesskey|_token|csrfmiddlewaretoken|__RequestVerificationToken)'
            r'["\'][^>]+value=["\']([^"\']{4,})["\']',
            pre.body, re.IGNORECASE,
        )
        if not m:
            m = re.search(
                r'<input[^>]+value=["\']([^"\']{4,})["\'][^>]+'
                r'name=["\']'
                r'(logintoken|sesskey|_token|csrfmiddlewaretoken|__RequestVerificationToken)'
                r'["\']',
                pre.body, re.IGNORECASE,
            )
            token_name = m.group(2) if m else None
            token_val  = m.group(1) if m else None
        else:
            token_name, token_val = m.group(1), m.group(2)
        if token_name and token_val:
            data[token_name] = token_val
            logger.debug("[IDOR] Pre-auth token: %s = %s…", token_name, token_val[:8])

    resp = await sender.post(login_url, data=data, follow_redirects=True)
    if resp is None:
        logger.warning("[IDOR] Login POST returned no response")
        return None   # ✅ not cached — will retry next scan

    set_cookie    = resp.headers.get("Set-Cookie", "")
    session_names = {
        "moodlesession", "phpsessid", "session", "jsessionid",
        "laravel_session", "asp.net_sessionid", "ci_session",
    }
    if not any(name in set_cookie.lower() for name in session_names):
        logger.warning("[IDOR] Login failed — no session cookie (status=%d final=%s)",
                       resp.status, resp.final_url)
        return None   # ✅ not cached — will retry next scan

    cookies = "; ".join(
        part.split(";")[0].strip()
        for part in set_cookie.split(",") if "=" in part.split(";")[0]
    )
    logger.info("[IDOR] Login OK (status=%d  final=%s)", resp.status, resp.final_url)
    headers = {"Cookie": cookies}
    _AUTH_CACHE[login_url] = headers   # ✅ only success is cached
    return headers


# ╔══════════════════════════════════════════════════════════════════════════════
# ║  MODULE
# ╚══════════════════════════════════════════════════════════════════════════════

class IDORModule:
    name     = "idor"
    category = "IDOR"

    def __init__(self, sender: RequestSender, oob_host: str = ""):
        self.sender   = sender
        self.oob_host = oob_host

        # ✅ FIX-11: _reported moved from module-level to instance-level.
        #            Module-level set persisted across scans in the same process,
        #            causing all IDOR findings on re-scanned targets to be silently
        #            skipped (false negatives on every scan after the first).
        self._reported: set[str] = set()

        # ✅ FIX-14: instance-level auth state prevents repeated login attempts
        #            within a single scan while still allowing retry across scans.
        self._auth_fetched: bool                    = False
        self._auth_headers: dict[str, str] | None  = None

    async def _get_auth(self) -> dict[str, str] | None:
        """
        Return cached auth headers for this scan instance.

        Priority:
          1. Already fetched this instance → return cached result immediately.
          2. Module-level success cache (previous scan in same process) → reuse.
          3. Attempt fresh login.
        """
        if self._auth_fetched:
            return self._auth_headers

        cfg       = _load_config()
        login_url = cfg.get("url", "")

        # Reuse a previously successful login from an earlier scan
        if login_url and login_url in _AUTH_CACHE:
            self._auth_fetched = True
            self._auth_headers = _AUTH_CACHE[login_url]
            return self._auth_headers

        result = await _login(self.sender, login_url, cfg) if login_url else None
        self._auth_fetched = True
        self._auth_headers = result
        return result

    # ── Entry points ──────────────────────────────────────────────────────────

    async def scan_endpoint(self, endpoint: dict, session_id: str, domain_id: int) -> list[dict]:
        auth = await self._get_auth()
        if auth is None and _load_config().get("enabled", False):
            return []
        return await self._probe(endpoint["url"], domain_id,
                                 endpoint_id=endpoint.get("id"), auth=auth)

    async def scan_form(self, form: dict, inputs: list[dict],
                        session_id: str, domain_id: int) -> list[dict]:
        return []

    async def scan_page(self, page: dict, session_id: str, domain_id: int) -> list[dict]:
        auth = await self._get_auth()
        if auth is None and _load_config().get("enabled", False):
            return []
        return await self._probe(page["url"], domain_id,
                                 page_id=page.get("id"), auth=auth)

    # ── Core probe ────────────────────────────────────────────────────────────

    async def _probe(self, url: str, domain_id: int, auth: dict | None = None,
                     page_id=None, endpoint_id=None) -> list[dict]:

        if _is_static_url(url):
            logger.debug("[IDOR] Skipping static asset: %s", url)
            return []

        meta         = _get_meta()
        offsets      = meta.get("strategy",   {}).get("numeric_neighbors", [-1, 1])
        common_ids   = meta.get("strategy",   {}).get("common_ids", [])
        ratio_range  = meta.get("heuristics", {}).get("size_ratio_threshold", [0.7, 1.3])
        success_codes = meta.get("heuristics", {}).get("success_codes", [200])
        lo, hi       = ratio_range

        headers  = auth or {}
        findings: list[dict] = []
        seen:     set[str]   = set()

        baseline = await self.sender.get(url, extra_headers=headers)
        if baseline is None or baseline.status not in success_codes:
            return findings
        # ✅ FIX-12: pass body_lower (pre-computed slot) — avoids re-lowercasing
        if _is_login_page(baseline.body_lower):
            return findings

        # ✅ FIX-15: pre-compute baseline token set once here; _compare receives
        #            it directly so the same baseline is never re-tokenized per candidate.
        base_tokens = _compute_tokens(baseline.body_lower)

        # ── Query param IDs ───────────────────────────────────────────────────
        params = get_query_params(url)
        for param, values in params.items():
            if param.lower() not in meta.get("id_params", []):
                continue
            try:
                orig_id = int(values[0])
            except (ValueError, IndexError):
                continue
            if _is_version_hash(orig_id):
                continue

            candidates  = [orig_id + o for o in offsets] + common_ids
            tasks:       list = []
            dedup_keys:  list[str] = []
            cid_list:    list[int] = []

            for cid in candidates:
                if cid <= 0 or cid == orig_id:
                    continue
                test_url  = inject_param(url, param, str(cid))
                dedup_key = f"{_url_path(url)}|{param}|{cid}"
                if test_url in seen or dedup_key in self._reported:
                    continue
                seen.add(test_url)
                dedup_keys.append(dedup_key)
                cid_list.append(cid)
                tasks.append(self.sender.get(test_url, extra_headers=headers))

            if tasks:
                # ✅ FIX-16: local semaphore caps concurrent IDOR probes so this
                #            asyncio.gather can't burst past the intended concurrency
                #            limit of the outer scanner semaphore.
                responses = await _bounded_gather(tasks)
                for resp, dedup_key, cid in zip(responses, dedup_keys, cid_list):
                    if not isinstance(resp, ScanResponse):
                        continue
                    # ✅ FIX-12: pass body_lower
                    if _is_login_page(resp.body_lower):
                        continue
                    f = self._compare(
                        baseline, resp,
                        inject_param(url, param, str(cid)),
                        url, param, f"{orig_id}→{cid}",
                        domain_id, lo, hi, base_tokens,
                        page_id=page_id, endpoint_id=endpoint_id, auth=auth,
                    )
                    if f:
                        self._reported.add(dedup_key)
                        findings.append(f)

        # ── Path IDs ──────────────────────────────────────────────────────────
        for seg in extract_path_ids(url):
            try:
                orig_id = int(seg)
            except ValueError:
                continue
            if _is_version_hash(orig_id):
                continue

            candidates = [orig_id + o for o in offsets] + common_ids
            tasks      = []
            dedup_keys = []
            cid_list   = []

            for cid in candidates:
                if cid <= 0 or cid == orig_id:
                    continue
                test_url  = url.replace(f"/{orig_id}", f"/{cid}", 1)
                dedup_key = f"{_url_path(url)}|path:{orig_id}|{cid}"
                if test_url in seen or test_url == url or dedup_key in self._reported:
                    continue
                seen.add(test_url)
                dedup_keys.append(dedup_key)
                cid_list.append(cid)
                tasks.append(self.sender.get(test_url, extra_headers=headers))

            if tasks:
                responses = await _bounded_gather(tasks)
                for resp, dedup_key, cid in zip(responses, dedup_keys, cid_list):
                    if not isinstance(resp, ScanResponse):
                        continue
                    # ✅ FIX-12
                    if _is_login_page(resp.body_lower):
                        continue
                    test_url = url.replace(f"/{orig_id}", f"/{cid}", 1)
                    f = self._compare(
                        baseline, resp,
                        test_url, url, f"path:{orig_id}", f"{orig_id}→{cid}",
                        domain_id, lo, hi, base_tokens,
                        page_id=page_id, endpoint_id=endpoint_id, auth=auth,
                    )
                    if f:
                        self._reported.add(dedup_key)
                        findings.append(f)

        return findings

    # ── Comparator ────────────────────────────────────────────────────────────

    def _compare(
        self,
        baseline:    ScanResponse,
        resp:        ScanResponse,
        test_url:    str,
        page_url:    str,
        param:       str,
        label:       str,
        domain_id:   int,
        lo:          float,
        hi:          float,
        base_tokens: set[str],   # ✅ FIX-15: pre-computed, not re-derived here
        page_id      = None,
        endpoint_id  = None,
        auth:        dict | None = None,
    ) -> dict | None:

        meta          = _get_meta()
        success_codes = meta.get("heuristics", {}).get("success_codes", [200])

        if resp.status not in success_codes:
            return None

        base_len = baseline.body_len   # pre-computed slot
        resp_len = resp.body_len       # pre-computed slot
        ratio    = resp_len / max(base_len, 1)

        if ratio == 1.0 or not (lo <= ratio <= hi):
            return None

        # ✅ FIX-15: pass resp.body_lower — avoids re-lowercasing inside
        similarity = _jaccard(base_tokens, resp.body_lower)
        if similarity >= SIMILARITY_THRESHOLD:
            return None

        # ✅ FIX-13: use headers_lower (pre-computed) — no .lower() needed
        content_type = resp.headers_lower.get("content-type", "")
        if "text" not in content_type and "json" not in content_type:
            return None

        cvss = compute_cvss(vuln_type="idor")
        sev  = SEVERITY_MAP["idor"]
        lh   = LIKELIHOOD_MAP.get("tentative", 0.4)

        logger.info("[IDOR] Potential finding param=%s %s ratio=%.2f similarity=%.0f%%",
                    param, label, ratio, similarity * 100)

        return {
            "vuln_type":      "idor",
            "domain_id":      domain_id,
            "page_url":       page_url,
            "url":            test_url,
            "title":          f"IDOR — parameter '{param}' allows object access",
            "category":       self.category,
            "confidence":     "tentative",
            "parameter_name": param,
            "payload": {
                "type":         "idor",
                "param":        param,
                "original_url": page_url,
                "payload_url":  test_url,
                "mutation":     label,
            },
            "evidence": build_evidence(
                "GET", test_url, {param: label}, resp,
                f"Baseline {base_len}B → Candidate {resp_len}B "
                f"ratio={ratio:.2f} similarity={similarity:.0%}",
                extra={
                    "baseline_status":    baseline.status,
                    "candidate_status":   resp.status,
                    "content_similarity": round(similarity, 3),
                    "authenticated":      auth is not None,
                },
            ),
            "raw_data":          build_raw_data(test_url, param, resp),
            "cwe":               meta["meta"]["cwe"],
            "wasc":              meta["meta"]["wasc"],
            "reference":         meta["meta"]["reference"],
            "page_id":           page_id,
            "endpoint_id":       endpoint_id,
            "severity":          sev,
            "likelihood":        lh,
            "impact":            7.0,
            "cvss_score":        cvss,
            "exploit_available": False,
            "severity_level":    severity_level(cvss),
        }


# ── Helpers ───────────────────────────────────────────────────────────────────

# ✅ FIX-16: semaphore caps concurrent IDOR sub-requests within one gather call
_IDOR_SEMAPHORE = asyncio.Semaphore(5)


async def _bounded_gather(tasks: list) -> list:
    """Run tasks with a local semaphore so IDOR probes don't burst concurrency."""
    async def _run(coro):
        async with _IDOR_SEMAPHORE:
            return await coro

    return await asyncio.gather(*[_run(t) for t in tasks], return_exceptions=True)


def _is_login_page(body_lower: str) -> bool:
    """
    ✅ FIX-12: accepts pre-lowercased body (body_lower slot from ScanResponse).
    The caller passes resp.body_lower directly — no allocation inside.
    """
    excerpt = body_lower[:4000]
    hits = sum(excerpt.count(kw) for kw in (
        "login", "sign in", "password", "username",
        "log in", "forgotten password", "remember me",
    ))
    return hits >= 6


def _compute_tokens(body_lower: str) -> set[str]:
    """
    ✅ FIX-15: standalone tokeniser called once per baseline (not per candidate).
    Accepts pre-lowercased body — strips HTML tags then extracts word tokens.
    """
    text = re.sub(r"<[^>]+>", " ", body_lower[:8000])
    return set(re.findall(r"[a-z0-9]{3,}", text))


def _jaccard(base_tokens: set[str], body_lower: str) -> float:
    """
    ✅ FIX-15: computes Jaccard similarity using pre-computed base_tokens.
    Only the candidate body is tokenised here.
    """
    tb = _compute_tokens(body_lower)
    if not base_tokens and not tb:
        return 1.0
    if not base_tokens or not tb:
        return 0.0
    return len(base_tokens & tb) / len(base_tokens | tb)