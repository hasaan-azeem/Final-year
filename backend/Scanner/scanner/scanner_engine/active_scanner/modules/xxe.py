from __future__ import annotations

import json
import logging
from urllib.parse import urlparse

from ..request_sender import RequestSender, ScanResponse
from ..response_checker import build_evidence, build_raw_data, contains_any
from ..utils.helpers import (
    load_payloads,
    SEVERITY_MAP,
    LIKELIHOOD_MAP,
    compute_cvss,
    severity_level,
)

logger = logging.getLogger("webxguard.active_scanner.xxe")

_META = None

_SAFE_XML = '<?xml version="1.0"?><root>safe</root>'

_XML_REJECTED = {400,404,405,415,422,501}


def _get_meta():
    global _META
    if _META is None:
        _META = load_payloads("xxe")
    return _META


def _url_path(url: str):
    return urlparse(url).path or "/"


def _resolve_payload(value: str, oob_host: str):

    if "OOB_HOST" in value:

        if not oob_host:
            return None

        return value.replace("OOB_HOST", oob_host)

    return value


def _is_oob(payload, oob_host):
    return bool(oob_host and oob_host in payload)


class XXEModule:

    name = "xxe"
    category = "XXE"

    def __init__(self, sender: RequestSender, oob_host: str = ""):
        self.sender = sender
        self.oob_host = oob_host
        self._seen: set[tuple[str,str]] = set()

    def _mark_seen(self, url, key):

        k = (_url_path(url), key)

        if k in self._seen:
            return True

        self._seen.add(k)
        return False

    def _unmark(self, url, key):
        self._seen.discard((_url_path(url), key))

    # ------------------------------------------------
    # endpoint scan
    # ------------------------------------------------

    async def scan_endpoint(self, endpoint, session_id, domain_id):

        url = endpoint["url"]

        findings = []

        meta = _get_meta()

        content_types = meta.get("content_types", [
            "application/xml",
            "text/xml"
        ])

        for ct in content_types:

            if self._mark_seen(url, ct):
                continue

            res = await self._probe_xml(
                url,
                ct,
                url,
                domain_id,
                endpoint_id=endpoint.get("id")
            )

            if res:
                findings.extend(res)
            else:
                self._unmark(url, ct)

        # json wrapped
        if not self._mark_seen(url, "json"):

            res = await self._probe_json(
                url,
                url,
                domain_id,
                endpoint_id=endpoint.get("id")
            )

            if res:
                findings.extend(res)
            else:
                self._unmark(url, "json")

        return findings

    # ------------------------------------------------
    # form scan
    # ------------------------------------------------

    async def scan_form(self, form, inputs, session_id, domain_id):

        url = form.get("action_url") or form.get("page_url")
        page_url = form.get("page_url", url)

        findings = []

        meta = _get_meta()

        for ct in meta.get("content_types", []):

            key = f"form:{ct}"

            if self._mark_seen(url, key):
                continue

            res = await self._probe_xml(
                url,
                ct,
                page_url,
                domain_id,
                form_id=form.get("id"),
            )

            if res:
                findings.extend(res)
            else:
                self._unmark(url, key)

        return findings

    async def scan_page(self, page, session_id, domain_id):
        return []

    # ------------------------------------------------
    # xml probe
    # ------------------------------------------------

    async def _probe_xml(
        self,
        url,
        content_type,
        page_url,
        domain_id,
        endpoint_id=None,
        form_id=None,
    ):

        meta = _get_meta()

        baseline = await self.sender.send_raw(
            "POST",
            url,
            data=_SAFE_XML,
            extra_headers={"Content-Type": content_type},
        )

        if not baseline:
            return []

        if baseline.status in _XML_REJECTED:
            return []

        if contains_any(baseline.body, meta["indicators"]):
            return []

        findings = []

        for p in meta["payloads"]:

            payload = _resolve_payload(p["value"], self.oob_host)

            if payload is None:
                continue

            resp = await self.sender.send_raw(
                "POST",
                url,
                data=payload,
                extra_headers={"Content-Type": content_type},
            )

            if not resp:
                continue

            match = contains_any(resp.body, meta["indicators"])

            if match:

                findings.append(
                    self._build(
                        url=url,
                        page_url=page_url,
                        param=f"body ({content_type})",
                        payload=p,
                        resp=resp,
                        match=str(match),
                        confidence="certain",
                        domain_id=domain_id,
                        label=p["label"],
                        endpoint_id=endpoint_id,
                        form_id=form_id,
                    )
                )

                continue

            if _is_oob(payload, self.oob_host):

                findings.append(
                    self._build(
                        url=url,
                        page_url=page_url,
                        param=f"body ({content_type})",
                        payload=p,
                        resp=resp,
                        match="OOB payload injected",
                        confidence="tentative",
                        domain_id=domain_id,
                        label=p["label"],
                        endpoint_id=endpoint_id,
                        form_id=form_id,
                    )
                )

        return findings

    # ------------------------------------------------
    # json wrapped
    # ------------------------------------------------

    async def _probe_json(
        self,
        url,
        page_url,
        domain_id,
        endpoint_id=None
    ):

        meta = _get_meta()

        fields = ["data","xml","payload","input","body"]

        findings = []

        for field in fields:

            baseline = await self.sender.post(
                url,
                json={field:_SAFE_XML},
                extra_headers={"Content-Type":"application/json"}
            )

            if not baseline:
                continue

            if contains_any(baseline.body, meta["indicators"]):
                continue

            for p in meta["payloads"]:

                payload = _resolve_payload(p["value"], self.oob_host)

                if payload is None:
                    continue

                resp = await self.sender.post(
                    url,
                    json={field:payload},
                    extra_headers={"Content-Type":"application/json"}
                )

                if not resp:
                    continue

                match = contains_any(resp.body, meta["indicators"])

                if match:

                    findings.append(
                        self._build(
                            url=url,
                            page_url=page_url,
                            param=f"json:{field}",
                            payload=p,
                            resp=resp,
                            match=str(match),
                            confidence="certain",
                            domain_id=domain_id,
                            label=f"{p['label']} ({field})",
                            endpoint_id=endpoint_id,
                        )
                    )

                    break

        return findings

    # ------------------------------------------------
    # finding builder
    # ------------------------------------------------

    def _build(
        self,
        *,
        url,
        page_url,
        param,
        payload,
        resp,
        match,
        confidence,
        domain_id,
        label="",
        endpoint_id=None,
        form_id=None,
    ):

        meta = _get_meta()["meta"]

        cvss = compute_cvss(vuln_type="xxe")

        return {

            "vuln_type": "xxe",
            "domain_id": domain_id,
            "page_url": page_url,
            "url": url,

            # title includes param
            "title": f"XML External Entity ({param}) — {label}",

            "category": self.category,
            "confidence": confidence,
            "parameter_name": param,

            # JSONB payload
            "payload": payload,

            "evidence": build_evidence(
                "POST",
                url,
                {},
                resp,
                match,
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

            "severity": SEVERITY_MAP["xxe"],
            "likelihood": LIKELIHOOD_MAP.get(confidence,0.5),
            "impact": 9.0,

            "cvss_score": cvss,
            "exploit_available": True,
            "severity_level": severity_level(cvss),
        }