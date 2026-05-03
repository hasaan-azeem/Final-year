"""
cve/cve_lookup.py
==================
Queries the NVD (National Vulnerability Database) CVE 2.0 REST API
to retrieve real CVSS scores for a given vulnerability category.

Features:
  - Two-tier cache: in-memory (session) + JSON file (persists across runs)
  - Graceful fallback to cve_mapper defaults when NVD is unreachable
  - Rate-limit aware (NVD allows ~5 req/30s without API key, 50/30s with key)
  - Extracts: cvss_v3_score, severity, exploit_available (EPSS), affected_versions

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import aiohttp

from .cve_mapper import VulnCVEProfile, get_profile

logger = logging.getLogger("webxguard.active_scanner.cve_lookup")

# ── Config ────────────────────────────────────────────────────────────────────
NVD_API_BASE     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY      = os.getenv("NVD_API_KEY", "")          # optional — higher rate limit
CACHE_DIR        = Path(__file__).parent / ".cache"
CACHE_TTL_HOURS  = 24                                      # re-fetch after 24 hours
REQUEST_TIMEOUT  = 15                                      # seconds
MAX_RESULTS      = 5                                       # CVEs per keyword query
RATE_LIMIT_SLEEP = 1.0 if NVD_API_KEY else 6.5            # adaptive: faster with API key


@dataclass
class CVERecord:
    """Normalised CVE data returned to the scoring engine."""
    cve_id:            str
    cvss_score:        float
    cvss_vector:       str
    severity:          str                  # critical / high / medium / low
    description:       str
    references:        list[str]
    exploit_available: bool
    published:         str
    _source:           str = "unknown"      # "live", "cache", or "fallback"

    def to_dict(self) -> dict[str, Any]:
        """Convert to plain dict for JSON serialization."""
        return {
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "severity": self.severity,
            "description": self.description,
            "references": self.references,
            "exploit_available": self.exploit_available,
            "published": self.published,
            "_source": self._source,
        }


class CVELookup:
    """
    Async CVE lookup client.
    One shared instance per scan session — pass into SeverityEngine.
    """

    def __init__(self, use_cache: bool = True):
        self.use_cache      = use_cache
        self._mem_cache:  dict[str, dict] = {}           # key → {ts, records}
        self._rate_lock   = asyncio.Lock()
        self._last_request: float = 0.0
        CACHE_DIR.mkdir(parents=True, exist_ok=True)

    # ── Public API ─────────────────────────────────────────────────────────────

    async def get_cve_score_for_category(self, category: str) -> dict[str, Any]:
        """
        Main entry point.  Returns a dict suitable for merging into a finding:
          {
            cvss_score, severity, exploit_available,
            matched_cves: [...],   # list of CVE IDs found
            source: "nvd" | "cache" | "fallback"
          }
        """
        profile = get_profile(category)
        if profile is None:
            logger.warning("[CVE] No profile for category: %s", category)
            return self._fallback_result(category)

        # Try to get live / cached data
        records = await self._fetch_for_profile(profile)

        if not records:
            logger.warning("[CVE] No records for %s — using fallback", category)
            return self._fallback_result(category, profile)

        # Use the highest CVSS score among returned records
        best = max(records, key=lambda r: r["cvss_score"])
        avg  = round(sum(r["cvss_score"] for r in records) / len(records), 1)
        
        # Determine source: if any record is "live", mark as "nvd"; else "cache"
        sources = {r.get("_source", "unknown") for r in records}
        source = "nvd" if "live" in sources else (sources.pop() if sources else "unknown")

        return {
            "cvss_score":       best["cvss_score"],
            "severity":         best["severity"],
            "exploit_available": best["exploit_available"] or any(r["exploit_available"] for r in records),
            "matched_cves":     [r["cve_id"] for r in records],
            "avg_cvss":         avg,
            "best_cve_id":      best["cve_id"],
            "source":           source,
        }

    async def get_cve_record(self, cve_id: str) -> dict | None:
        """Fetch a single CVE by ID (e.g. 'CVE-2021-44228')."""
        cache_key = f"id:{cve_id}"
        cached = self._load_cache(cache_key)
        if cached:
            return cached[0] if cached else None

        records = await self._nvd_request(params={"cveId": cve_id})
        if records:
            # Mark as live since we just fetched it
            for r in records:
                r["_source"] = "live"
            self._save_cache(cache_key, records)
            return records[0]
        
        return None

    # ── Fetch logic ────────────────────────────────────────────────────────────

    async def _fetch_for_profile(self, profile: VulnCVEProfile) -> list[dict]:
        cache_key = f"kw:{profile.category}"

        # 1. Memory cache
        if cache_key in self._mem_cache:
            entry = self._mem_cache[cache_key]
            if time.time() - entry["ts"] < CACHE_TTL_HOURS * 3600:
                logger.debug("[CVE] Memory cache hit: %s", profile.category)
                return entry["records"]

        # 2. File cache
        cached = self._load_cache(cache_key)
        if cached:
            self._mem_cache[cache_key] = {"ts": time.time(), "records": cached}
            logger.debug("[CVE] File cache hit: %s", profile.category)
            return cached

        # 3. Live NVD request with deduplication
        all_records = []
        seen_cve_ids: set = set()  # ← Track CVE IDs to avoid duplicates
        
        for keyword in profile.nvd_keywords:
            records = await self._nvd_request(params={
                "keywordSearch": keyword,
                "resultsPerPage": MAX_RESULTS,
                # ❌ REMOVED: "cvssV3Severity" filter — get ALL severity levels
            })
            
            # Deduplicate: only add if we haven't seen this CVE ID before
            for r in records:
                cve_id = r.get("cve_id", "")
                if cve_id and cve_id not in seen_cve_ids:
                    all_records.append(r)
                    seen_cve_ids.add(cve_id)
            
            if all_records:
                break   # first keyword hit is enough

        if all_records:
            for r in all_records:
                r["_source"] = "live"
            self._save_cache(cache_key, all_records)
            self._mem_cache[cache_key] = {"ts": time.time(), "records": all_records}
            logger.debug("[CVE] Fetched %d unique records from NVD for %s", 
                        len(all_records), profile.category)

        return all_records

    # ── NVD request ────────────────────────────────────────────────────────────

    async def _nvd_request(self, params: dict) -> list[dict]:
        """Send one request to the NVD API and parse response into CVE record dicts."""
        async with self._rate_lock:
            elapsed = time.time() - self._last_request
            if elapsed < RATE_LIMIT_SLEEP:
                await asyncio.sleep(RATE_LIMIT_SLEEP - elapsed)
            self._last_request = time.time()

        headers = {}
        if NVD_API_KEY:
            headers["apiKey"] = NVD_API_KEY

        try:
            timeout = aiohttp.ClientTimeout(total=REQUEST_TIMEOUT)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(NVD_API_BASE, params=params, headers=headers) as resp:
                    if resp.status != 200:
                        logger.warning("[CVE] NVD returned HTTP %d", resp.status)
                        return []
                    data = await resp.json()
                    return self._parse_nvd_response(data)

        except asyncio.TimeoutError:
            logger.warning("[CVE] NVD request timed out after %ds", REQUEST_TIMEOUT)
        except aiohttp.ClientError as exc:
            logger.warning("[CVE] NVD request error: %s", exc)
        except Exception as exc:
            logger.exception("[CVE] Unexpected error querying NVD")

        return []

    @staticmethod
    def _parse_nvd_response(data: dict) -> list[dict]:
        """Parse NVD API response into CVE records."""
        records = []
        
        try:
            vulnerabilities = data.get("vulnerabilities", [])
        except (TypeError, AttributeError):
            logger.warning("[CVE] Invalid NVD response structure")
            return []

        for item in vulnerabilities:
            try:
                cve = item.get("cve", {})
                cve_id = cve.get("id", "").strip()
                
                if not cve_id:
                    continue

                # ── Extract CVSS score ────────────────────────────────────────
                cvss_score, cvss_vector, severity = CVELookup._extract_cvss(cve)

                # ── Description (English preferred) ────────────────────────────
                desc = CVELookup._extract_description(cve)

                # ── References ─────────────────────────────────────────────────
                refs = CVELookup._extract_references(cve)

                # ── Exploit available ──────────────────────────────────────────
                exploit_available = CVELookup._check_exploit_available(cve)

                # ── Published date ─────────────────────────────────────────────
                published = cve.get("published", "")

                records.append({
                    "cve_id":            cve_id,
                    "cvss_score":        cvss_score,
                    "cvss_vector":       cvss_vector,
                    "severity":          severity,
                    "description":       desc,
                    "references":        refs,
                    "exploit_available": exploit_available,
                    "published":         published,
                })

            except Exception as exc:
                logger.debug("[CVE] Failed to parse CVE item: %s", exc)
                continue

        return records

    # ── Helper methods for parsing ─────────────────────────────────────────────

    @staticmethod
    def _extract_cvss(cve: dict) -> tuple[float, str, str]:
        """Extract CVSS score, vector, and severity from CVE metrics."""
        cvss_score = 0.0
        cvss_vector = ""
        severity = "medium"

        try:
            metrics = cve.get("metrics", {})

            # Try v3.1 first, then v3.0, then v2.0
            for key in ("cvssMetricV31", "cvssMetricV30"):
                if key not in metrics or not metrics[key]:
                    continue
                    
                try:
                    m = metrics[key][0].get("cvssData", {})
                    cvss_score = m.get("baseScore", 0.0)
                    cvss_vector = m.get("vectorString", "")
                    severity = m.get("baseSeverity", "MEDIUM").lower()
                    return cvss_score, cvss_vector, severity
                except (IndexError, TypeError, KeyError):
                    continue

            # Fallback to CVSS v2.0
            if "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
                try:
                    m = metrics["cvssMetricV2"][0].get("cvssData", {})
                    cvss_score = m.get("baseScore", 0.0)
                    severity = "critical" if cvss_score >= 9 else "high" if cvss_score >= 7 else "medium" if cvss_score >= 4 else "low"
                    return cvss_score, cvss_vector, severity
                except (IndexError, TypeError, KeyError):
                    pass

        except Exception as exc:
            logger.debug("[CVE] CVSS extraction failed: %s", exc)

        return cvss_score, cvss_vector, severity

    @staticmethod
    def _extract_description(cve: dict) -> str:
        """Extract English description from CVE."""
        try:
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    return desc[:400] if desc else ""
        except (TypeError, AttributeError):
            pass
        return ""

    @staticmethod
    def _extract_references(cve: dict) -> list[str]:
        """Extract up to 3 reference URLs from CVE."""
        refs = []
        try:
            for r in cve.get("references", [])[:3]:
                url = r.get("url", "").strip()
                if url:
                    refs.append(url)
        except (TypeError, AttributeError):
            pass
        return refs

    @staticmethod
    def _check_exploit_available(cve: dict) -> bool:
        """Check if exploit is marked as available in CVE."""
        try:
            references = cve.get("references", [])
            for r in references:
                # Check URL
                url = r.get("url", "").lower()
                if "exploit" in url or "poc" in url:
                    return True
                
                # Check tags if present
                tags = r.get("tags", [])
                if isinstance(tags, list):
                    for tag in tags:
                        if isinstance(tag, str) and "exploit" in tag.lower():
                            return True
        except (TypeError, AttributeError):
            pass
        return False

    # ── Cache helpers ─────────────────────────────────────────────────────────

    def _cache_path(self, key: str) -> Path:
        safe_key = key.replace(":", "_").replace("/", "_").replace(" ", "_")
        return CACHE_DIR / f"{safe_key}.json"

    def _load_cache(self, key: str) -> list[dict] | None:
        if not self.use_cache:
            return None
        path = self._cache_path(key)
        if not path.exists():
            return None
        try:
            with open(path, "r") as f:
                entry = json.load(f)
            
            ts = entry.get("ts", 0)
            if time.time() - ts > CACHE_TTL_HOURS * 3600:
                path.unlink(missing_ok=True)
                logger.debug("[CVE] Cache expired: %s", key)
                return None
            
            logger.debug("[CVE] File cache hit: %s", key)
            return entry.get("records", [])
        except Exception as exc:
            logger.debug("[CVE] Cache load failed for %s: %s", key, exc)
            return None

    def _save_cache(self, key: str, records: list[dict]) -> None:
        if not self.use_cache:
            return
        try:
            path = self._cache_path(key)
            with open(path, "w") as f:
                json.dump({"ts": time.time(), "records": records}, f, indent=2)
        except Exception as exc:
            logger.debug("[CVE] Cache save failed: %s", exc)

    # ── Fallback ──────────────────────────────────────────────────────────────

    @staticmethod
    def _fallback_result(category: str, profile: VulnCVEProfile | None = None) -> dict:
        if profile is None:
            profile = get_profile(category)
        
        if profile is None:
            return {
                "cvss_score":       5.0,
                "severity":         "medium",
                "exploit_available": False,
                "matched_cves":     [],
                "avg_cvss":         5.0,
                "best_cve_id":      "",
                "source":           "fallback",
            }

        return {
            "cvss_score":       profile.fallback_cvss,
            "severity":         profile.fallback_severity,
            "exploit_available": False,
            "matched_cves":     profile.representative_cves[:3],
            "avg_cvss":         profile.fallback_cvss,
            "best_cve_id":      profile.representative_cves[0] if profile.representative_cves else "",
            "source":           "fallback",
        }