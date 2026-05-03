"""
scoring/severity_engine.py
============================
The SeverityEngine is the single source of truth for all numeric scores
stored in the `vulnerabilities` table.

It combines:
  ┌─────────────────────────┐     ┌──────────────────────────┐
  │   CVE CVSS base score   │  ×  │  Page criticality weight │
  │   (from NVD API)        │     │  (from PageCriticalityScorer) │
  └─────────────────────────┘     └──────────────────────────┘
                          ↓
              adjusted_cvss  (0 – 10, capped)
                          ↓
         likelihood  ×  impact  →  target_priority
                          ↓
               All DB columns populated

DB columns filled:
  severity          → raw CVSS base score (from NVD or fallback)
  likelihood        → 0.0–1.0 based on confidence string
  impact            → category-specific impact score
  cvss_score        → adjusted CVSS after criticality scaling
  exploit_available → from NVD data
  page_criticality  → raw page score from PageCriticalityScorer
  severity_level    → 1–5 ordinal (info → critical)
  target_priority   → 0–10 final triage score
  priority_category → human-readable label
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

from ..cve.cve_lookup  import CVELookup
from ..cve.cve_mapper  import get_profile, VulnCVEProfile
from .page_criticality import PageCriticalityScorer

logger = logging.getLogger("webxguard.active_scanner.severity_engine")

# ── Confidence → likelihood mapping ──────────────────────────────────────────
CONFIDENCE_LIKELIHOOD: dict[str, float] = {
    "certain":   1.0,
    "firm":      0.7,
    "tentative": 0.4,
}

# ── Category → base impact score (independent of CVSS) ───────────────────────
CATEGORY_IMPACT: dict[str, float] = {
    "sql_injection":     9.5,
    "command_injection": 10.0,
    "xxe":               9.0,
    "ssti":              9.5,
    "ssrf":              9.0,
    "path_traversal":    8.0,
    "xss":               7.0,
    "idor":              7.5,
    "open_redirect":     5.5,
    "csrf":              6.5,
}

# ── Criticality multiplier curve ──────────────────────────────────────────────
# Maps page_criticality (0–10) → multiplier applied to CVSS base score
# criticality=5 → multiplier=1.0 (no change, baseline)
# criticality=10 → multiplier=1.25 (+25%)
# criticality=0  → multiplier=0.75 (−25%)

def _criticality_multiplier(criticality: float) -> float:
    """
    Linear scaling centred at 5.0.
    Range: [0.75 (criticality=0) … 1.25 (criticality=10)]
    """
    return round(0.75 + (criticality / 10.0) * 0.5, 4)


def _severity_level(adjusted_cvss: float) -> float:
    """Map adjusted CVSS to 1–5 ordinal."""
    if adjusted_cvss >= 9.0:  return 5.0   # critical
    if adjusted_cvss >= 7.0:  return 4.0   # high
    if adjusted_cvss >= 5.0:  return 3.0   # medium
    if adjusted_cvss >= 3.0:  return 2.0   # low
    return 1.0                              # info


def _severity_label(adjusted_cvss: float) -> str:
    if adjusted_cvss >= 9.0:  return "critical"
    if adjusted_cvss >= 7.0:  return "high"
    if adjusted_cvss >= 5.0:  return "medium"
    if adjusted_cvss >= 3.0:  return "low"
    return "info"

class SeverityEngine:
    """
    Async severity scoring engine.
    Instantiate once per scan session and pass to every module.

    Usage:
        engine = SeverityEngine(cve_lookup=CVELookup())
        scores = await engine.score(
            category      = "sql_injection",
            confidence    = "certain",
            page          = page_dict,          # or endpoint / form dict
            target_type   = "page",             # "page" | "endpoint" | "form"
        )
        finding.update(scores)
    """

    def __init__(self, cve_lookup: CVELookup):
        self.cve_lookup  = cve_lookup
        self.criticality = PageCriticalityScorer()

    async def score(
        self,
        *,
        category:     str,
        confidence:   str,
        page:         dict[str, Any] | None = None,
        endpoint:     dict[str, Any] | None = None,
        form:         dict[str, Any] | None = None,
        target_type:  str = "page",   # "page" | "endpoint" | "form"
    ) -> dict[str, Any]:
        """
        Compute all score columns for a finding.

        Returns a dict with keys matching vulnerabilities table columns:
          severity, likelihood, impact, cvss_score, exploit_available,
          page_criticality, severity_level, target_priority, priority_category,
          matched_cves, cve_source
        """
        # 1. Page criticality
        page_criticality = self._get_criticality(page, endpoint, form, target_type)

        # 2. CVE data (async NVD call, cached)
        cve_data = await self.cve_lookup.get_cve_score_for_category(category)
        base_cvss = cve_data["cvss_score"]

        # 3. Adjusted CVSS based on page criticality
        multiplier     = _criticality_multiplier(page_criticality)
        adjusted_cvss  = round(min(10.0, base_cvss * multiplier), 2)

        # 4. Likelihood from confidence
        likelihood = CONFIDENCE_LIKELIHOOD.get(confidence, 0.5)

        # 5. Impact from category
        cat_key = category.lower().replace(" ", "_").replace("-", "_")
        impact  = CATEGORY_IMPACT.get(cat_key, 6.0)

        # 7. Derived fields
        sev_level = _severity_level(adjusted_cvss)
        sev_label = _severity_label(adjusted_cvss)

        return {
            # ── Core score columns ─────────────────────────
            "severity":          base_cvss,           # raw NVD CVSS base
            "likelihood":        likelihood,
            "impact":            impact,
            "cvss_score":        adjusted_cvss,        # criticality-adjusted
            "exploit_available": cve_data["exploit_available"],
            "page_criticality":  page_criticality,
            # ── Derived ────────────────────────────────────
            "severity_level":    sev_level,
            # ── CVE metadata (for display / evidence) ──────
            "matched_cves":      cve_data.get("matched_cves", []),
            "best_cve_id":       cve_data.get("best_cve_id", ""),
            "cve_source":        cve_data.get("source", "fallback"),
            "severity_label":    sev_label,
            "criticality_multiplier": multiplier,
        }

    # ── Criticality dispatcher ────────────────────────────────────────────────

    def _get_criticality(self, page, endpoint, form, target_type) -> float:
        if target_type == "form" and form:
            return self.criticality.score_form(form)
        if target_type == "endpoint" and endpoint:
            return self.criticality.score_endpoint(endpoint)
        if page:
            return self.criticality.score(page)
        # Last resort: try whichever is available
        for obj, method in [(form, self.criticality.score_form),
                             (endpoint, self.criticality.score_endpoint)]:
            if obj:
                return method(obj)
        return 5.0   # neutral baseline

    # ── Convenience sync wrapper (for tests) ─────────────────────────────────

    def score_sync(self, **kwargs) -> dict[str, Any]:
        """Synchronous wrapper — only for unit tests, not production use."""
        return asyncio.get_event_loop().run_until_complete(self.score(**kwargs))