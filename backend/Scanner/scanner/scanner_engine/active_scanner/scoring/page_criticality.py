"""
scoring/page_criticality.py
=============================
Assigns a criticality score (0.0 – 10.0) to each page based on:
  - URL path patterns  (admin panel > login > API > static assets)
  - Crawler phase      (admin > auth > guest)
  - Page title         (keywords like "payment", "dashboard", "settings")
  - HTTP method context (POST endpoints are more critical than GET)

The score feeds into SeverityEngine to boost/reduce CVSS scores dynamically.

Score bands:
  9.0–10.0  →  Critical  (admin panels, payment flows, auth endpoints)
  7.0–8.9   →  High      (user dashboards, API endpoints, settings)
  5.0–6.9   →  Medium    (general authenticated pages)
  3.0–4.9   →  Low       (public/informational pages)
  0.0–2.9   →  Minimal   (static assets, 404s)
"""
from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse


# ── Scored URL patterns ───────────────────────────────────────────────────────
# Format: (regex_pattern, score_boost)
# Patterns are matched against the lowercase URL path. Boosts are additive.

URL_PATTERN_SCORES: list[tuple[str, float]] = [
    # Admin / management
    (r"/(admin|administrator|wp-admin|manage|management|superuser|root)", 4.5),
    (r"/(panel|control.?panel|cpanel|backend|backoffice)",               4.0),
    (r"/(dashboard|console)",                                             3.5),

    # Authentication
    (r"/(login|signin|sign.in|auth|authenticate|sso|oauth|saml)",        4.0),
    (r"/(logout|signout|sign.out)",                                       1.0),
    (r"/(register|signup|sign.up|create.account)",                       3.0),
    (r"/(password|reset.password|forgot.password|change.password)",      3.5),
    (r"/(2fa|mfa|otp|two.factor|verify)",                                3.5),

    # Payment / financial
    (r"/(payment|checkout|billing|invoice|order|purchase|cart|buy)",     4.5),
    (r"/(credit.card|stripe|paypal|transaction|refund|subscription)",    4.5),

    # User data / settings
    (r"/(profile|account|settings|preferences|config|configuration)",    3.0),
    (r"/(user|users|member|members|customer|customers)",                  2.5),
    (r"/(upload|file.?upload|import|export)",                            3.0),

    # API endpoints
    (r"/api/v?[0-9]*/",                                                  3.5),
    (r"/(api|rest|graphql|rpc|webhook|ws|websocket)",                    3.0),

    # Sensitive data
    (r"/(report|analytics|stats|metrics|logs|audit)",                    2.5),
    (r"/(search|query|find)",                                             2.0),
    (r"/(download|attachment|document|media)",                            2.0),

    # Static / low value
    (r"\.(css|js|png|jpg|jpeg|gif|ico|svg|woff|ttf|eot|map)$",         -3.0),
    (r"/(static|assets|dist|build|vendor|public)",                       -2.0),
    (r"/(favicon|robots\.txt|sitemap\.xml)",                             -4.0),
]

# Phase multipliers (from crawler `phase` column)
PHASE_MULTIPLIER: dict[str, float] = {
    "admin":  1.30,   # +30%
    "auth":   1.15,   # +15%
    "guest":  1.00,   # baseline
    "":       1.00,
}

# Page title keyword boosts
TITLE_KEYWORD_SCORES: list[tuple[str, float]] = [
    (r"admin",           2.0),
    (r"payment|billing", 2.0),
    (r"login|signin",    1.5),
    (r"dashboard",       1.5),
    (r"settings?|config",1.0),
    (r"upload",          1.0),
    (r"api",             1.0),
    (r"profile|account", 0.5),
    (r"search",          0.5),
]

BASE_SCORE = 2.0    # every page starts here
MAX_SCORE  = 10.0
MIN_SCORE  = 0.0


class PageCriticalityScorer:
    """
    Scores a page dict (as returned by the crawler DB query) with a 0–10 criticality value.
    """

    def score(self, page: dict[str, Any]) -> float:
        """
        page dict keys used:
          url, phase, title (optional)
        Returns a float in [0, 10].
        """
        url   = (page.get("url") or "").lower()
        phase = (page.get("phase") or "guest").lower()
        title = (page.get("title") or "").lower()

        score = BASE_SCORE

        # 1. URL path pattern matching
        parsed = urlparse(url)
        path   = parsed.path.lower()
        for pattern, boost in URL_PATTERN_SCORES:
            if re.search(pattern, path, re.IGNORECASE):
                score += boost

        # 2. Query string heuristics (parameterised URLs are more interesting)
        if parsed.query:
            param_count = parsed.query.count("&") + 1
            score += min(param_count * 0.3, 1.5)   # cap at +1.5

        # 3. Phase multiplier
        multiplier = PHASE_MULTIPLIER.get(phase, 1.0)
        score *= multiplier

        # 4. Title keyword boosts
        for pattern, boost in TITLE_KEYWORD_SCORES:
            if re.search(pattern, title, re.IGNORECASE):
                score += boost

        # 5. Clamp
        return round(max(MIN_SCORE, min(MAX_SCORE, score)), 2)

    def label(self, score: float) -> str:
        if score >= 9.0:
            return "Critical"
        if score >= 7.0:
            return "High"
        if score >= 5.0:
            return "Medium"
        if score >= 3.0:
            return "Low"
        return "Minimal"

    def score_endpoint(self, endpoint: dict[str, Any]) -> float:
        """Score a bare endpoint (no phase/title — URL only)."""
        return self.score({"url": endpoint.get("url", ""), "phase": "guest", "title": ""})

    def score_form(self, form: dict[str, Any]) -> float:
        """Score using the form's action URL + page phase."""
        return self.score({
            "url":   form.get("action_url") or form.get("page_url", ""),
            "phase": form.get("phase", "guest"),
            "title": "",
        })