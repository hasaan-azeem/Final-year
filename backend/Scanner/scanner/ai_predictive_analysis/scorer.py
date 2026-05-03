"""
posture/scorer.py
=================
Computes the real-time security score (0-100) from monitor_vulnerabilities.

Formula (per vulnerability):
    decay        = exp(-λ × age_hours)
    base         = cvss×0.35 + likelihood×10×0.20 + impact×0.20
                 + page_criticality×0.15 + severity×0.10
    contribution = base × decay × exploit_mult × confidence_mult

Aggregate score:
    norm_i       = contribution_i / MAX_CONTRIBUTION   (0-1 per vuln)
    avg_severity = mean(norm_i)                        (quality of threats)
    count_factor = min(0.30, log1p(N) × 0.046)        (volume pressure)
    score        = min(100, (avg_severity + count_factor) × 100)

Why this formula:
    The old formula (sum / (N×0.5) × 10) gave ~80-100 for ANY site because
    average contribution (~4.5) divided by 0.5 × 10 ≈ 90 regardless of N.
    The new formula normalises each contribution against the theoretical
    maximum (cvss=10, exploit, certain, fresh = 13.5) so the score reflects
    actual threat quality, with a log-scaled count bonus for volume.

Score reference:
    3  low  vulns (cvss~3)           →  ~21  Safe/Low
    10 med  vulns (cvss~5.5)         →  ~44  Medium
    5  high vulns (cvss~7.5)         →  ~53  Medium/High
    5  crit vulns (cvss~9, exploit)  →  ~97  Critical
    20 mixed (typical site)          →  ~38  Low/Medium

Risk levels:
    80-100 → Critical  |  60-79 → High  |  40-59 → Medium
    20-39  → Low       |   0-19 → Safe
"""
from __future__ import annotations

import logging
import math
from datetime import datetime, timezone

logger = logging.getLogger("webxguard.posture.scorer")

DECAY_LAMBDA = 0.15
EXPLOIT_MULT = 1.35

CONFIDENCE_MULT = {
    "certain":   1.00,
    "firm":      0.85,
    "tentative": 0.65,
}

WEIGHTS = {
    "cvss_score":       0.35,
    "likelihood":       0.20,
    "impact":           0.20,
    "page_criticality": 0.15,
    "severity":         0.10,
}

# Theoretical max: all inputs=10, exploit=True, confidence=certain, age=0
# = (10 × sum_of_weights) × EXPLOIT_MULT = 10.0 × 1.35 = 13.5
_MAX_CONTRIBUTION: float = (
    10.0 * WEIGHTS["cvss_score"]       +
    (1.0 * 10) * WEIGHTS["likelihood"] +
    10.0 * WEIGHTS["impact"]           +
    10.0 * WEIGHTS["page_criticality"] +
    10.0 * WEIGHTS["severity"]
) * EXPLOIT_MULT   # = 13.5

RISK_THRESHOLDS: list[tuple[float, str]] = [
    (80.0, "Critical"),
    (60.0, "High"),
    (40.0, "Medium"),
    (20.0, "Low"),
    ( 0.0, "Safe"),
]


def risk_level(score: float) -> str:
    for threshold, label in RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "Safe"


def _vuln_contribution(row: dict, now: datetime) -> float:
    """Decay-weighted, exploit-adjusted contribution of one vulnerability."""
    created_at = row.get("created_at")
    if isinstance(created_at, str):
        created_at = datetime.fromisoformat(created_at)
    if created_at and created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=timezone.utc)
    age_hours = (now - created_at).total_seconds() / 3600 if created_at else 72.0

    cvss  = float(row.get("cvss_score")       or 5.0)
    lk    = float(row.get("likelihood")       or 0.5)
    imp   = float(row.get("impact")           or 5.0)
    pcrit = float(row.get("page_criticality") or 5.0)
    sev   = float(row.get("severity")         or 5.0)

    base = (
        cvss      * WEIGHTS["cvss_score"]       +
        (lk * 10) * WEIGHTS["likelihood"]       +
        imp       * WEIGHTS["impact"]           +
        pcrit     * WEIGHTS["page_criticality"] +
        sev       * WEIGHTS["severity"]
    )
    decay   = math.exp(-DECAY_LAMBDA * age_hours)
    exploit = EXPLOIT_MULT if row.get("exploit_available") else 1.0
    conf    = CONFIDENCE_MULT.get(
        str(row.get("confidence") or "firm").lower(), 0.85
    )
    return base * decay * exploit * conf


def compute_score(
    vulns: list[dict],
    now:   datetime | None = None,
) -> tuple[float, dict, list[float]]:
    """
    Compute security score for a list of DEDUPLICATED monitor_vulnerabilities rows.
    (Deduplication is done in db.fetch_monitor_vulns — one row per unique finding.)

    Returns:
        (score_float, counts_dict, contributions_list)
    """
    if now is None:
        now = datetime.now(timezone.utc)

    if not vulns:
        return 0.0, {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}, []

    contributions: list[float] = []
    counts = {"total": len(vulns), "critical": 0, "high": 0, "medium": 0, "low": 0}

    for row in vulns:
        contributions.append(_vuln_contribution(row, now))
        cat = str(row.get("priority_category") or "low").lower().strip()
        if cat in counts:
            counts[cat] += 1
        else:
            counts["low"] += 1

    # avg_severity: how severe are the vulns on average (0-1)
    # count_factor: log-scaled volume pressure (max +30 pts)
    avg_severity = sum(c / _MAX_CONTRIBUTION for c in contributions) / len(contributions)
    count_factor = min(0.30, math.log1p(len(vulns)) * 0.046)
    score        = round(min(100.0, max(0.0, (avg_severity + count_factor) * 100)), 2)

    return score, counts, contributions