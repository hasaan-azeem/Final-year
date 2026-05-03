"""
compliance/checker.py - SIMPLIFIED VERSION

Orchestrates the full compliance check for one scan session.
Uses existing category and title columns - NO vuln_type required.

Flow:
  1. Load all vulnerabilities for the session from the DB
  2. For each vulnerability, resolve which compliance rules it violates
     (mapper uses category → title keyword fallback)
  3. Persist each (vulnerability × rule) pair to compliance_violations
  4. Per standard: compute compliant % and upsert to compliance_scores
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .mapper import get_violated_rules
from .standard.rules import ALL_STANDARDS, Rule
from .db import (
    load_vulnerabilities,
    save_violation,
    save_score,
    get_scores,
)

logger = logging.getLogger("webxguard.compliance.checker")

# ── Score thresholds ──────────────────────────────────────────────────────────
_PASS_THRESHOLD = 80.0   # ≥ 80% compliant → pass
_WARN_THRESHOLD = 50.0   # ≥ 50%           → warn  |  < 50% → fail


def _status(pct: float) -> str:
    if pct >= _PASS_THRESHOLD:
        return "pass"
    if pct >= _WARN_THRESHOLD:
        return "warn"
    return "fail"


# ── Per-standard accumulator ──────────────────────────────────────────────────

@dataclass
class _StandardResult:
    standard:   str
    total_rules: int
    violated_rule_ids: set[str] = field(default_factory=set)
    # rule_id → list of vuln ids that triggered it
    violation_map: dict[str, list[int]] = field(default_factory=dict)

    @property
    def violated_rules(self) -> int:
        return len(self.violated_rule_ids)

    @property
    def compliant_rules(self) -> int:
        return self.total_rules - self.violated_rules

    @property
    def score_percent(self) -> float:
        if self.total_rules == 0:
            return 100.0
        return (self.compliant_rules / self.total_rules) * 100.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "standard":          self.standard,
            "total_rules":       self.total_rules,
            "violated_rules":    self.violated_rules,
            "compliant_rules":   self.compliant_rules,
            "score_percent":     round(self.score_percent, 2),
            "status":            _status(self.score_percent),
            "violated_rule_ids": sorted(self.violated_rule_ids),
        }


# ── Main class ────────────────────────────────────────────────────────────────

class ComplianceChecker:
    """
    Runs a full compliance check for one scan session.
    Instantiate and call `await checker.run()`.
    
    Uses existing vulnerability columns (category, title) - no vuln_type required.
    """

    def __init__(
        self,
        session_id: str,
        domain_id: int,
        active_standards: list[str] | None = None,
    ) -> None:
        self.session_id       = session_id
        self.domain_id        = domain_id
        self.active_standards = active_standards or list(ALL_STANDARDS.keys())

        unknown = set(self.active_standards) - set(ALL_STANDARDS)
        if unknown:
            raise ValueError(f"Unknown compliance standards: {unknown}")

    async def run(self) -> dict[str, dict[str, Any]]:
        """
        Run the full compliance check, persist results, return summary dict.

        Returns:
            {standard_name: _StandardResult.to_dict()} for each standard.
        """
        logger.info(
            "[Compliance] Starting — session=%s domain=%d standards=%s",
            self.session_id, self.domain_id, self.active_standards,
        )

        # 1. Load vulnerabilities
        vulns = await load_vulnerabilities(self.session_id)
        logger.info("[Compliance] Loaded %d vulnerabilities", len(vulns))

        if not vulns:
            logger.warning(
                "[Compliance] No vulnerabilities found — "
                "all standards will score 100%%"
            )

        # 2. Initialise per-standard accumulators
        results: dict[str, _StandardResult] = {
            std: _StandardResult(
                standard=std,
                total_rules=len(ALL_STANDARDS[std]),
            )
            for std in self.active_standards
        }

        # 3. Process each vulnerability
        saved = skipped = 0

        for vuln in vulns:
            vuln_id   = vuln["id"]
            category  = vuln.get("category")  or ""
            title     = vuln.get("title")      or ""

            # Map to compliance rules using category and title
            violated = get_violated_rules(
                category=category,
                title=title,
                active_standards=self.active_standards,
            )

            for standard, rules in violated.items():
                result = results[standard]
                for rule in rules:
                    result.violated_rule_ids.add(rule.rule_id)
                    result.violation_map.setdefault(rule.rule_id, []).append(vuln_id)

                    row_id = await save_violation(
                        session_id=self.session_id,
                        domain_id=self.domain_id,
                        vulnerability_id=vuln_id,
                        standard=standard,
                        rule_id=rule.rule_id,
                        rule_name=rule.rule_name,
                        category=category,
                        title=title,
                        page_url=vuln.get("page_url") or "",
                        severity=vuln.get("severity"),
                        cvss_score=vuln.get("cvss_score"),
                        confidence=vuln.get("confidence"),
                    )
                    if row_id:
                        saved += 1
                    else:
                        skipped += 1

        logger.info(
            "[Compliance] Violations — saved=%d  duplicate_skipped=%d",
            saved, skipped,
        )

        # 4. Compute and persist scores
        summary: dict[str, dict[str, Any]] = {}

        for std, result in results.items():
            pct = result.score_percent
            status = _status(pct)

            await save_score(
                session_id=self.session_id,
                domain_id=self.domain_id,
                standard=std,
                total_rules=result.total_rules,
                violated_rules=result.violated_rules,
                compliant_rules=result.compliant_rules,
                score_percent=pct,
                status=status,
                violated_rule_ids=sorted(result.violated_rule_ids),
            )

            summary[std] = result.to_dict()
            logger.info(
                "[Compliance] %-15s  %5.1f%%  %-4s  violated=%d/%d rules",
                std, pct, status.upper(),
                result.violated_rules, result.total_rules,
            )

        logger.info("[Compliance] Complete — session=%s", self.session_id)
        return summary


# ── Convenience shortcut ──────────────────────────────────────────────────────

async def run_compliance_check(
    session_id: str,
    domain_id: int,
    active_standards: list[str] | None = None,
) -> dict[str, dict[str, Any]]:
    """
    Module-level shortcut. Use this in main.py.

    Example:
        from webxguard.compliance.checker import run_compliance_check

        summary = await run_compliance_check(
            session_id=session_id,
            domain_id=domain_id,
        )
    """
    return await ComplianceChecker(
        session_id=session_id,
        domain_id=domain_id,
        active_standards=active_standards,
    ).run()