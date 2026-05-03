"""
cve/cve_mapper.py
==================
Maps every active-scanner vulnerability category to:
  - NVD keyword search terms (used for live CVE lookup)
  - A curated list of representative CVE IDs (well-known, stable references)
  - Fallback CVSS scores if NVD is unreachable

These CVEs are used to:
  1. Pull a real CVSS base score from NVD
  2. Attach CWE / reference data to findings
  3. Show operators which real-world CVEs match the detected pattern
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class VulnCVEProfile:
    category:          str
    nvd_keywords:      list[str]              # sent to NVD keyword search
    representative_cves: list[str]            # well-known CVEs for this class
    fallback_cvss:     float                  # used if NVD is unreachable
    fallback_severity: str                    # critical/high/medium/low
    cwe:               str
    wasc:              str
    description:       str


# ── Master mapping ────────────────────────────────────────────────────────────
VULN_CVE_PROFILES: dict[str, VulnCVEProfile] = {

    "sql_injection": VulnCVEProfile(
        category           = "SQL Injection",
        nvd_keywords       = ["SQL injection"],
        representative_cves= ["CVE-2012-1823", "CVE-2019-9193", "CVE-2022-21661",
                               "CVE-2023-23752", "CVE-2021-22205"],
        fallback_cvss      = 9.8,
        fallback_severity  = "critical",
        cwe                = "CWE-89",
        wasc               = "WASC-19",
        description        = "Unsanitised user input incorporated into SQL queries, "
                             "allowing an attacker to read, modify, or delete database data.",
    ),

    "xss": VulnCVEProfile(
        category           = "XSS",
        nvd_keywords       = ["cross-site scripting XSS reflected"],
        representative_cves= ["CVE-2020-11022", "CVE-2021-41773", "CVE-2022-22965",
                               "CVE-2023-26360", "CVE-2019-11358"],
        fallback_cvss      = 6.1,
        fallback_severity  = "medium",
        cwe                = "CWE-79",
        wasc               = "WASC-8",
        description        = "User-supplied data is reflected in the response without "
                             "proper HTML encoding, enabling script injection.",
    ),

    "command_injection": VulnCVEProfile(
        category           = "Command Injection",
        nvd_keywords       = ["OS command injection"],
        representative_cves= ["CVE-2021-42013", "CVE-2021-41773", "CVE-2022-1388",
                               "CVE-2023-27997", "CVE-2021-22941"],
        fallback_cvss      = 9.8,
        fallback_severity  = "critical",
        cwe                = "CWE-78",
        wasc               = "WASC-31",
        description        = "User input is passed to an OS shell without sanitisation, "
                             "allowing arbitrary command execution on the server.",
    ),

    "path_traversal": VulnCVEProfile(
        category           = "Path Traversal",
        nvd_keywords       = ["path traversal directory traversal"],
        representative_cves= ["CVE-2021-41773", "CVE-2019-0230", "CVE-2022-22947",
                               "CVE-2023-22515", "CVE-2021-45046"],
        fallback_cvss      = 7.5,
        fallback_severity  = "high",
        cwe                = "CWE-22",
        wasc               = "WASC-33",
        description        = "File path parameters are not normalised, allowing traversal "
                             "outside the web root to read arbitrary files.",
    ),

    "ssrf": VulnCVEProfile(
        category           = "SSRF",
        nvd_keywords       = ["server-side request forgery SSRF"],
        representative_cves= ["CVE-2021-26855", "CVE-2022-22947", "CVE-2019-18935",
                               "CVE-2023-23397", "CVE-2021-21985"],
        fallback_cvss      = 9.8,
        fallback_severity  = "critical",
        cwe                = "CWE-918",
        wasc               = "WASC-40",
        description        = "The server fetches user-supplied URLs, allowing access "
                             "to internal infrastructure and cloud metadata.",
    ),

    "xxe": VulnCVEProfile(
        category           = "XXE",
        nvd_keywords       = ["XML external entity XXE injection"],
        representative_cves= ["CVE-2019-12402", "CVE-2021-44228", "CVE-2018-1000840",
                               "CVE-2022-45378", "CVE-2021-23926"],
        fallback_cvss      = 8.6,
        fallback_severity  = "high",
        cwe                = "CWE-611",
        wasc               = "WASC-43",
        description        = "XML parser is configured to process external entities, "
                             "enabling file disclosure and SSRF.",
    ),

    "ssti": VulnCVEProfile(
        category           = "SSTI",
        nvd_keywords       = ["server-side template injection SSTI"],
        representative_cves= ["CVE-2022-22965", "CVE-2019-3396", "CVE-2020-9483",
                               "CVE-2021-25646", "CVE-2022-46169"],
        fallback_cvss      = 9.8,
        fallback_severity  = "critical",
        cwe                = "CWE-94",
        wasc               = "WASC-20",
        description        = "User input is embedded in a template and evaluated by "
                             "the template engine, allowing remote code execution.",
    ),

    "idor": VulnCVEProfile(
        category           = "IDOR",
        nvd_keywords       = ["insecure direct object reference broken access control"],
        representative_cves= ["CVE-2023-20198", "CVE-2021-21315", "CVE-2022-0540",
                               "CVE-2022-27596", "CVE-2021-38647", "CVE-2024-38874"],
        fallback_cvss      = 8.8,
        fallback_severity  = "high",
        cwe                = "CWE-639",
        wasc               = "WASC-2",
        description        = "Object identifiers exposed in requests are not validated "
                             "against the authenticated user, allowing unauthorised access.",
    ),

    "open_redirect": VulnCVEProfile(
        category           = "Open Redirect",
        nvd_keywords       = ["open redirect unvalidated redirect"],
        representative_cves= ["CVE-2018-1000620", "CVE-2020-7699", "CVE-2021-41281",
                               "CVE-2022-22576", "CVE-2019-11358"],
        fallback_cvss      = 6.1,
        fallback_severity  = "medium",
        cwe                = "CWE-601",
        wasc               = "WASC-38",
        description        = "The application redirects to attacker-controlled URLs, "
                             "enabling phishing and credential harvesting.",
    ),

    "csrf": VulnCVEProfile(
        category           = "CSRF",
        nvd_keywords       = ["cross-site request forgery CSRF"],
        representative_cves= ["CVE-2020-11022", "CVE-2021-32682", "CVE-2019-9978",
                               "CVE-2022-29221", "CVE-2021-24917"],
        fallback_cvss      = 6.5,
        fallback_severity  = "medium",
        cwe                = "CWE-352",
        wasc               = "WASC-9",
        description        = "State-changing requests lack proper CSRF protection, "
                             "allowing attackers to forge requests on behalf of victims.",
    ),
}


def get_profile(category: str) -> VulnCVEProfile | None:
    """Return the CVE profile for a given vuln category key."""
    return VULN_CVE_PROFILES.get(category.lower().replace(" ", "_").replace("-", "_"))


def all_categories() -> list[str]:
    return list(VULN_CVE_PROFILES.keys())