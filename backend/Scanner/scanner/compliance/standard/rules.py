"""
compliance/standards/rules.py

Rule definitions for all 5 compliance standards.
Covers every active AND passive vulnerability type WebXGuard detects.

Active  : sql_injection, xss, csrf, command_injection, path_traversal,
          xxe, ssti, ssrf, idor, open_redirect
Passive : access_control, cache, cms, comments, cookies, cors, csp,
          error_status, external_links, forms, headers, javascript,
          mixed_content, robots, secrets, sensitive_inputs, sitemap,
          ssl_tls, storage, versioning, page_content_change
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    rule_id:     str
    rule_name:   str
    description: str
    weight:      float = 1.0


# ── OWASP Top 10 (2021) ───────────────────────────────────────────────────────

OWASP_TOP10: dict[str, Rule] = {
    "A01:2021": Rule(
        "A01:2021", "Broken Access Control",
        "Restrictions on authenticated users are not properly enforced. "
        "Includes IDOR, directory traversal, privilege escalation, "
        "admin panel exposure, directory listing, sensitive file exposure.",
        weight=1.5,
    ),
    "A02:2021": Rule(
        "A02:2021", "Cryptographic Failures",
        "Failures related to cryptography exposing sensitive data. "
        "Includes weak TLS, missing HTTPS, insecure cookie attributes, "
        "mixed content, JWT in client storage, hardcoded secrets, "
        "high-entropy string exposure.",
        weight=1.5,
    ),
    "A03:2021": Rule(
        "A03:2021", "Injection",
        "User-supplied data is not validated or sanitised before execution. "
        "Includes SQL injection, OS command injection, LDAP injection, "
        "XXE, SSTI, and XSS (reflected/stored/DOM).",
        weight=2.0,
    ),
    "A04:2021": Rule(
        "A04:2021", "Insecure Design",
        "Missing or ineffective control design and security patterns. "
        "Includes CSRF, open redirect, insecure form submission over HTTP, "
        "forms submitting to external domains, unauthenticated sensitive endpoints.",
        weight=1.0,
    ),
    "A05:2021": Rule(
        "A05:2021", "Security Misconfiguration",
        "Missing security hardening across the application stack. "
        "Includes missing security headers, misconfigured CORS/CSP, "
        "directory listing, debug/error pages, version disclosure, "
        "exposed admin/actuator/database admin panels, "
        "backup file exposure, overly permissive cache headers.",
        weight=1.0,
    ),
    "A06:2021": Rule(
        "A06:2021", "Vulnerable and Outdated Components",
        "Components with known vulnerabilities used without proper management. "
        "Includes CMS version disclosure (WordPress/Drupal/Joomla), "
        "JavaScript library version exposure, outdated TLS cipher suites, "
        "PHP info exposure.",
        weight=1.0,
    ),
    "A07:2021": Rule(
        "A07:2021", "Identification and Authentication Failures",
        "Authentication weaknesses permitting compromise of credentials or sessions. "
        "Includes missing cookie attributes (HttpOnly/Secure/SameSite), "
        "low-entropy session tokens, JWT in cookies, excessive cookie lifetime, "
        "CSRF on authentication forms.",
        weight=1.5,
    ),
    "A08:2021": Rule(
        "A08:2021", "Software and Data Integrity Failures",
        "Code and infrastructure not protecting against integrity violations. "
        "Includes CORS misconfigurations allowing arbitrary origins, "
        "mixed content on HTTPS pages, insecure WebSocket connections.",
        weight=1.0,
    ),
    "A09:2021": Rule(
        "A09:2021", "Security Logging and Monitoring Failures",
        "Insufficient logging, detection, monitoring, and active response. "
        "Violated by stack traces in error pages, debug info disclosure, "
        "sensitive information in HTML comments, developer comments in production.",
        weight=0.5,
    ),
    "A10:2021": Rule(
        "A10:2021", "Server-Side Request Forgery",
        "SSRF flaws occur when a web app fetches a remote resource without "
        "validating the user-supplied URL. Also covers internal/dev URL "
        "exposure in JavaScript source.",
        weight=1.5,
    ),
}

# ── PCI-DSS v4.0 ──────────────────────────────────────────────────────────────

PCI_DSS: dict[str, Rule] = {
    "PCI-2.2.1": Rule(
        "PCI-2.2.1", "System Component Configuration Standards",
        "Configuration standards must be developed and implemented for all "
        "system components to prevent known security vulnerabilities. "
        "Covers missing security headers, CSP, CORS hardening, "
        "removal of version banners, debug endpoints, and unnecessary services.",
        weight=1.0,
    ),
    "PCI-4.2.1": Rule(
        "PCI-4.2.1", "Strong Cryptography in Transit",
        "Strong cryptography must safeguard PAN during transmission over "
        "open, public networks. Covers TLS version adequacy, "
        "cipher suite strength, HTTPS enforcement, HSTS, "
        "mixed content, insecure WebSocket, certificate validity.",
        weight=2.0,
    ),
    "PCI-6.2.4": Rule(
        "PCI-6.2.4", "Prevent Common Web Attacks in Bespoke Software",
        "Software engineering techniques to prevent or mitigate common attacks. "
        "Covers injection (SQL/OS/XXE/SSTI), XSS, CSRF, broken access control, "
        "SSRF, path traversal, open redirect, IDOR.",
        weight=2.0,
    ),
    "PCI-6.3.3": Rule(
        "PCI-6.3.3", "Security Patches and Updates",
        "All system components protected by installing applicable security "
        "patches/updates within defined timelines. "
        "Covers CMS version disclosure, JS library exposure, weak TLS versions.",
        weight=1.5,
    ),
    "PCI-6.4.1": Rule(
        "PCI-6.4.1", "Web Application Firewall",
        "Public-facing web applications protected against known attacks via "
        "WAF or equivalent technical controls. "
        "Covers CSP implementation, security headers.",
        weight=1.0,
    ),
    "PCI-6.5.1": Rule(
        "PCI-6.5.1", "Injection Flaws",
        "Injection flaws, particularly SQL injection, must be prevented. "
        "Covers SQL injection, OS command injection, XXE, SSTI, LDAP injection.",
        weight=2.0,
    ),
    "PCI-7.2.1": Rule(
        "PCI-7.2.1", "Access Control Systems",
        "Access control systems must deny all access unless explicitly allowed. "
        "Covers IDOR, admin panel exposure, directory listing, "
        "sensitive file/backup exposure, API documentation exposure.",
        weight=1.5,
    ),
    "PCI-8.2.1": Rule(
        "PCI-8.2.1", "Unique User IDs and Authentication Mechanisms",
        "All users must have unique IDs; authentication cannot be forged or bypassed. "
        "Covers cookie security attributes, CSRF on login/register forms, "
        "low-entropy session tokens, JWT in cookies.",
        weight=1.5,
    ),
    "PCI-8.6.1": Rule(
        "PCI-8.6.1", "System and Application Account Management",
        "System/application accounts and authentication managed by policy. "
        "Covers hardcoded credentials, secrets in JS/comments/storage, "
        "AWS key exposure.",
        weight=1.0,
    ),
    "PCI-11.3.1": Rule(
        "PCI-11.3.1", "External Penetration Testing",
        "External penetration testing performed at least once every 12 months "
        "and after significant infrastructure/application changes. "
        "All active vulnerability findings are relevant here.",
        weight=1.0,
    ),
    "PCI-11.4.1": Rule(
        "PCI-11.4.1", "Intrusion Detection and Prevention",
        "Intrusion-detection/prevention techniques to detect and prevent "
        "network intrusions. Covers SSRF, command injection, "
        "open redirect abuse chains.",
        weight=1.0,
    ),
}

# ── GDPR ──────────────────────────────────────────────────────────────────────

GDPR: dict[str, Rule] = {
    "GDPR-Art5": Rule(
        "GDPR-Art5", "Principles of Data Processing",
        "Personal data must be processed with integrity and confidentiality. "
        "Violated by injection attacks (data exfiltration), IDOR, "
        "secrets/credentials exposure, sensitive data in HTML comments or JS, "
        "email addresses exposed in JS/storage.",
        weight=2.0,
    ),
    "GDPR-Art25": Rule(
        "GDPR-Art25", "Data Protection by Design and Default",
        "Technical and organisational measures to implement data-protection principles. "
        "Covers cookie security attributes, CSP, security headers, "
        "CORS misconfiguration, CSRF protection, mixed content, "
        "cache control on sensitive pages.",
        weight=1.5,
    ),
    "GDPR-Art32": Rule(
        "GDPR-Art32", "Security of Processing",
        "Appropriate technical measures ensuring confidentiality, integrity, "
        "and availability. Covers SSL/TLS, HSTS, cookie security, mixed content, "
        "secrets/credential exposure, CORS, XSS, injection attacks, "
        "missing security headers, insecure forms.",
        weight=2.0,
    ),
    "GDPR-Art33": Rule(
        "GDPR-Art33", "Notification of Personal Data Breach",
        "Breach likely to result in risk must be notified within 72 hours. "
        "Relevant violations: exposed credentials, AWS keys, JWT tokens in JS, "
        "email addresses in JS/storage, high-entropy secrets.",
        weight=1.0,
    ),
    "GDPR-Art35": Rule(
        "GDPR-Art35", "Data Protection Impact Assessment",
        "DPIA required for high-risk processing activities. "
        "Relevant for admin panel exposure, sensitive endpoints in sitemap, "
        "backup file exposure, database admin panel exposure.",
        weight=1.0,
    ),
}

# ── HIPAA ─────────────────────────────────────────────────────────────────────

HIPAA: dict[str, Rule] = {
    "HIPAA-164.306": Rule(
        "HIPAA-164.306", "Security Standards — General Rules",
        "Covered entities must protect against reasonably anticipated threats "
        "or hazards to ePHI security. All vulnerability findings are relevant.",
        weight=2.0,
    ),
    "HIPAA-164.308a": Rule(
        "HIPAA-164.308a", "Administrative Safeguards — Security Management",
        "Implement policies to prevent, detect, contain, and correct security violations. "
        "Covers access control exposure, admin panel, backup/sensitive file exposure, "
        "directory listing, database admin panel exposure.",
        weight=1.5,
    ),
    "HIPAA-164.312a": Rule(
        "HIPAA-164.312a", "Technical Safeguards — Access Control",
        "Technical policies allowing ePHI access only to authorised persons. "
        "Covers IDOR, broken authentication, session cookie security "
        "(HttpOnly/Secure/SameSite), CSRF on auth forms, path traversal.",
        weight=2.0,
    ),
    "HIPAA-164.312b": Rule(
        "HIPAA-164.312b", "Technical Safeguards — Audit Controls",
        "Hardware/software mechanisms to record and examine ePHI system activity. "
        "Violated by stack trace exposure, debug endpoints, server status pages, "
        "sensitive information in HTML comments.",
        weight=1.0,
    ),
    "HIPAA-164.312c": Rule(
        "HIPAA-164.312c", "Technical Safeguards — Integrity Controls",
        "Protect ePHI from improper alteration or destruction. "
        "Covers XSS (DOM manipulation), CSRF attacks, CORS misconfigurations, "
        "mixed content allowing content injection.",
        weight=1.0,
    ),
    "HIPAA-164.312e": Rule(
        "HIPAA-164.312e", "Technical Safeguards — Transmission Security",
        "Guard against unauthorised access to ePHI transmitted over networks. "
        "Covers SSL/TLS version and cipher issues, missing HSTS, "
        "mixed content, insecure WebSocket, insecure SSE.",
        weight=1.5,
    ),
    "HIPAA-164.314": Rule(
        "HIPAA-164.314", "Organisational Requirements",
        "Business associate contracts must include adequate ePHI safeguards. "
        "Relevant for external domain form submission, suspicious external links.",
        weight=0.5,
    ),
}

# ── ISO/IEC 27001:2022 ────────────────────────────────────────────────────────

ISO_27001: dict[str, Rule] = {
    "ISO-A.5.15": Rule(
        "ISO-A.5.15", "Access Control",
        "Rules to control physical and logical access to information. "
        "Covers IDOR, admin panel/database admin exposure, directory listing, "
        "broken access control, path traversal, overly permissive CORS.",
        weight=1.5,
    ),
    "ISO-A.5.17": Rule(
        "ISO-A.5.17", "Authentication Information",
        "Management of authentication information. "
        "Covers cookie attributes (HttpOnly/Secure/SameSite), "
        "low-entropy session tokens, JWT in storage/cookies/JS, "
        "hardcoded credentials, excessive cookie lifetime.",
        weight=1.5,
    ),
    "ISO-A.8.8": Rule(
        "ISO-A.8.8", "Management of Technical Vulnerabilities",
        "Obtain and evaluate technical vulnerability information; "
        "take appropriate measures. All detected vulnerabilities are relevant.",
        weight=2.0,
    ),
    "ISO-A.8.9": Rule(
        "ISO-A.8.9", "Configuration Management",
        "Security configurations of hardware, software, services, and networks "
        "must be established, documented, implemented, and monitored. "
        "Covers security headers, CSP, CORS, cache headers, robots.txt, "
        "sitemap exposure, version disclosure, debug endpoints.",
        weight=1.0,
    ),
    "ISO-A.8.20": Rule(
        "ISO-A.8.20", "Networks Security",
        "Networks and devices must be secured, managed and controlled. "
        "Covers CORS policy, mixed content, insecure WebSocket, "
        "cross-domain policy, suspicious external links.",
        weight=1.0,
    ),
    "ISO-A.8.21": Rule(
        "ISO-A.8.21", "Security of Network Services",
        "Security mechanisms for network services must be identified and monitored. "
        "Covers SSL/TLS configuration, HSTS, cipher suites, "
        "certificate validity and expiry.",
        weight=1.5,
    ),
    "ISO-A.8.23": Rule(
        "ISO-A.8.23", "Web Filtering",
        "Access to external websites managed to reduce malicious content exposure. "
        "Covers suspicious external links, open redirect, SSRF.",
        weight=0.5,
    ),
    "ISO-A.8.24": Rule(
        "ISO-A.8.24", "Use of Cryptography",
        "Rules for effective use of cryptography, including key management. "
        "Covers SSL/TLS, mixed content, weak ciphers, JWT token security, "
        "hardcoded secrets, high-entropy secrets in storage/JS.",
        weight=1.5,
    ),
    "ISO-A.8.25": Rule(
        "ISO-A.8.25", "Secure Development Lifecycle",
        "Security principles applied throughout the development lifecycle. "
        "Covers CMS plugin/theme/version exposure, version disclosure, "
        "backup file exposure, sensitive HTML comments, commented-out code.",
        weight=1.0,
    ),
    "ISO-A.8.28": Rule(
        "ISO-A.8.28", "Secure Coding",
        "Secure coding principles to prevent injection, XSS, CSRF, "
        "path traversal, XXE, SSTI, SSRF, open redirect, IDOR.",
        weight=2.0,
    ),
    "ISO-A.8.29": Rule(
        "ISO-A.8.29", "Security Testing in Development and Acceptance",
        "Security testing processes in the development lifecycle. "
        "All active vulnerability findings are relevant.",
        weight=1.5,
    ),
}

# ── Master registry ───────────────────────────────────────────────────────────

ALL_STANDARDS: dict[str, dict[str, Rule]] = {
    "OWASP Top 10": OWASP_TOP10,
    "PCI-DSS":      PCI_DSS,
    "GDPR":         GDPR,
    "HIPAA":        HIPAA,
    "ISO 27001":    ISO_27001,
}