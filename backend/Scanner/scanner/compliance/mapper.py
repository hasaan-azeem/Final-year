"""
compliance/mapper.py - SIMPLIFIED VERSION

Maps every vulnerability found by WebXGuard to the compliance rules it violates.

Resolution order (first match wins):
  1. category   — the category column (CSRF, SQL Injection, etc.)
  2. title      — keyword scan of the title string (catch-all)
  3. generic    — fallback for anything unrecognised

NO vuln_type column required - uses existing database columns only.
The mapping dict values are {standard_name: [rule_id, ...]}
"""
from __future__ import annotations
from .standard.rules import ALL_STANDARDS, Rule

# ═════════════════════════════════════════════════════════════════════════════
# PRIMARY MAP  (keyed by normalised category string)
# ═════════════════════════════════════════════════════════════════════════════

_M: dict[str, dict[str, list[str]]] = {

    # ── ACTIVE: Injection family ──────────────────────────────────────────────

    "sql_injection": {
        "OWASP Top 10": ["A03:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-6.5.1", "PCI-11.3.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.8", "ISO-A.8.28", "ISO-A.8.29"],
    },
    "command_injection": {
        "OWASP Top 10": ["A03:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-6.5.1", "PCI-11.3.1", "PCI-11.4.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.8", "ISO-A.8.28", "ISO-A.8.29"],
    },
    "xxe": {
        "OWASP Top 10": ["A03:2021", "A05:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-6.5.1", "PCI-11.3.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.8", "ISO-A.8.28", "ISO-A.8.29"],
    },
    "ssti": {
        "OWASP Top 10": ["A03:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-6.5.1", "PCI-11.3.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a"],
        "ISO 27001":    ["ISO-A.8.8", "ISO-A.8.28", "ISO-A.8.29"],
    },

    # ── ACTIVE: XSS ──────────────────────────────────────────────────────────

    "xss": {
        "OWASP Top 10": ["A03:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-6.4.1", "PCI-11.3.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312c"],
        "ISO 27001":    ["ISO-A.8.8", "ISO-A.8.28", "ISO-A.8.29"],
    },

    # ── ACTIVE: CSRF ─────────────────────────────────────────────────────────

    "csrf": {
        "OWASP Top 10": ["A01:2021", "A04:2021", "A07:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-8.2.1", "PCI-11.3.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312c"],
        "ISO 27001":    ["ISO-A.5.15", "ISO-A.8.28", "ISO-A.8.29"],
    },

    # ── ACTIVE: Path traversal ────────────────────────────────────────────────

    "path_traversal": {
        "OWASP Top 10": ["A01:2021", "A05:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-7.2.1", "PCI-11.3.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a"],
        "ISO 27001":    ["ISO-A.5.15", "ISO-A.8.28", "ISO-A.8.29"],
    },

    # ── ACTIVE: SSRF ─────────────────────────────────────────────────────────

    "ssrf": {
        "OWASP Top 10": ["A10:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-11.3.1", "PCI-11.4.1"],
        "GDPR":         ["GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.8", "ISO-A.8.23", "ISO-A.8.28", "ISO-A.8.29"],
    },

    # ── ACTIVE: IDOR ─────────────────────────────────────────────────────────

    "idor": {
        "OWASP Top 10": ["A01:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-7.2.1", "PCI-8.2.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a"],
        "ISO 27001":    ["ISO-A.5.15", "ISO-A.8.28", "ISO-A.8.29"],
    },

    # ── ACTIVE: Open redirect ─────────────────────────────────────────────────

    "open_redirect": {
        "OWASP Top 10": ["A01:2021", "A04:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-11.3.1"],
        "GDPR":         ["GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306"],
        "ISO 27001":    ["ISO-A.8.23", "ISO-A.8.28", "ISO-A.8.29"],
    },

    # ── PASSIVE: Access control ───────────────────────────────────────────────

    "access_control": {
        "OWASP Top 10": ["A01:2021", "A05:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-7.2.1", "PCI-11.3.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32", "GDPR-Art35"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.308a", "HIPAA-164.312a"],
        "ISO 27001":    ["ISO-A.5.15", "ISO-A.8.9", "ISO-A.8.29"],
    },

    # ── PASSIVE: Cache ────────────────────────────────────────────────────────

    "cache": {
        "OWASP Top 10": ["A05:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-4.2.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.9"],
    },

    # ── PASSIVE: CMS ─────────────────────────────────────────────────────────

    "cms": {
        "OWASP Top 10": ["A05:2021", "A06:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.3.3", "PCI-7.2.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.308a"],
        "ISO 27001":    ["ISO-A.8.8", "ISO-A.8.9", "ISO-A.8.25"],
    },

    # ── PASSIVE: Comments ─────────────────────────────────────────────────────

    "comments": {
        "OWASP Top 10": ["A05:2021", "A09:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-8.6.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art25", "GDPR-Art33"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312b"],
        "ISO 27001":    ["ISO-A.8.9", "ISO-A.8.25"],
    },

    # ── PASSIVE: Cookies ─────────────────────────────────────────────────────

    "cookies": {
        "OWASP Top 10": ["A02:2021", "A07:2021"],
        "PCI-DSS":      ["PCI-4.2.1", "PCI-8.2.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.5.17", "ISO-A.8.24"],
    },

    # ── PASSIVE: CORS ────────────────────────────────────────────────────────

    "cors": {
        "OWASP Top 10": ["A05:2021", "A08:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.2.4"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312c", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.9", "ISO-A.8.20"],
    },

    # ── PASSIVE: CSP / security_headers ──────────────────────────────────────

    "csp": {
        "OWASP Top 10": ["A05:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.4.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312c"],
        "ISO 27001":    ["ISO-A.8.9", "ISO-A.8.25"],
    },
    "security_headers": {
        "OWASP Top 10": ["A05:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.4.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312c"],
        "ISO 27001":    ["ISO-A.8.9"],
    },

    # ── PASSIVE: Error / debug disclosure ────────────────────────────────────

    "error_status": {
        "OWASP Top 10": ["A05:2021", "A09:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.3.3"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312b"],
        "ISO 27001":    ["ISO-A.8.9", "ISO-A.8.25"],
    },

    # ── PASSIVE: External links ───────────────────────────────────────────────

    "external_links": {
        "OWASP Top 10": ["A04:2021", "A10:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-11.4.1"],
        "GDPR":         ["GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.314"],
        "ISO 27001":    ["ISO-A.8.20", "ISO-A.8.23"],
    },

    # ── PASSIVE: Forms ────────────────────────────────────────────────────────

    "forms": {
        "OWASP Top 10": ["A02:2021", "A04:2021"],
        "PCI-DSS":      ["PCI-4.2.1", "PCI-6.2.4"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.21", "ISO-A.8.28"],
    },

    # ── PASSIVE: Headers ─────────────────────────────────────────────────────

    "headers": {
        "OWASP Top 10": ["A05:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.4.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.9"],
    },

    # ── PASSIVE: JavaScript ───────────────────────────────────────────────────

    "javascript": {
        "OWASP Top 10": ["A02:2021", "A05:2021", "A09:2021", "A10:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.3.3", "PCI-8.6.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art25", "GDPR-Art33"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312b"],
        "ISO 27001":    ["ISO-A.5.17", "ISO-A.8.24", "ISO-A.8.25"],
    },

    # ── PASSIVE: Mixed content ────────────────────────────────────────────────

    "mixed_content": {
        "OWASP Top 10": ["A02:2021", "A05:2021", "A08:2021"],
        "PCI-DSS":      ["PCI-4.2.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312c", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.20", "ISO-A.8.21", "ISO-A.8.24"],
    },

    # ── PASSIVE: Robots.txt ───────────────────────────────────────────────────

    "robots": {
        "OWASP Top 10": ["A05:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-7.2.1"],
        "GDPR":         ["GDPR-Art25"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.308a"],
        "ISO 27001":    ["ISO-A.8.9"],
    },

    # ── PASSIVE: Secrets ─────────────────────────────────────────────────────

    "secrets": {
        "OWASP Top 10": ["A02:2021", "A05:2021"],
        "PCI-DSS":      ["PCI-6.3.3", "PCI-8.6.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art32", "GDPR-Art33"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312b"],
        "ISO 27001":    ["ISO-A.5.17", "ISO-A.8.24", "ISO-A.8.25"],
    },

    # ── PASSIVE: Sensitive inputs / CSRF token missing ────────────────────────

    "sensitive_inputs": {
        "OWASP Top 10": ["A04:2021", "A07:2021"],
        "PCI-DSS":      ["PCI-6.2.4", "PCI-8.2.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312c"],
        "ISO 27001":    ["ISO-A.5.17", "ISO-A.8.28"],
    },

    # ── PASSIVE: Sitemap ─────────────────────────────────────────────────────

    "sitemap": {
        "OWASP Top 10": ["A01:2021", "A05:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-7.2.1"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art35"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.308a"],
        "ISO 27001":    ["ISO-A.8.9"],
    },

    # ── PASSIVE: SSL/TLS ─────────────────────────────────────────────────────

    "ssl_tls": {
        "OWASP Top 10": ["A02:2021", "A05:2021"],
        "PCI-DSS":      ["PCI-4.2.1", "PCI-6.3.3"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312e"],
        "ISO 27001":    ["ISO-A.8.21", "ISO-A.8.24"],
    },

    # ── PASSIVE: Storage ─────────────────────────────────────────────────────

    "storage": {
        "OWASP Top 10": ["A02:2021", "A07:2021"],
        "PCI-DSS":      ["PCI-4.2.1", "PCI-8.6.1"],
        "GDPR":         ["GDPR-Art5", "GDPR-Art25", "GDPR-Art33"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312a", "HIPAA-164.312b"],
        "ISO 27001":    ["ISO-A.5.17", "ISO-A.8.24"],
    },

    # ── PASSIVE: Versioning ───────────────────────────────────────────────────

    "versioning": {
        "OWASP Top 10": ["A05:2021", "A06:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.3.3"],
        "GDPR":         ["GDPR-Art25"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.308a"],
        "ISO 27001":    ["ISO-A.8.8", "ISO-A.8.9", "ISO-A.8.25"],
    },

    # ── PASSIVE: Information disclosure (generic) ─────────────────────────────

    "information_disclosure": {
        "OWASP Top 10": ["A05:2021", "A09:2021"],
        "PCI-DSS":      ["PCI-2.2.1", "PCI-6.3.3"],
        "GDPR":         ["GDPR-Art25", "GDPR-Art32"],
        "HIPAA":        ["HIPAA-164.306", "HIPAA-164.312b"],
        "ISO 27001":    ["ISO-A.8.9", "ISO-A.8.25"],
    },
}

# ═════════════════════════════════════════════════════════════════════════════
# CATEGORY ALIASES  (exact strings from the `category` DB column)
# ═════════════════════════════════════════════════════════════════════════════

_CATEGORY_ALIASES: dict[str, str] = {
    # Active
    "SQL Injection":                       "sql_injection",
    "XSS":                                 "xss",
    "Cross-Site Scripting":                "xss",
    "CSRF":                                "csrf",
    "Cross-Site Request Forgery":          "csrf",
    "Command Injection":                   "command_injection",
    "OS Command Injection":                "command_injection",
    "RCE":                                 "command_injection",
    "Path Traversal":                      "path_traversal",
    "LFI":                                 "path_traversal",
    "Directory Traversal":                 "path_traversal",
    "XXE":                                 "xxe",
    "XML External Entity":                 "xxe",
    "SSTI":                                "ssti",
    "Server-Side Template Injection":      "ssti",
    "SSRF":                                "ssrf",
    "Server-Side Request Forgery":         "ssrf",
    "IDOR":                                "idor",
    "Insecure Direct Object Reference":    "idor",
    "Broken Access Control":              "idor",
    "Open Redirect":                       "open_redirect",
    # Passive
    "Access Control":                      "access_control",
    "Cache":                               "cache",
    "Cache Control":                       "cache",
    "CMS":                                 "cms",
    "WordPress":                           "cms",
    "Drupal":                              "cms",
    "Joomla":                              "cms",
    "Comments":                            "comments",
    "HTML Comments":                       "comments",
    "Information Disclosure":              "information_disclosure",
    "Cookies":                             "cookies",
    "Cookie":                              "cookies",
    "Cookie Security":                     "cookies",
    "CORS":                                "cors",
    "CSP":                                 "csp",
    "Content Security Policy":             "csp",
    "Security Headers":                    "security_headers",
    "Headers":                             "headers",
    "HTTP Headers":                        "headers",
    "Error":                               "error_status",
    "Error Disclosure":                    "error_status",
    "Debug Information":                   "error_status",
    "External Links":                      "external_links",
    "Forms":                               "forms",
    "Insecure Form":                       "forms",
    "JavaScript":                          "javascript",
    "JS":                                  "javascript",
    "Mixed Content":                       "mixed_content",
    "Robots":                              "robots",
    "Robots.txt":                          "robots",
    "Secrets":                             "secrets",
    "Secret Exposure":                     "secrets",
    "Sensitive Inputs":                    "sensitive_inputs",
    "Sitemap":                             "sitemap",
    "SSL":                                 "ssl_tls",
    "SSL/TLS":                             "ssl_tls",
    "TLS":                                 "ssl_tls",
    "Certificate":                         "ssl_tls",
    "Storage":                             "storage",
    "Client Storage":                      "storage",
    "Versioning":                          "versioning",
    "Version Disclosure":                  "versioning",
}

# ═════════════════════════════════════════════════════════════════════════════
# TITLE KEYWORD MAP  (substring match on the title column, in priority order)
# ═════════════════════════════════════════════════════════════════════════════

_TITLE_KEYWORDS: list[tuple[str, str]] = [
    # Active
    ("sql injection",                  "sql_injection"),
    ("union-based",                    "sql_injection"),
    ("boolean-based",                  "sql_injection"),
    ("time-based",                     "sql_injection"),
    ("command injection",              "command_injection"),
    ("os command",                     "command_injection"),
    ("remote code execution",          "command_injection"),
    ("path traversal",                 "path_traversal"),
    ("local file inclusion",           "path_traversal"),
    ("directory traversal",            "path_traversal"),
    ("xml external entity",            "xxe"),
    ("xxe",                            "xxe"),
    ("server-side template injection", "ssti"),
    ("ssti",                           "ssti"),
    ("server-side request forgery",    "ssrf"),
    ("ssrf",                           "ssrf"),
    ("insecure direct object",         "idor"),
    ("idor",                           "idor"),
    ("cross-site scripting",           "xss"),
    ("reflected xss",                  "xss"),
    ("stored xss",                     "xss"),
    ("dom xss",                        "xss"),
    ("xss",                            "xss"),
    ("cross-site request forgery",     "csrf"),
    ("csrf",                           "csrf"),
    ("anti-csrf",                      "csrf"),
    ("missing csrf token",             "csrf"),
    ("open redirect",                  "open_redirect"),
    ("external redirect",              "open_redirect"),
    # Passive — access control
    ("administrative interface",       "access_control"),
    ("admin panel",                    "access_control"),
    ("admin interface",                "access_control"),
    ("database admin",                 "access_control"),
    ("phpmyadmin",                     "access_control"),
    ("spring boot actuator",           "access_control"),
    ("api documentation",              "access_control"),
    ("swagger",                        "access_control"),
    ("directory listing",              "access_control"),
    ("backup file",                    "access_control"),
    ("git repository",                 "access_control"),
    ("svn repository",                 "access_control"),
    ("sensitive file",                 "access_control"),
    ("php info",                       "access_control"),
    ("phpinfo",                        "access_control"),
    ("server status",                  "access_control"),
    ("cross-domain policy",            "access_control"),
    ("crossdomain.xml",                "access_control"),
    # Passive — cache
    ("cache-control",                  "cache"),
    ("cache control",                  "cache"),
    ("cacheable",                      "cache"),
    ("cached",                         "cache"),
    ("surrogate-control",              "cache"),
    ("cdn cache",                      "cache"),
    ("etag",                           "cache"),
    ("pragma",                         "cache"),
    ("vary header",                    "cache"),
    ("immutable",                      "cache"),
    # Passive — CMS
    ("wordpress",                      "cms"),
    ("wp-",                            "cms"),
    ("drupal",                         "cms"),
    ("joomla",                         "cms"),
    ("shopify",                        "cms"),
    ("xml-rpc",                        "cms"),
    ("cms version",                    "cms"),
    ("cms plugin",                     "cms"),
    # Passive — comments
    ("html comment",                   "comments"),
    ("developer comment",              "comments"),
    ("commented-out",                  "comments"),
    ("internal ip",                    "comments"),
    ("credential pattern",             "comments"),
    ("hidden endpoint",                "comments"),
    # Passive — cookies
    ("secure attribute",               "cookies"),
    ("httponly",                       "cookies"),
    ("samesite",                       "cookies"),
    ("session cookie",                 "cookies"),
    ("cookie lifetime",                "cookies"),
    ("jwt stored in",                  "cookies"),
    ("cookie entropy",                 "cookies"),
    ("cookie scoped",                  "cookies"),
    # Passive — CORS
    ("cors",                           "cors"),
    ("access-control-allow-origin",    "cors"),
    ("wildcard origin",                "cors"),
    ("null origin",                    "cors"),
    ("reflected origin",               "cors"),
    # Passive — CSP / headers
    ("content-security-policy",        "csp"),
    ("content security policy",        "csp"),
    ("csp",                            "csp"),
    ("strict-transport-security",      "headers"),
    ("hsts",                           "headers"),
    ("x-content-type",                 "headers"),
    ("x-frame-options",                "headers"),
    ("referrer-policy",                "headers"),
    ("permissions-policy",             "headers"),
    ("cross-origin-resource-policy",   "headers"),
    ("cross-origin-embedder-policy",   "headers"),
    ("cross-origin-opener-policy",     "headers"),
    ("clickjacking",                   "headers"),
    # Passive — error / debug
    ("stack trace",                    "error_status"),
    ("debug info",                     "error_status"),
    ("server version disclosure",      "versioning"),
    ("error page",                     "error_status"),
    # Passive — external links
    ("suspicious domain",              "external_links"),
    ("link to suspicious",             "external_links"),
    # Passive — forms
    ("password form",                  "forms"),
    ("form submits",                   "forms"),
    ("form over http",                 "forms"),
    # Passive — JS
    ("javascript",                     "javascript"),
    ("aws access key",                 "javascript"),
    ("hardcoded secret",               "javascript"),
    ("internal url",                   "javascript"),
    ("jwt token found in javascript",  "javascript"),
    ("debug function",                 "javascript"),
    # Passive — mixed content
    ("mixed content",                  "mixed_content"),
    ("http resource on https",         "mixed_content"),
    ("insecure websocket",             "mixed_content"),
    ("insecure server-sent",           "mixed_content"),
    ("serviceworker",                  "mixed_content"),
    ("insecure media",                 "mixed_content"),
    ("insecure web font",              "mixed_content"),
    # Passive — robots
    ("robots.txt",                     "robots"),
    ("disallow directive",             "robots"),
    # Passive — secrets
    ("high-entropy",                   "secrets"),
    ("secret",                         "secrets"),
    ("api key",                        "secrets"),
    ("token exposure",                 "secrets"),
    ("base64 high-entropy",            "secrets"),
    # Passive — sensitive inputs (CSRF token)
    ("post form missing csrf",         "sensitive_inputs"),
    ("missing csrf",                   "sensitive_inputs"),
    # Passive — sitemap
    ("sitemap",                        "sitemap"),
    ("sensitive endpoint listed",      "sitemap"),
    # Passive — SSL/TLS
    ("ssl certificate",                "ssl_tls"),
    ("tls version",                    "ssl_tls"),
    ("cipher suite",                   "ssl_tls"),
    ("forward secrecy",                "ssl_tls"),
    ("https redirect",                 "ssl_tls"),
    ("self-signed",                    "ssl_tls"),
    ("certificate expir",              "ssl_tls"),
    ("weak tls",                       "ssl_tls"),
    # Passive — storage
    ("jwt token in client storage",    "storage"),
    ("secret in storage",              "storage"),
    ("email in storage",               "storage"),
    ("high entropy storage",           "storage"),
    # Passive — versioning
    ("version disclosure",             "versioning"),
    ("generator meta tag",             "versioning"),
    ("library version",                "versioning"),
    ("version query parameter",        "versioning"),
    ("version info in html",           "versioning"),
]

# ═════════════════════════════════════════════════════════════════════════════
# GENERIC FALLBACK
# ═════════════════════════════════════════════════════════════════════════════

_GENERIC: dict[str, list[str]] = {
    "OWASP Top 10": ["A05:2021"],
    "PCI-DSS":      ["PCI-2.2.1", "PCI-11.3.1"],
    "GDPR":         ["GDPR-Art32"],
    "HIPAA":        ["HIPAA-164.306"],
    "ISO 27001":    ["ISO-A.8.8"],
}


# ═════════════════════════════════════════════════════════════════════════════
# RESOLUTION FUNCTION (SIMPLIFIED - NO vuln_type)
# ═════════════════════════════════════════════════════════════════════════════

def _resolve_key(
    category: str,
    title: str,
) -> str:
    """Return the canonical map key for a vulnerability row.
    
    Resolution order:
    1. Category alias lookup
    2. Title keyword scan
    3. Empty string (generic fallback)
    """
    # 1. Category alias
    if category:
        alias = _CATEGORY_ALIASES.get(category.strip())
        if alias and alias in _M:
            return alias
        # Direct category key
        k = category.lower().strip()
        if k in _M:
            return k

    # 2. Title keyword scan
    if title:
        lower_title = title.lower()
        for keyword, key in _TITLE_KEYWORDS:
            if keyword in lower_title:
                return key

    return ""   # caller will use generic fallback


def get_violated_rules(
    category: str,
    title: str,
    active_standards: list[str] | None = None,
) -> dict[str, list[Rule]]:
    """
    Return {standard_name: [Rule, ...]} for every rule violated.

    Args:
        category:         vulnerabilities.category (e.g., "CSRF", "SQL Injection")
        title:            vulnerabilities.title (used for keyword fallback)
        active_standards: if given, filter to only these standards

    Returns:
        Dict mapping standard name → list of Rule objects violated.
    """
    standards = active_standards or list(ALL_STANDARDS.keys())

    key = _resolve_key(category or "", title or "")
    mapping = _M.get(key, _GENERIC)

    result: dict[str, list[Rule]] = {}
    for std in standards:
        rule_ids = mapping.get(std, [])
        std_rules = ALL_STANDARDS.get(std, {})
        rules = [std_rules[rid] for rid in rule_ids if rid in std_rules]
        if rules:
            result[std] = rules

    return result