"""
backend/Scanner/scanner/ai_remediation/knowledge_base.py
========================================================
Static remediation database for common web vulnerabilities.

Purpose
-------
* Layer 1 (this file) — instant lookup, 0 cost, no API call
* Layer 2 (ai_client.py) — LLM fallback when KB miss

KB covers ~25 most common findings (SQLi, XSS, CSRF, SSRF, XXE, IDOR,
command injection, open redirect, missing security headers, weak SSL/TLS,
insecure cookies, etc.) which represent ~80% of real scan findings.

Lookup is by category (case-insensitive substring match against vuln_category
or title). On miss, caller falls back to LLM.
"""
from __future__ import annotations
from typing import Optional


# Each entry maps to the JSON payload that ai_client.py / API returns.
# Keep `fix_steps` 3-6 items, actionable, no fluff. Keep `code_example` minimal
# (one secure pattern only). `references` should be authoritative (OWASP, MITRE).

KNOWLEDGE_BASE: dict[str, dict] = {
    # ──────────────────────────────────────────────────────────────────────
    # INJECTION
    # ──────────────────────────────────────────────────────────────────────
    "sql_injection": {
        "summary": (
            "SQL injection allows an attacker to execute arbitrary SQL on the "
            "database server, potentially exposing or destroying data."
        ),
        "fix_steps": [
            "Use parameterized queries / prepared statements for every dynamic SQL.",
            "Never concatenate user input into SQL strings, even after sanitization.",
            "Use a well-tested ORM (SQLAlchemy, Sequelize, Django ORM) where possible.",
            "Apply least-privilege at the DB level — the app user should not have DROP, ALTER, or admin rights.",
            "Validate input format (length, charset) on top of parameterization, never instead of it.",
            "Enable detailed query logging in dev to catch unsafe patterns early.",
        ],
        "code_example": (
            "# Python (psycopg2) - SAFE\n"
            "cur.execute(\n"
            "    \"SELECT * FROM users WHERE email = %s AND active = %s\",\n"
            "    (email, True),  # parameters tuple — driver handles escaping\n"
            ")\n\n"
            "# UNSAFE — DO NOT DO THIS\n"
            "# cur.execute(f\"SELECT * FROM users WHERE email = '{email}'\")"
        ),
        "references": [
            {"title": "OWASP SQL Injection Prevention Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"},
            {"title": "CWE-89: SQL Injection",
             "url": "https://cwe.mitre.org/data/definitions/89.html"},
        ],
    },

    "xss": {
        "summary": (
            "Cross-site scripting (XSS) lets attackers inject browser-side "
            "JavaScript into pages other users see, enabling session theft, "
            "defacement, and phishing."
        ),
        "fix_steps": [
            "Output-encode user data based on context: HTML body, attribute, JS, CSS, URL all need different encoders.",
            "Use a templating engine that auto-escapes by default (Jinja2, React JSX, Vue templates).",
            "Set Content-Security-Policy header (start with `default-src 'self'`) to block inline scripts.",
            "Set HttpOnly + Secure + SameSite=Strict on session cookies — limits damage if XSS lands.",
            "Sanitize rich-text user input with DOMPurify (frontend) or Bleach (Python) — strict whitelist.",
            "Avoid `innerHTML`, `document.write`, `eval`, `dangerouslySetInnerHTML` unless explicitly sanitized.",
        ],
        "code_example": (
            "// React — SAFE (auto-escapes)\n"
            "<div>{userComment}</div>\n\n"
            "// Sanitize rich HTML before rendering\n"
            "import DOMPurify from 'dompurify';\n"
            "<div dangerouslySetInnerHTML={{\n"
            "  __html: DOMPurify.sanitize(userComment)\n"
            "}} />"
        ),
        "references": [
            {"title": "OWASP XSS Prevention Cheat Sheet",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"},
            {"title": "CWE-79: Cross-site Scripting",
             "url": "https://cwe.mitre.org/data/definitions/79.html"},
        ],
    },

    "command_injection": {
        "summary": (
            "Command injection allows arbitrary OS commands to be executed by "
            "the application, often via shell metacharacters in user input."
        ),
        "fix_steps": [
            "Avoid invoking the shell with user input — use language APIs (e.g. `subprocess.run([...], shell=False)`).",
            "Pass arguments as a list, never as a single concatenated string.",
            "Validate input against a strict whitelist (e.g. only filename characters).",
            "Apply the principle of least privilege — run the app as a non-root user with no sudo rights.",
            "If shell is unavoidable, use `shlex.quote()` to escape — but prefer no-shell APIs.",
        ],
        "code_example": (
            "# SAFE\n"
            "import subprocess\n"
            "subprocess.run(\n"
            "    [\"ls\", \"-la\", user_dir],   # list form\n"
            "    shell=False,\n"
            "    check=True,\n"
            ")\n\n"
            "# UNSAFE\n"
            "# os.system(f\"ls -la {user_dir}\")"
        ),
        "references": [
            {"title": "OWASP Command Injection",
             "url": "https://owasp.org/www-community/attacks/Command_Injection"},
            {"title": "CWE-78",
             "url": "https://cwe.mitre.org/data/definitions/78.html"},
        ],
    },

    "ssti": {
        "summary": (
            "Server-side template injection occurs when user input is rendered "
            "as part of a template, enabling code execution on the server."
        ),
        "fix_steps": [
            "Never pass user-controlled strings as the template itself — only as variables.",
            "Use sandboxed template environments (Jinja2 SandboxedEnvironment) for any user-authored templates.",
            "Disable dangerous template filters/globals if you must allow user templates.",
            "Run the template engine as the lowest-privilege process possible.",
            "Audit all template rendering paths during code review — `render_template_string` with user data is a red flag.",
        ],
        "code_example": (
            "# Flask — SAFE\n"
            "return render_template(\"profile.html\", name=user.name)\n\n"
            "# UNSAFE\n"
            "# return render_template_string(f\"Hello {user.name}\")"
        ),
        "references": [
            {"title": "PortSwigger SSTI",
             "url": "https://portswigger.net/web-security/server-side-template-injection"},
        ],
    },

    "xxe": {
        "summary": (
            "XML external entity injection lets attackers read server files, "
            "make blind SSRF requests, or trigger DoS via malicious XML."
        ),
        "fix_steps": [
            "Disable DTD processing and external entity resolution in your XML parser.",
            "Prefer simpler formats — JSON or Protocol Buffers — when possible.",
            "Use defusedxml (Python) or equivalent hardened parsers in other languages.",
            "Validate file uploads against an XML schema; reject anything with a DOCTYPE.",
            "Patch parser libraries promptly — XXE flaws are still discovered yearly.",
        ],
        "code_example": (
            "# Python — SAFE\n"
            "from defusedxml.ElementTree import fromstring\n"
            "tree = fromstring(xml_blob)\n\n"
            "# UNSAFE\n"
            "# from xml.etree.ElementTree import fromstring  # allows entities"
        ),
        "references": [
            {"title": "OWASP XXE Prevention",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html"},
        ],
    },

    "ssrf": {
        "summary": (
            "Server-side request forgery lets an attacker pivot through your "
            "server to reach internal services, cloud metadata endpoints, "
            "or other private networks."
        ),
        "fix_steps": [
            "Maintain an allow-list of permitted external hosts; reject everything else.",
            "Block requests to private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.169.254 cloud metadata).",
            "Resolve the hostname yourself, then make the request to the resolved IP — prevents DNS rebinding.",
            "Disable HTTP redirects on outbound requests, or re-validate the redirect target against the allow-list.",
            "Use a separate, network-restricted egress proxy for any user-driven URL fetching.",
        ],
        "code_example": (
            "# Python — guard before fetching\n"
            "import ipaddress, socket\n"
            "def is_safe_target(host: str) -> bool:\n"
            "    ip = ipaddress.ip_address(socket.gethostbyname(host))\n"
            "    return not (ip.is_private or ip.is_loopback or ip.is_link_local)\n"
        ),
        "references": [
            {"title": "OWASP SSRF Prevention",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html"},
        ],
    },

    "path_traversal": {
        "summary": (
            "Path traversal lets attackers escape an intended directory and "
            "read or write arbitrary files on the server (e.g. /etc/passwd, "
            "config files with secrets)."
        ),
        "fix_steps": [
            "Reject input containing `..`, `\\`, `/`, or null bytes outright.",
            "Resolve the user-supplied path with `os.path.realpath` and verify it starts with the safe base directory.",
            "Use a whitelist of allowed filenames or IDs that map to file paths internally.",
            "Run the app with file-system permissions limited to only the directories it needs.",
            "Never serve user uploads from the same directory as application code.",
        ],
        "code_example": (
            "import os\n"
            "BASE = \"/var/app/uploads\"\n"
            "def safe_open(name: str):\n"
            "    full = os.path.realpath(os.path.join(BASE, name))\n"
            "    if not full.startswith(BASE + os.sep):\n"
            "        raise ValueError(\"path traversal blocked\")\n"
            "    return open(full, \"rb\")"
        ),
        "references": [
            {"title": "CWE-22",
             "url": "https://cwe.mitre.org/data/definitions/22.html"},
        ],
    },

    "open_redirect": {
        "summary": (
            "Open redirect lets attackers craft links on your domain that "
            "transparently send users to attacker-controlled sites — used "
            "in phishing campaigns to bypass email filters."
        ),
        "fix_steps": [
            "Avoid taking redirect URLs from user input. Use internal IDs/codes that map to known destinations.",
            "If user-supplied is unavoidable, validate against a strict allow-list of trusted hosts.",
            "Reject absolute URLs entirely if redirects should always stay on-site.",
            "Show an interstitial page warning the user when redirecting off-site.",
            "Encode/sanitize the URL before placing it in a Location header.",
        ],
        "code_example": (
            "from urllib.parse import urlparse\n"
            "def safe_redirect_target(target: str, default: str = \"/\"):\n"
            "    p = urlparse(target)\n"
            "    if p.netloc and p.netloc != \"yourdomain.com\":\n"
            "        return default\n"
            "    return target"
        ),
        "references": [
            {"title": "CWE-601",
             "url": "https://cwe.mitre.org/data/definitions/601.html"},
        ],
    },

    "csrf": {
        "summary": (
            "CSRF tricks an authenticated user's browser into submitting "
            "unwanted state-changing requests (transfers, password changes, "
            "etc.) to your site."
        ),
        "fix_steps": [
            "Use anti-CSRF tokens — random, per-session, validated on every state-changing request.",
            "Set session cookies to SameSite=Lax (default-safe) or SameSite=Strict.",
            "Require explicit re-authentication for sensitive actions (password change, payment).",
            "Use the framework's built-in CSRF protection (Django, Flask-WTF, Spring Security) — don't roll your own.",
            "For SPAs, use the double-submit cookie pattern or custom request header.",
        ],
        "code_example": (
            "# Flask — Flask-WTF auto-issues CSRF tokens\n"
            "from flask_wtf.csrf import CSRFProtect\n"
            "csrf = CSRFProtect(app)"
        ),
        "references": [
            {"title": "OWASP CSRF Prevention",
             "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"},
        ],
    },

    "idor": {
        "summary": (
            "Insecure Direct Object Reference exposes records by manipulating "
            "an ID/key in the URL or request body, without the app verifying "
            "ownership — e.g. `/api/orders/999` returns someone else's order."
        ),
        "fix_steps": [
            "On every record fetch, verify the resource belongs to the authenticated user (or that user has explicit permission).",
            "Use unguessable IDs (UUIDs, ULIDs) in addition to authorization — defense in depth.",
            "Implement a centralized authorization layer (decorator/middleware) so every endpoint runs the check.",
            "Log and alert on any 403 spike — sign of someone enumerating IDs.",
            "Audit endpoints for the pattern `Order.get(id)` followed by no user-id check.",
        ],
        "code_example": (
            "# Always join on user_id\n"
            "order = await fetchrow(\n"
            "    \"SELECT * FROM orders WHERE id = $1 AND user_id = $2\",\n"
            "    order_id, current_user_id,\n"
            ")\n"
            "if not order: raise HTTPException(404)"
        ),
        "references": [
            {"title": "OWASP Top 10 — Broken Access Control",
             "url": "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"},
        ],
    },

    # ──────────────────────────────────────────────────────────────────────
    # MISCONFIGURATIONS / HEADERS / TLS
    # ──────────────────────────────────────────────────────────────────────
    "missing_security_headers": {
        "summary": (
            "Critical security response headers are missing, leaving the app "
            "vulnerable to clickjacking, MIME sniffing, and protocol downgrade."
        ),
        "fix_steps": [
            "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` (force HTTPS for 1 year).",
            "Add `X-Content-Type-Options: nosniff` (prevent MIME-type sniffing).",
            "Add `X-Frame-Options: DENY` or use CSP `frame-ancestors 'none'` (anti-clickjacking).",
            "Add `Referrer-Policy: strict-origin-when-cross-origin`.",
            "Add `Content-Security-Policy` — start with `default-src 'self'` and tighten per page.",
            "Set headers at the reverse-proxy (nginx/Caddy) level for consistency across all endpoints.",
        ],
        "code_example": (
            "# nginx\n"
            "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;\n"
            "add_header X-Content-Type-Options nosniff always;\n"
            "add_header X-Frame-Options DENY always;\n"
            "add_header Content-Security-Policy \"default-src 'self'\" always;"
        ),
        "references": [
            {"title": "OWASP Secure Headers Project",
             "url": "https://owasp.org/www-project-secure-headers/"},
        ],
    },

    "insecure_cookies": {
        "summary": (
            "Cookies are missing one or more of Secure, HttpOnly, or SameSite "
            "flags, making them susceptible to network sniffing, XSS theft, "
            "or CSRF."
        ),
        "fix_steps": [
            "Set `Secure` flag — cookie only sent over HTTPS.",
            "Set `HttpOnly` flag — cookie not accessible to JavaScript (mitigates XSS theft).",
            "Set `SameSite=Lax` (default-safe) or `Strict` for session cookies.",
            "Use short cookie lifetimes for sensitive sessions; rotate on privilege change.",
            "Sign and/or encrypt cookie payloads — never trust client-side data.",
        ],
        "code_example": (
            "# Flask\n"
            "app.config.update(\n"
            "    SESSION_COOKIE_SECURE=True,\n"
            "    SESSION_COOKIE_HTTPONLY=True,\n"
            "    SESSION_COOKIE_SAMESITE=\"Lax\",\n"
            ")"
        ),
        "references": [
            {"title": "MDN — Secure Cookies",
             "url": "https://developer.mozilla.org/docs/Web/HTTP/Cookies"},
        ],
    },

    "weak_tls": {
        "summary": (
            "Server supports outdated TLS versions or weak cipher suites — "
            "downgrade attacks, weak encryption, or certificate trust issues."
        ),
        "fix_steps": [
            "Disable TLS 1.0 and 1.1; allow only TLS 1.2 and 1.3.",
            "Disable weak ciphers (RC4, 3DES, NULL, EXPORT). Use a modern cipher suite list.",
            "Enable HSTS to prevent downgrade attacks.",
            "Use Mozilla's SSL Configuration Generator for your server type.",
            "Renew certificates before expiry; automate with Let's Encrypt + Certbot.",
            "Test with SSL Labs (ssllabs.com/ssltest) — aim for grade A or A+.",
        ],
        "code_example": None,
        "references": [
            {"title": "Mozilla SSL Config Generator",
             "url": "https://ssl-config.mozilla.org/"},
            {"title": "SSL Labs Test",
             "url": "https://www.ssllabs.com/ssltest/"},
        ],
    },

    "directory_listing": {
        "summary": (
            "The server returns directory contents when no index file is "
            "present, exposing file names, backup files, and source code."
        ),
        "fix_steps": [
            "Disable directory autoindex on the web server.",
            "Place an index.html (or a 403 page) in every served directory.",
            "Move all non-public files outside the document root.",
            "Configure the server to deny access to dot-files and backup extensions (`.bak`, `~`, `.swp`).",
        ],
        "code_example": (
            "# nginx — explicitly off\n"
            "autoindex off;\n\n"
            "# Apache\n"
            "Options -Indexes"
        ),
        "references": [
            {"title": "CWE-548",
             "url": "https://cwe.mitre.org/data/definitions/548.html"},
        ],
    },

    "exposed_secrets_in_js": {
        "summary": (
            "JavaScript bundles or HTML source contain API keys, tokens, or "
            "internal URLs that should not be public."
        ),
        "fix_steps": [
            "Move all secrets to backend environment variables — never ship to frontend.",
            "Rotate any leaked credentials immediately, then revoke the old ones.",
            "Use a build-time scanner (gitleaks, trufflehog) to catch secrets before deploy.",
            "Use OAuth/PKCE flow on frontend — exchange short-lived codes for tokens server-side.",
            "If the API key MUST be on the frontend, scope it to specific origins/operations and monitor usage.",
        ],
        "code_example": None,
        "references": [
            {"title": "gitleaks", "url": "https://github.com/gitleaks/gitleaks"},
        ],
    },

    "outdated_dependency": {
        "summary": (
            "A library version with known CVEs is in use. Attackers often "
            "scan for these — exploitation is fast once a CVE is published."
        ),
        "fix_steps": [
            "Run `npm audit fix` / `pip-audit` / `pip install --upgrade <pkg>` to bump to the patched version.",
            "Add Dependabot (GitHub) or Renovate to auto-PR security updates.",
            "Lock dependencies (package-lock.json, poetry.lock) so all environments use the same versions.",
            "Subscribe to security advisories for your major frameworks.",
            "Schedule a quarterly dependency review even if no CVEs are open.",
        ],
        "code_example": None,
        "references": [
            {"title": "GitHub Advisories",
             "url": "https://github.com/advisories"},
        ],
    },

    "missing_csp": {
        "summary": (
            "No Content-Security-Policy header — biggest defense layer against "
            "XSS is missing."
        ),
        "fix_steps": [
            "Start with a strict policy: `default-src 'self'; script-src 'self'`.",
            "Add explicit hosts for each external resource you legitimately load (CDNs, analytics).",
            "Avoid `'unsafe-inline'` and `'unsafe-eval'` — use nonces or hashes if you need inline scripts.",
            "Use `report-uri` (or `report-to`) to collect CSP violations during rollout.",
            "Tighten progressively — deploy in `Content-Security-Policy-Report-Only` first.",
        ],
        "code_example": (
            "Content-Security-Policy: default-src 'self'; "
            "script-src 'self' https://cdn.example.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "frame-ancestors 'none'"
        ),
        "references": [
            {"title": "MDN CSP",
             "url": "https://developer.mozilla.org/docs/Web/HTTP/CSP"},
        ],
    },
}


# Aliases — many scanners label the same vuln differently. Map all known
# spellings to the canonical KB key.
ALIASES: dict[str, str] = {
    # SQL injection
    "sql injection": "sql_injection",
    "sqli": "sql_injection",
    "blind sql injection": "sql_injection",
    "error-based sql injection": "sql_injection",

    # XSS
    "cross-site scripting": "xss",
    "cross site scripting": "xss",
    "reflected xss": "xss",
    "stored xss": "xss",
    "dom-based xss": "xss",
    "dom xss": "xss",

    # Command
    "os command injection": "command_injection",
    "shell injection": "command_injection",
    "rce": "command_injection",
    "remote code execution": "command_injection",

    # SSTI
    "server-side template injection": "ssti",

    # XXE
    "xml external entities": "xxe",
    "xml injection": "xxe",

    # SSRF
    "server-side request forgery": "ssrf",
    "blind ssrf": "ssrf",

    # Path traversal
    "directory traversal": "path_traversal",
    "lfi": "path_traversal",
    "local file inclusion": "path_traversal",

    # CSRF
    "cross-site request forgery": "csrf",
    "anti-csrf token missing": "csrf",
    "csrf token missing": "csrf",

    # Open redirect
    "url redirection": "open_redirect",
    "unvalidated redirect": "open_redirect",

    # IDOR
    "broken access control": "idor",
    "insecure direct object reference": "idor",
    "missing authorization": "idor",

    # Headers
    "x-frame-options missing": "missing_security_headers",
    "x-content-type-options missing": "missing_security_headers",
    "missing strict-transport-security": "missing_security_headers",
    "missing referrer-policy": "missing_security_headers",
    "hsts missing": "missing_security_headers",
    "clickjacking": "missing_security_headers",

    # Cookies
    "cookie without secure flag": "insecure_cookies",
    "cookie without httponly flag": "insecure_cookies",
    "cookie without samesite": "insecure_cookies",
    "session cookie not secure": "insecure_cookies",

    # TLS
    "ssl/tls": "weak_tls",
    "weak ssl": "weak_tls",
    "tls 1.0 enabled": "weak_tls",
    "ssl certificate": "weak_tls",

    # Misc
    "directory indexing enabled": "directory_listing",
    "directory listing": "directory_listing",
    "secrets in javascript": "exposed_secrets_in_js",
    "exposed api key": "exposed_secrets_in_js",
    "outdated library": "outdated_dependency",
    "vulnerable component": "outdated_dependency",
    "known vulnerability": "outdated_dependency",
    "content security policy missing": "missing_csp",
    "content-security-policy not set": "missing_csp",
    "csp not set": "missing_csp",
}


def lookup_kb(category: str | None, title: str | None) -> Optional[dict]:
    """
    Try to find a remediation entry in the static KB.
    Match against category first, then title. Returns None on miss.
    """
    haystacks = []
    if category:
        haystacks.append(category.strip().lower())
    if title:
        haystacks.append(title.strip().lower())

    for hay in haystacks:
        # Direct key match
        if hay in KNOWLEDGE_BASE:
            return _decorate(KNOWLEDGE_BASE[hay], hay)
        # Alias match (exact or substring)
        for alias, canonical in ALIASES.items():
            if alias in hay:
                return _decorate(KNOWLEDGE_BASE[canonical], canonical)
        # Last resort: substring match against canonical keys
        for key in KNOWLEDGE_BASE:
            if key.replace("_", " ") in hay:
                return _decorate(KNOWLEDGE_BASE[key], key)

    return None


def _decorate(entry: dict, kb_key: str) -> dict:
    """Tag a KB entry with provenance metadata so callers know it's static."""
    out = dict(entry)
    out["source"] = "static"
    out["model"] = f"kb:{kb_key}"
    return out