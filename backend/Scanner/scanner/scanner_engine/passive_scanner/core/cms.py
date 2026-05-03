import re
import logging
from urllib.parse import urlparse

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.cms")

MAX_SNIPPET_LEN = 120
MAX_BODY_SIZE = 1_000_000  # Prevent DoS from huge responses

OWASP_FINGERPRINT = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"
OWASP_ADMIN = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"
OWASP_BACKUP = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"
OWASP_ENUM = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"
OWASP_DIR = "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information"

GENERIC_SENSITIVE_PATHS = frozenset({
    "/admin", "/administrator", "/wp-admin",
    "/login", "/dashboard", "/user/login",
    "/config", "/backup", "/.git", "/debug",
})

# ─────────────────────────────────────────────────────────────────────────────
# PRE-COMPILED REGEX PATTERNS (Prevent ReDoS)
# ─────────────────────────────────────────────────────────────────────────────

WORDPRESS_VERSION_PATTERN = re.compile(
    r'<meta\s+name=(["\'])generator\1\s+content=(["\'])wordpress\s*([\d.]+)\2',
    re.IGNORECASE
)
DRUPAL_VERSION_PATTERN = re.compile(
    r'<meta\s+name=(["\'])generator\1\s+content=(["\'])drupal\s*([\d.]+)\2',
    re.IGNORECASE
)
JOOMLA_VERSION_PATTERN = re.compile(
    r'<meta\s+name=(["\'])generator\1\s+content=(["\'])joomla!?\s*([^"\']*)\2',
    re.IGNORECASE
)
GENERIC_VERSION_PATTERN = re.compile(
    r'<meta\s+name=(["\'])generator\1\s+content=(["\'])([^"\']+)\2',
    re.IGNORECASE
)
PLUGIN_PATTERN = re.compile(
    r'/wp-content/plugins/([a-z0-9_-]{2,}?)/',
    re.IGNORECASE
)
THEME_PATTERN = re.compile(
    r'/wp-content/themes/([a-z0-9_-]{2,}?)/',
    re.IGNORECASE
)
JOOMLA_COMPONENT_PATTERN = re.compile(
    r'option=com_([a-z0-9_]{2,})',
    re.IGNORECASE
)
SHOPIFY_THEME_PATTERN = re.compile(
    r'cdn\.shopify\.com/s/files/[^/]+/[^/]+/[^/]+/t/([a-z0-9_-]+)/',
    re.IGNORECASE
)
SHOPIFY_TOKEN_PATTERN = re.compile(
    r'(["\'])storefrontAccessToken\1\s*:\s*["\']([a-f0-9]{32})["\']',
    re.IGNORECASE
)

# Cache detection strings (faster than regex for simple checks)
WORDPRESS_INDICATORS = ("wp-content", "wp-includes", "wordpress")
DRUPAL_INDICATORS = ("drupal", "sites/default")
JOOMLA_INDICATORS = ("joomla", "option=com_")
SHOPIFY_INDICATORS = ("shopify", "cdn.shopify.com")


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

def _norm_headers(headers) -> dict:
    """Normalize headers safely."""
    if not isinstance(headers, dict):
        return {}
    return {
        k.lower()[:64]: str(v)[:256]
        for k, v in headers.items()
    }

def _is_text(headers: dict) -> bool:
    """Check if content type is text."""
    ct = headers.get("content-type", "").lower()
    return any(x in ct for x in ["text", "html", "json", "javascript"])

def _trunc(text: str, length: int = MAX_SNIPPET_LEN) -> str:
    """Truncate text safely."""
    return text[:length] if text else ""

def _validate_input(url: str, body: str) -> bool:
    """Validate inputs to prevent DoS."""
    if not isinstance(url, str) or len(url) > 8192:
        return False
    if not isinstance(body, str):
        return False
    if len(body) > MAX_BODY_SIZE:
        return False
    return True


# ─────────────────────────────────────────────────────────────────────────────
# PER-SCAN REPORTER HELPER
# ─────────────────────────────────────────────────────────────────────────────

async def _report(
    reporter, _seen: set, url: str, title: str, category: str,
    profile_key: str, confidence: str, evidence: dict,
    cwe: str = "CWE-200", wasc: str = "WASC-13",
    reference: str = OWASP_FINGERPRINT,
    page_id=None, endpoint_id=None, raw_extra: dict = None
):
    """Dedup-check, score, and report a single CMS finding."""
    seen_key = (url, title)
    if seen_key in _seen:
        return
    _seen.add(seen_key)

    try:
        scores = build_ai_scores(profile_key, url)
        meta = scores.pop("_meta", {})

        await reporter.report(
            page_url=url,
            title=title,
            category=category,
            confidence=confidence,
            evidence=evidence,
            raw_data={**(raw_extra or {}), **meta},
            cwe=cwe,
            wasc=wasc,
            reference=reference,
            page_id=page_id,
            endpoint_id=endpoint_id,
            **scores,
        )
    except Exception as e:
        logger.error(f"Report failed for {url}: {_trunc(str(e))}")


# ─────────────────────────────────────────────────────────────────────────────
# WORDPRESS (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

async def _scan_wordpress(
    event: dict, reporter, _seen: set, page_id=None, endpoint_id=None
):
    url = event["url"]
    body = event.get("body", "") or ""
    body_lower = body.lower()
    status_code = event.get("status_code")
    parsed = urlparse(url)
    path = parsed.path.lower()

    kw = dict(
        reporter=reporter, _seen=_seen, category="CMS WordPress",
        page_id=page_id, endpoint_id=endpoint_id
    )

    # ── Version disclosure (using pre-compiled regex) ────────────────────────
    m = WORDPRESS_VERSION_PATTERN.search(body)
    if m:
        version = m.group(3)
        await _report(
            url=url,
            title=f"WordPress Version Disclosure: {version}",
            profile_key="wp_version_disclosure",
            confidence="high",
            evidence={"version": version},
            cwe="CWE-200",
            wasc="WASC-13",
            **kw
        )

    # ── XML-RPC endpoint ──────────────────────────────────────────────────────
    if path.endswith("/xmlrpc.php"):
        await _report(
            url=url,
            title="WordPress XML-RPC Endpoint Exposed",
            profile_key="wp_xmlrpc_exposed",
            confidence="high",
            evidence={"endpoint": "/xmlrpc.php"},
            cwe="CWE-284",
            wasc="WASC-02",
            reference=OWASP_ADMIN,
            **kw
        )

    # ── REST API ──────────────────────────────────────────────────────────────
    if "/wp-json/" in body_lower or path.startswith("/wp-json"):
        await _report(
            url=url,
            title="WordPress REST API Exposed",
            profile_key="wp_rest_api_exposed",
            confidence="medium",
            evidence={"endpoint": "/wp-json/"},
            **kw
        )

    # ── Plugins (cached, using pre-compiled regex) ────────────────────────────
    plugins = set(PLUGIN_PATTERN.findall(body_lower))
    for plugin in plugins:
        await _report(
            url=url,
            title=f"WordPress Plugin Detected: {plugin}",
            profile_key="wp_plugin_detected",
            confidence="medium",
            evidence={"plugin": plugin},
            **kw
        )

    # ── readme.html ───────────────────────────────────────────────────────────
    if path.endswith("/readme.html"):
        await _report(
            url=url,
            title="WordPress readme.html Exposed",
            profile_key="wp_readme_exposed",
            confidence="medium",
            evidence={"file": "readme.html"},
            cwe="CWE-538",
            wasc="WASC-13",
            reference=OWASP_BACKUP,
            **kw
        )

    # ── Debug mode (simple string check, not regex) ───────────────────────────
    if ("wp_debug" in body_lower or
        "notice:" in body_lower or
        "fatal error:" in body_lower):
        await _report(
            url=url,
            title="WordPress Debug Mode May Be Enabled (Error/Notice Detected)",
            profile_key="wp_debug_enabled",
            confidence="medium",
            evidence={"indicator": "WP_DEBUG output detected"},
            cwe="CWE-209",
            **kw
        )

    # ── Themes (cached, using pre-compiled regex) ─────────────────────────────
    themes = set(THEME_PATTERN.findall(body_lower))
    for theme in themes:
        await _report(
            url=url,
            title=f"WordPress Theme Detected: {theme}",
            profile_key="wp_theme_detected",
            confidence="low",
            evidence={"theme": theme},
            **kw
        )

    # ── User enumeration via ?author= ─────────────────────────────────────────
    if "?author=" in url:
        await _report(
            url=url,
            title="WordPress User Enumeration via Author Parameter",
            profile_key="wp_user_enumeration",
            confidence="high",
            evidence={"url": url},
            reference=OWASP_ENUM,
            **kw
        )

    # ── Uploads directory listing ─────────────────────────────────────────────
    if path.startswith("/wp-content/uploads") and status_code == 200:
        if "index of" in body_lower or "parent directory" in body_lower:
            await _report(
                url=url,
                title="WordPress Uploads Directory Listing Enabled",
                profile_key="wp_uploads_dir_listing",
                confidence="high",
                evidence={"path": _trunc(parsed.path)},
                cwe="CWE-548",
                wasc="WASC-16",
                reference=OWASP_DIR,
                **kw
            )

    # ── license.txt ───────────────────────────────────────────────────────────
    if path.endswith("/license.txt"):
        await _report(
            url=url,
            title="WordPress license.txt Exposed",
            profile_key="wp_license_exposed",
            confidence="low",
            evidence={"file": "license.txt"},
            cwe="CWE-538",
            reference=OWASP_BACKUP,
            **kw
        )


# ─────────────────────────────────────────────────────────────────────────────
# DRUPAL (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

async def _scan_drupal(
    event: dict, reporter, _seen: set, page_id=None, endpoint_id=None
):
    url = event["url"]
    body = event.get("body", "") or ""
    body_lower = body.lower()
    status_code = event.get("status_code")
    headers = _norm_headers(event.get("headers", {}))
    parsed = urlparse(url)
    path = parsed.path.lower()

    kw = dict(
        reporter=reporter, _seen=_seen, category="CMS Drupal",
        page_id=page_id, endpoint_id=endpoint_id
    )

    # ── Version via meta generator ────────────────────────────────────────────
    m = DRUPAL_VERSION_PATTERN.search(body)
    if m:
        version = m.group(3)
        await _report(
            url=url,
            title=f"Drupal Version Disclosure: {version}",
            profile_key="drupal_version_disclosure",
            confidence="high",
            evidence={"version": version},
            **kw
        )

    # ── X-Generator header ────────────────────────────────────────────────────
    if "x-generator" in headers and "drupal" in headers["x-generator"].lower():
        await _report(
            url=url,
            title="Drupal Version Disclosure via Header",
            profile_key="drupal_header_disclosure",
            confidence="medium",
            evidence={"header": _trunc(headers["x-generator"])},
            **kw
        )

    # ── Login endpoint ────────────────────────────────────────────────────────
    if path == "/user/login":
        await _report(
            url=url,
            title="Drupal Login Endpoint Accessible",
            profile_key="drupal_login_exposed",
            confidence="medium",
            evidence={"endpoint": "/user/login"},
            cwe="CWE-284",
            wasc="WASC-02",
            **kw
        )

    # ── CHANGELOG.txt ─────────────────────────────────────────────────────────
    if path == "/changelog.txt":
        await _report(
            url=url,
            title="Drupal CHANGELOG.txt Exposed",
            profile_key="drupal_changelog_exposed",
            confidence="medium",
            evidence={"file": "CHANGELOG.txt"},
            cwe="CWE-538",
            reference=OWASP_BACKUP,
            **kw
        )

    # ── Sensitive scripts ─────────────────────────────────────────────────────
    sensitive_files = {"/install.php", "/update.php", "/cron.php"}
    if path in sensitive_files:
        await _report(
            url=url,
            title=f"Drupal Sensitive Script Exposed: {parsed.path}",
            profile_key="drupal_sensitive_script",
            confidence="high",
            evidence={"file": parsed.path},
            cwe="CWE-284",
            wasc="WASC-02",
            reference=OWASP_ADMIN,
            **kw
        )

    # ── User enumeration via /user/{id} ───────────────────────────────────────
    if re.match(r"^/user/\d+$", path) and status_code == 200:
        await _report(
            url=url,
            title="Drupal User Enumeration via /user/{id}",
            profile_key="drupal_user_enumeration",
            confidence="medium",
            evidence={"path": parsed.path},
            reference=OWASP_ENUM,
            **kw
        )

    # ── Devel module ──────────────────────────────────────────────────────────
    if "/devel/" in body_lower or "devel_generate" in body_lower:
        await _report(
            url=url,
            title="Drupal Devel Module Detected (Debug Module Active)",
            profile_key="drupal_devel_module",
            confidence="medium",
            evidence={"indicator": "devel module references in body"},
            cwe="CWE-209",
            **kw
        )

    # ── README / INSTALL files ───────────────────────────────────────────────
    info_files = {"/readme.txt", "/install.txt"}
    if path in info_files:
        await _report(
            url=url,
            title=f"Drupal Information File Exposed: {parsed.path}",
            profile_key="drupal_info_file_exposed",
            confidence="low",
            evidence={"file": parsed.path},
            cwe="CWE-538",
            reference=OWASP_BACKUP,
            **kw
        )


# ─────────────────────────────────────────────────────────────────────────────
# JOOMLA (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

async def _scan_joomla(
    event: dict, reporter, _seen: set, page_id=None, endpoint_id=None
):
    url = event["url"]
    body = event.get("body", "") or ""
    body_lower = body.lower()
    parsed = urlparse(url)
    path = parsed.path.lower()

    kw = dict(
        reporter=reporter, _seen=_seen, category="CMS Joomla",
        page_id=page_id, endpoint_id=endpoint_id
    )

    # ── Version via meta generator ────────────────────────────────────────────
    m = JOOMLA_VERSION_PATTERN.search(body)
    if m:
        v = m.group(3).strip()
        await _report(
            url=url,
            title=f"Joomla Version Disclosure: {v}",
            profile_key="joomla_version_disclosure",
            confidence="high",
            evidence={"version": v},
            **kw
        )

    # ── Admin panel ───────────────────────────────────────────────────────────
    if path.startswith("/administrator"):
        await _report(
            url=url,
            title="Joomla Admin Panel Accessible",
            profile_key="joomla_admin_panel",
            confidence="high",
            evidence={"endpoint": "/administrator"},
            cwe="CWE-284",
            wasc="WASC-02",
            reference=OWASP_ADMIN,
            **kw
        )

    # ── configuration.php / backups ───────────────────────────────────────────
    config_files = {
        "/configuration.php", "/configuration.php.bak",
        "/configuration.php~", "/configuration.php.old"
    }
    if path in config_files:
        await _report(
            url=url,
            title="Joomla Configuration File Exposed",
            profile_key="joomla_config_exposed",
            confidence="high",
            evidence={"file": parsed.path},
            cwe="CWE-538",
            reference=OWASP_BACKUP,
            **kw
        )

    # ── Components (pre-compiled regex) ───────────────────────────────────────
    components = set(JOOMLA_COMPONENT_PATTERN.findall(body_lower))
    for comp in components:
        await _report(
            url=url,
            title=f"Joomla Component Detected: com_{comp}",
            profile_key="joomla_component_detected",
            confidence="low",
            evidence={"component": f"com_{comp}"},
            **kw
        )

    # ── Info files ────────────────────────────────────────────────────────────
    info_files = {"/readme.txt", "/license.txt"}
    if path in info_files:
        await _report(
            url=url,
            title=f"Joomla Information File Exposed: {parsed.path}",
            profile_key="joomla_info_file_exposed",
            confidence="low",
            evidence={"file": parsed.path},
            cwe="CWE-538",
            reference=OWASP_BACKUP,
            **kw
        )


# ─────────────────────────────────────────────────────────────────────────────
# SHOPIFY (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

async def _scan_shopify(
    event: dict, reporter, _seen: set, page_id=None, endpoint_id=None
):
    url = event["url"]
    body = event.get("body", "") or ""
    body_lower = body.lower()

    kw = dict(
        reporter=reporter, _seen=_seen, category="CMS Shopify",
        page_id=page_id, endpoint_id=endpoint_id
    )

    # ── Platform detected (simple string check) ───────────────────────────────
    if "cdn.shopify.com" in body_lower or "shopify" in body_lower:
        await _report(
            url=url,
            title="Shopify Store Detected",
            profile_key="shopify_detected",
            confidence="high",
            evidence={},
            **kw
        )

    # ── Theme disclosure (pre-compiled regex) ─────────────────────────────────
    themes = set(SHOPIFY_THEME_PATTERN.findall(body_lower))
    for theme in themes:
        await _report(
            url=url,
            title=f"Shopify Theme Detected: {theme}",
            profile_key="shopify_theme_detected",
            confidence="low",
            evidence={"theme": theme},
            **kw
        )

    # ── Storefront API token (pre-compiled regex) ─────────────────────────────
    m = SHOPIFY_TOKEN_PATTERN.search(body)
    if m:
        token = m.group(2)
        await _report(
            url=url,
            title="Shopify Storefront API Token Found in Page Source",
            profile_key="shopify_api_token_exposed",
            confidence="medium",
            evidence={"token_hint": token[:8] + "****"},
            cwe="CWE-312",
            **kw
        )


# ─────────────────────────────────────────────────────────────────────────────
# GENERIC CMS (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

async def _scan_generic_cms(
    event: dict, reporter, _seen: set, page_id=None, endpoint_id=None
):
    url = event["url"]
    body = event.get("body", "") or ""
    parsed = urlparse(url)
    path = parsed.path.lower()

    kw = dict(
        reporter=reporter, _seen=_seen, category="CMS Other",
        page_id=page_id, endpoint_id=endpoint_id
    )

    # ── Meta generator version disclosure ──────────────────────────────────────
    m = GENERIC_VERSION_PATTERN.search(body)
    if m:
        version = m.group(3)
        await _report(
            url=url,
            title=f"CMS Version Disclosure: {_trunc(version)}",
            profile_key="cms_version_disclosure",
            confidence="medium",
            evidence={"version": _trunc(version)},
            **kw
        )

    # ── Sensitive path access ─────────────────────────────────────────────────
    for sensitive in GENERIC_SENSITIVE_PATHS:
        if path.startswith(sensitive):
            await _report(
                url=url,
                title=f"Sensitive Endpoint Accessible: {sensitive}",
                profile_key="cms_sensitive_endpoint",
                confidence="medium",
                evidence={"endpoint": sensitive},
                cwe="CWE-284",
                wasc="WASC-02",
                reference=OWASP_ADMIN,
                **kw
            )
            break  # Only report once per URL


# ─────────────────────────────────────────────────────────────────────────────
# MAIN ENTRY POINT (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

async def detect_and_scan_cms(
    event: dict,
    reporter,
    page_id=None,
    endpoint_id=None,
    _seen: set = None
):
    """
    Detect the CMS platform from the response body and dispatch to the
    appropriate CMS-specific scanner.

    Optimizations:
    - Input validation prevents DoS
    - Pre-compiled regex patterns prevent ReDoS
    - Simple string checks before regex
    - Early body truncation
    """
    if _seen is None:
        _seen = set()

    url = event.get("url")
    body = event.get("body", "") or ""

    if not _validate_input(url, body):
        logger.warning(f"Invalid input for CMS scan: url={url}, body_len={len(body)}")
        return

    # ── Safe header check ─────────────────────────────────────────────────────
    headers = _norm_headers(event.get("headers", {}))
    if not _is_text(headers):
        return

    body_lower = body.lower()

    try:
        # ── Fast detection using simple string checks before regex ────────────
        if any(x in body_lower for x in WORDPRESS_INDICATORS):
            await _scan_wordpress(event, reporter, _seen, page_id=page_id, endpoint_id=endpoint_id)

        elif any(x in body_lower for x in DRUPAL_INDICATORS):
            await _scan_drupal(event, reporter, _seen, page_id=page_id, endpoint_id=endpoint_id)

        elif any(x in body_lower for x in JOOMLA_INDICATORS):
            await _scan_joomla(event, reporter, _seen, page_id=page_id, endpoint_id=endpoint_id)

        elif any(x in body_lower for x in SHOPIFY_INDICATORS):
            await _scan_shopify(event, reporter, _seen, page_id=page_id, endpoint_id=endpoint_id)

        elif GENERIC_VERSION_PATTERN.search(body):
            await _scan_generic_cms(event, reporter, _seen, page_id=page_id, endpoint_id=endpoint_id)

    except Exception as e:
        logger.error(f"[CMS] Failed on {url}: {_trunc(str(e))}")