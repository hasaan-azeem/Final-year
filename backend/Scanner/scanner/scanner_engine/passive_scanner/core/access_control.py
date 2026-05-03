import logging
import re
from urllib.parse import urlparse
from functools import lru_cache

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.access_control")

MAX_SNIPPET_LEN = 100
MAX_BODY_SIZE = 1_000_000  # 1MB limit
MAX_URL_LEN = 8192
MAX_HEADER_VALUE_LEN = 16384

# Pre-compile patterns for ReDoS protection
DIRECTORY_LISTING_PATTERN = re.compile(
    r"(index of /|directory listing for|parent directory)",
    re.IGNORECASE
)
PHPINFO_PATTERN = re.compile(
    r"(phpinfo\(\)|php version|php credits|<title>phpinfo\(\)</title>)",
    re.IGNORECASE
)
CROSSDOMAIN_PATTERN = re.compile(
    r'domain=(["\'])\*\1',
    re.IGNORECASE
)

# Pre-computed frozensets for O(1) lookups instead of O(n) iterations
SENSITIVE_ENDPOINTS_SET = frozenset({
    "/admin", "/administrator", "/wp-admin",
    "/dashboard", "/internal", "/debug",
    "/config", "/backup",
    "/console", "/manage", "/management",
    "/setup", "/install", "/sysadmin",
    "/webadmin", "/cpanel", "/whm", "/plesk",
    "/panel", "/controlpanel", "/adminpanel",
})

SENSITIVE_FILES_SET = frozenset({
    ".git/config", ".env", "config.php",
    "backup.sql", "db.sql",
    ".htaccess", "web.config", "wp-config.php",
    "composer.json", "package.json",
    ".DS_Store", "crossdomain.xml",
    "clientaccesspolicy.xml",
})

BACKUP_EXTENSIONS_TUPLE = (
    ".zip", ".tar", ".gz", ".rar", ".7z", ".bak", ".old"
)

API_DOC_ENDPOINTS_SET = frozenset({
    "/swagger-ui.html", "/swagger-ui/", "/swagger/",
    "/api-docs", "/api/docs", "/api/swagger",
    "/openapi.json", "/openapi.yaml",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/redoc", "/graphql",
})

ACTUATOR_ENDPOINTS_SET = frozenset({
    "/actuator", "/actuator/env", "/actuator/health",
    "/actuator/beans", "/actuator/mappings",
    "/actuator/trace", "/actuator/loggers",
    "/actuator/heapdump", "/actuator/threaddump",
    "/actuator/configprops",
})

DB_ADMIN_ENDPOINTS_SET = frozenset({
    "/phpmyadmin", "/pma", "/adminer",
    "/adminer.php", "/phpMyAdmin",
    "/db/", "/database/",
    "/mysql/", "/dbadmin/",
})

PHPINFO_FILES_SET = frozenset({
    "phpinfo.php", "info.php", "test.php",
    "php_info.php", "phpversion.php",
})

SERVER_STATUS_PATHS_SET = frozenset({
    "/server-status", "/server-info",
})

PROTECTED_STATUS_CODES = frozenset({401, 403})
REDIRECT_STATUS_CODES = frozenset({301, 302, 307, 308})


# ─────────────────────────────────────────────────────────────────────────────
# HELPERS (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

def _trunc(text: str, length: int = MAX_SNIPPET_LEN) -> str:
    """Truncate text safely."""
    return text[:length] if text else ""

@lru_cache(maxsize=256)
def _normalize_path(path: str) -> str:
    """Cache normalized paths for O(1) lookup."""
    return path.rstrip("/").lower()

def _match_endpoint_fast(path: str, endpoint_set: frozenset) -> bool:
    """O(n) set member check instead of O(n*m) nested loop."""
    normalized = _normalize_path(path)
    # Check exact match or as prefix with /
    return (normalized in endpoint_set or
            any(normalized.startswith(ep.rstrip("/") + "/") 
                for ep in endpoint_set))

def _match_file(path: str, filename: str) -> bool:
    """Case-insensitive file matching."""
    return _normalize_path(path).endswith(_normalize_path(filename))

def _match_backup(path: str) -> bool:
    """Fast backup extension check using tuple."""
    norm = _normalize_path(path)
    return any(norm.endswith(ext) for ext in BACKUP_EXTENSIONS_TUPLE)

def _detect_directory_listing(body: str) -> bool:
    """Use pre-compiled regex pattern."""
    if not body or len(body) > MAX_BODY_SIZE:
        return False
    return bool(DIRECTORY_LISTING_PATTERN.search(body))

def _detect_phpinfo(body: str) -> bool:
    """Use pre-compiled regex pattern."""
    if not body or len(body) > MAX_BODY_SIZE:
        return False
    return bool(PHPINFO_PATTERN.search(body))

def _detect_crossdomain_wildcard(body: str) -> bool:
    """Use pre-compiled regex pattern."""
    if not body or len(body) > MAX_BODY_SIZE:
        return False
    return bool(CROSSDOMAIN_PATTERN.search(body))

def _content_type(headers: dict) -> str:
    """Safe header extraction."""
    return headers.get("content-type", "").lower()[:256]

def _is_text(content_type: str) -> bool:
    """Check if content type is text-based."""
    return any(t in content_type for t in ["text", "json", "javascript", "xml", "html"])

def _validate_url(url: str) -> bool:
    """Validate URL format and length."""
    return url and len(url) <= MAX_URL_LEN and url.startswith(("http://", "https://"))


# ─────────────────────────────────────────────────────────────────────────────
# MAIN DETECTOR (OPTIMIZED)
# ─────────────────────────────────────────────────────────────────────────────

async def detect_admin_exposure(
    event: dict, 
    reporter, 
    page_id=None, 
    endpoint_id=None, 
    _seen: set = None
):
    """
    Detect exposed admin panels, sensitive files, backup files, repo leaks,
    directory listings, API docs, actuators, DB admin panels, phpinfo, and
    misconfigured cross-domain policies.

    Optimized for speed: Uses sets for O(1) lookup, pre-compiled regex,
    and caching of normalized paths.
    """
    if _seen is None:
        _seen = set()

    # ──── INPUT VALIDATION ────
    url = event.get("url")
    status_code = event.get("status_code")

    if not _validate_url(url) or not isinstance(status_code, int):
        logger.warning(f"Invalid input: url={url}, status_code={status_code}")
        return

    parsed = urlparse(url)
    path = _normalize_path(parsed.path)
    if not path or path == "/":
        return

    # ──── SAFE HEADER PROCESSING ────
    headers_raw = event.get("headers")
    if not isinstance(headers_raw, dict):
        headers_raw = {}
    headers = {
        k.lower()[:64]: _trunc(str(v), MAX_HEADER_VALUE_LEN)
        for k, v in headers_raw.items()
    }

    # ──── TRUNCATE BODY FOR SAFETY ────
    body = (event.get("body") or "")
    if not isinstance(body, str):
        body = ""
    if len(body) > MAX_BODY_SIZE:
        body = body[:MAX_BODY_SIZE]

    content_type = _content_type(headers)
    t_path = _trunc(path)

    async def _report(
        title, profile_key, confidence, evidence,
        cwe="CWE-284", wasc="WASC-02", reference=None, raw_data=None
    ):
        """Report with deduplication."""
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
                category="access_control",
                confidence=confidence,
                evidence=evidence,
                raw_data={**(raw_data or {}), **meta},
                cwe=cwe,
                wasc=wasc,
                reference=reference or "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
                page_id=page_id,
                endpoint_id=endpoint_id,
                **scores,
            )
        except Exception as e:
            logger.error(f"Report failed for {url}: {_trunc(str(e))}")

    try:
        # ── 1. Sensitive admin endpoints (O(1) lookup) ────────────────────────
        if _match_endpoint_fast(path, SENSITIVE_ENDPOINTS_SET):
            if status_code == 200:
                await _report(
                    title="Administrative Interface Publicly Accessible",
                    profile_key="admin_exposed",
                    confidence="high",
                    evidence={"path": t_path, "status_code": status_code},
                )
            elif status_code in PROTECTED_STATUS_CODES:
                reason = "Forbidden" if status_code == 403 else "Unauthorized"
                await _report(
                    title=f"Administrative Interface Detected (Access Restricted — {reason})",
                    profile_key="admin_restricted",
                    confidence="medium",
                    evidence={"path": t_path, "status_code": status_code},
                )
            elif status_code in REDIRECT_STATUS_CODES:
                await _report(
                    title="Administrative Interface Detected (Redirect — Possible Login Wall)",
                    profile_key="admin_redirect",
                    confidence="medium",
                    evidence={"path": t_path, "status_code": status_code},
                )

        # ── 2. Sensitive files (O(1) lookup) ──────────────────────────────────
        for sensitive_file in SENSITIVE_FILES_SET:
            if _match_file(path, sensitive_file):
                if status_code == 200:
                    await _report(
                        title="Sensitive File Publicly Accessible",
                        profile_key="sensitive_file_exposed",
                        confidence="high",
                        evidence={"file": _trunc(sensitive_file), "url": url, "status_code": status_code},
                        cwe="CWE-538",
                        wasc="WASC-13",
                        reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                    )
                elif status_code in PROTECTED_STATUS_CODES:
                    await _report(
                        title="Sensitive File Detected (Access Restricted)",
                        profile_key="sensitive_file_restricted",
                        confidence="medium",
                        evidence={"file": _trunc(sensitive_file), "url": url, "status_code": status_code},
                        cwe="CWE-538",
                        wasc="WASC-13",
                        reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
                    )

        # ── 3. Backup files ───────────────────────────────────────────────────
        if _match_backup(path) and status_code == 200:
            await _report(
                title="Backup File Publicly Accessible",
                profile_key="backup_file_exposed",
                confidence="high",
                evidence={"path": t_path, "status_code": status_code},
                cwe="CWE-530",
                wasc="WASC-13",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information",
            )

        # ── 4. Git / SVN repository exposure ──────────────────────────────────
        if "/.git/" in path and status_code == 200:
            await _report(
                title="Exposed Git Repository File",
                profile_key="git_exposed",
                confidence="high",
                evidence={"path": t_path, "status_code": status_code},
                cwe="CWE-538",
                wasc="WASC-13",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration",
            )
        if "/.svn/" in path and status_code == 200:
            await _report(
                title="Exposed SVN Repository File",
                profile_key="svn_exposed",
                confidence="high",
                evidence={"path": t_path, "status_code": status_code},
                cwe="CWE-538",
                wasc="WASC-13",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration",
            )

        # ── 5. Directory listing ───────────────────────────────────────────────
        if status_code == 200 and _is_text(content_type) and _detect_directory_listing(body):
            await _report(
                title="Directory Listing Enabled",
                profile_key="dir_listing_exposed",
                confidence="medium",
                evidence={"path": t_path},
                cwe="CWE-548",
                wasc="WASC-16",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/03-Test_File_Extensions_Handling_for_Sensitive_Information",
            )

        # ── 6. API documentation (O(1) lookup) ────────────────────────────────
        if _match_endpoint_fast(path, API_DOC_ENDPOINTS_SET):
            if status_code == 200:
                await _report(
                    title="API Documentation Publicly Accessible",
                    profile_key="api_docs_exposed",
                    confidence="medium",
                    evidence={"path": t_path, "status_code": status_code},
                    cwe="CWE-200",
                    wasc="WASC-13",
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/",
                )
            elif status_code in PROTECTED_STATUS_CODES:
                await _report(
                    title="API Documentation Detected (Access Restricted)",
                    profile_key="api_docs_restricted",
                    confidence="low",
                    evidence={"path": t_path, "status_code": status_code},
                    cwe="CWE-200",
                    wasc="WASC-13",
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/",
                )

        # ── 7. Spring Boot actuators (O(1) lookup) ─────────────────────────────
        if _match_endpoint_fast(path, ACTUATOR_ENDPOINTS_SET):
            if status_code == 200:
                await _report(
                    title="Spring Boot Actuator Endpoint Publicly Accessible",
                    profile_key="actuator_exposed",
                    confidence="high",
                    evidence={"path": t_path, "status_code": status_code},
                    cwe="CWE-215",
                    wasc="WASC-13",
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration",
                )
            elif status_code in PROTECTED_STATUS_CODES:
                await _report(
                    title="Spring Boot Actuator Endpoint Detected (Access Restricted)",
                    profile_key="actuator_restricted",
                    confidence="medium",
                    evidence={"path": t_path, "status_code": status_code},
                    cwe="CWE-215",
                    wasc="WASC-13",
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration",
                )

        # ── 8. Database admin panels (O(1) lookup) ────────────────────────────
        if _match_endpoint_fast(path, DB_ADMIN_ENDPOINTS_SET):
            if status_code == 200:
                await _report(
                    title="Database Administration Panel Publicly Accessible",
                    profile_key="db_admin_exposed",
                    confidence="high",
                    evidence={"path": t_path, "status_code": status_code},
                )
            elif status_code in PROTECTED_STATUS_CODES:
                await _report(
                    title="Database Administration Panel Detected (Access Restricted)",
                    profile_key="db_admin_restricted",
                    confidence="medium",
                    evidence={"path": t_path, "status_code": status_code},
                )

        # ── 9. PHP info pages ──────────────────────────────────────────────────
        for php_file in PHPINFO_FILES_SET:
            if (_match_file(path, php_file) and
                status_code == 200 and
                _is_text(content_type) and
                _detect_phpinfo(body)):
                await _report(
                    title="PHP Info Page Publicly Accessible",
                    profile_key="phpinfo_exposed",
                    confidence="high",
                    evidence={"path": t_path, "status_code": status_code},
                    cwe="CWE-200",
                    wasc="WASC-13",
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration",
                )

        # ── 10. Server status pages (O(1) lookup) ──────────────────────────────
        if _match_endpoint_fast(path, SERVER_STATUS_PATHS_SET) and status_code == 200:
            await _report(
                title="Server Status Page Publicly Accessible",
                profile_key="server_status_exposed",
                confidence="medium",
                evidence={"path": t_path, "status_code": status_code},
                cwe="CWE-200",
                wasc="WASC-13",
                reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration",
            )

        # ── 11. Overly permissive cross-domain policy ──────────────────────────
        for crossdomain_file in ["crossdomain.xml", "clientaccesspolicy.xml"]:
            if (_match_file(path, crossdomain_file) and
                status_code == 200 and
                _is_text(content_type) and
                _detect_crossdomain_wildcard(body)):
                await _report(
                    title="Overly Permissive Cross-Domain Policy",
                    profile_key="crossdomain_wildcard",
                    confidence="high",
                    evidence={"path": t_path, "status_code": status_code},
                    cwe="CWE-942",
                    wasc="WASC-14",
                    reference="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-Side_Testing/08-Testing_for_Cross_Site_Flashing",
                )

    except Exception as e:
        logger.error(f"[Access Control] Failed on {url}: {_trunc(str(e))}")