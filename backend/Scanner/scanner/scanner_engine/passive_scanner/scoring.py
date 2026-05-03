from decimal import Decimal, ROUND_HALF_UP
from urllib.parse import urlparse
from typing import Optional

def _q(v, places: int = 2):
    """
    Quantize a float to `places` decimal places via Decimal arithmetic,
    then return as float for asyncpg compatibility.
    Eliminates binary float noise (e.g. 5.4000000000000003...) before
    values reach PostgreSQL NUMERIC columns.
    """
    if v is None:
        return None
    fmt = Decimal("0." + "0" * places)
    return float(Decimal(str(v)).quantize(fmt, rounding=ROUND_HALF_UP))

# ─────────────────────────────────────────────────────────────────────────────
# PATH SENSITIVITY TIERS
# ─────────────────────────────────────────────────────────────────────────────

_TIERS: list[tuple[float, list[str]]] = [
    # (multiplier, path_prefixes)  — top-down, first match wins

    (1.40, [
        "/payment", "/checkout", "/pay/",
        "/billing", "/invoice", "/transfer",
        "/withdraw", "/deposit", "/wallet",
        "/purchase", "/order", "/card",
        "/bank", "/crypto", "/subscribe",
    ]),

    (1.30, [
        "/login", "/signin", "/sign-in",
        "/logout", "/signout", "/sign-out",
        "/auth", "/authenticate", "/oauth",
        "/register", "/signup", "/sign-up",
        "/password", "/forgot", "/reset",
        "/verify", "/confirm",
        "/2fa", "/mfa", "/otp", "/totp",
        "/session", "/token",
    ]),

    (1.20, [
        "/admin", "/administrator",
        "/dashboard", "/manage", "/management",
        "/settings", "/config", "/configuration",
        "/setup", "/install", "/internal",
        "/staff", "/operator", "/superuser",
        "/console", "/panel", "/controlpanel",
        "/debug", "/sysadmin",
    ]),

    (1.15, [
        "/api/", "/api",
        "/v1/", "/v2/", "/v3/",
        "/graphql", "/rest/",
        "/profile", "/account", "/me/",
        "/user/", "/users/",
        "/upload", "/uploads/",
        "/file/", "/files/",
        "/media/", "/attachment/",
        "/document/", "/docs/",
        "/export", "/import",
        "/report", "/reports/",
        "/data/", "/private/",
    ]),
]

_DEFAULT_MULTIPLIER = 1.00


def get_path_multiplier(url: str) -> float:
    """
    Return the sensitivity multiplier for the given URL's path.
    Evaluates tiers top-down; returns the first match or 1.0.
    """
    try:
        path = urlparse(url).path.lower()
    except Exception:
        return _DEFAULT_MULTIPLIER

    for multiplier, prefixes in _TIERS:
        if any(path.startswith(p) for p in prefixes):
            return multiplier
    return _DEFAULT_MULTIPLIER


def get_path_tier_name(url: str) -> str:
    """Human-readable tier name — stored in raw_data for AI training."""
    m = get_path_multiplier(url)
    return {
        1.40: "critical",
        1.30: "high",
        1.20: "elevated",
        1.15: "sensitive",
        1.00: "normal",
    }.get(m, "normal")


# ─────────────────────────────────────────────────────────────────────────────
# MULTIPLIER APPLICATION
# ─────────────────────────────────────────────────────────────────────────────

def _apply(base: dict, multiplier: float) -> dict:
    soft = 1.0 + (multiplier - 1.0) * 0.5

    def cap(v, ceiling: float):
        return _q(min(v, ceiling)) if v is not None else None

    # Always return a fresh dict — never return the base PROFILES entry directly,
    # as callers pop() _meta from the result which would corrupt the shared dict.
    return {
        "severity":          cap(base["severity"]          * multiplier,        1.0),
        "impact":            cap(base["impact"]            * multiplier,        1.0),
        "likelihood":        cap(base["likelihood"]        * soft,              1.0),
        "cvss_score":        cap(base["cvss_score"]        * multiplier,       10.0),
        "page_criticality":  cap(base["page_criticality"]  * multiplier * 1.15, 10.0),
        "exploit_available": base["exploit_available"],
    }


# ─────────────────────────────────────────────────────────────────────────────
# BASE PROFILES
# ─────────────────────────────────────────────────────────────────────────────
# CVSS v3.1 alignment bands:
#   Critical ≥9.0 | High ≥7.0 | Medium ≥4.0 | Low <4.0
#
# OWASP Risk Rating alignment:
#   severity / impact / likelihood — each 0-1
#   Critical: severity≥0.9  impact≥0.9  likelihood≥0.7
#   High:     severity≥0.7  impact≥0.7  likelihood≥0.6
#   Medium:   severity≥0.4  impact≥0.4  likelihood≥0.4
#   Low:      severity<0.4  impact<0.4  likelihood<0.4
#
# ─────────────────────────────────────────────────────────────────────────────

_NULL = dict(
    severity=None, likelihood=None, impact=None,
    cvss_score=None, exploit_available=None, page_criticality=None,
)

# fmt: off
PROFILES: dict[str, dict] = {

    # ── Security Headers ─────────────────────────────────────────────────────
    "missing_csp_high":              dict(severity=0.75, likelihood=0.70, impact=0.75, cvss_score=7.5,  exploit_available=False, page_criticality=8.0),
    "missing_csp_medium":            dict(severity=0.55, likelihood=0.55, impact=0.55, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "csp_unsafe_inline":             dict(severity=0.70, likelihood=0.65, impact=0.70, cvss_score=7.0,  exploit_available=True,  page_criticality=7.5),
    "csp_unsafe_eval":               dict(severity=0.65, likelihood=0.60, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.0),
    "csp_wildcard":                  dict(severity=0.60, likelihood=0.60, impact=0.60, cvss_score=6.0,  exploit_available=False, page_criticality=6.5),
    "csp_missing_directives":        dict(severity=0.45, likelihood=0.50, impact=0.45, cvss_score=4.5,  exploit_available=False, page_criticality=5.5),
    "missing_xfo_high":              dict(severity=0.65, likelihood=0.60, impact=0.65, cvss_score=6.5,  exploit_available=False, page_criticality=7.0),
    "missing_xfo_medium":            dict(severity=0.45, likelihood=0.45, impact=0.45, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "hsts_absent":                   dict(severity=0.70, likelihood=0.65, impact=0.70, cvss_score=7.0,  exploit_available=False, page_criticality=7.5),
    "hsts_weak_maxage":              dict(severity=0.50, likelihood=0.55, impact=0.50, cvss_score=5.0,  exploit_available=False, page_criticality=6.0),
    "hsts_missing_subdomains":       dict(severity=0.35, likelihood=0.40, impact=0.35, cvss_score=3.5,  exploit_available=False, page_criticality=5.0),
    "hsts_not_preloaded":            dict(severity=0.20, likelihood=0.25, impact=0.20, cvss_score=2.0,  exploit_available=False, page_criticality=3.0),
    "nosniff_absent":                dict(severity=0.35, likelihood=0.40, impact=0.35, cvss_score=3.5,  exploit_available=False, page_criticality=4.0),
    "referrer_missing_high":         dict(severity=0.45, likelihood=0.50, impact=0.45, cvss_score=4.5,  exploit_available=False, page_criticality=6.0),
    "referrer_missing_medium":       dict(severity=0.30, likelihood=0.35, impact=0.30, cvss_score=3.0,  exploit_available=False, page_criticality=4.0),
    "referrer_unsafe_url":           dict(severity=0.50, likelihood=0.55, impact=0.50, cvss_score=5.0,  exploit_available=False, page_criticality=5.5),
    "permissions_absent_high":       dict(severity=0.40, likelihood=0.45, impact=0.40, cvss_score=4.0,  exploit_available=False, page_criticality=5.5),
    "permissions_absent_medium":     dict(severity=0.25, likelihood=0.30, impact=0.25, cvss_score=2.5,  exploit_available=False, page_criticality=3.5),
    "permissions_wildcard":          dict(severity=0.50, likelihood=0.50, impact=0.50, cvss_score=5.0,  exploit_available=False, page_criticality=5.5),

    # ── Access Control ───────────────────────────────────────────────────────
    "admin_exposed":                 dict(severity=0.90, likelihood=0.85, impact=0.90, cvss_score=9.0,  exploit_available=True,  page_criticality=9.0),
    "admin_restricted":              dict(severity=0.55, likelihood=0.50, impact=0.65, cvss_score=5.5,  exploit_available=False, page_criticality=8.0),
    "admin_redirect":                dict(severity=0.45, likelihood=0.45, impact=0.55, cvss_score=4.5,  exploit_available=False, page_criticality=7.0),
    "sensitive_file_exposed":        dict(severity=0.80, likelihood=0.85, impact=0.80, cvss_score=8.0,  exploit_available=True,  page_criticality=8.5),
    "sensitive_file_restricted":     dict(severity=0.50, likelihood=0.45, impact=0.55, cvss_score=4.5,  exploit_available=False, page_criticality=7.0),
    "backup_file_exposed":           dict(severity=0.85, likelihood=0.80, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=8.5),
    "repo_exposed":                  dict(severity=0.90, likelihood=0.85, impact=0.90, cvss_score=9.0,  exploit_available=True,  page_criticality=9.0),
    "directory_listing":             dict(severity=0.60, likelihood=0.75, impact=0.60, cvss_score=6.0,  exploit_available=False, page_criticality=6.5),
    "api_docs_exposed":              dict(severity=0.55, likelihood=0.70, impact=0.55, cvss_score=5.5,  exploit_available=False, page_criticality=7.0),
    "api_docs_restricted":           dict(severity=0.30, likelihood=0.40, impact=0.35, cvss_score=3.0,  exploit_available=False, page_criticality=5.0),
    "actuator_exposed":              dict(severity=0.85, likelihood=0.80, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=9.0),
    "actuator_restricted":           dict(severity=0.50, likelihood=0.50, impact=0.55, cvss_score=5.0,  exploit_available=False, page_criticality=7.5),
    "db_admin_exposed":              dict(severity=0.95, likelihood=0.85, impact=0.95, cvss_score=9.5,  exploit_available=True,  page_criticality=9.5),
    "db_admin_restricted":           dict(severity=0.60, likelihood=0.55, impact=0.65, cvss_score=6.0,  exploit_available=False, page_criticality=8.5),
    "phpinfo_exposed":               dict(severity=0.75, likelihood=0.80, impact=0.70, cvss_score=7.0,  exploit_available=True,  page_criticality=7.0),
    "server_status_exposed":         dict(severity=0.55, likelihood=0.70, impact=0.50, cvss_score=5.0,  exploit_available=False, page_criticality=6.0),
    "crossdomain_wildcard":          dict(severity=0.80, likelihood=0.75, impact=0.80, cvss_score=8.0,  exploit_available=True,  page_criticality=7.5),
    "git_exposed":                   dict(severity=0.90, likelihood=0.85, impact=0.90, cvss_score=9.0,  exploit_available=True,  page_criticality=9.0),
    "svn_exposed":                   dict(severity=0.85, likelihood=0.80, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=8.5),
    "dir_listing_exposed":           dict(severity=0.65, likelihood=0.75, impact=0.60, cvss_score=6.5,  exploit_available=False, page_criticality=7.0),
    "sensitive_file_unexpected":     dict(severity=0.35, likelihood=0.50, impact=0.30, cvss_score=3.5,  exploit_available=False, page_criticality=5.0),

    # ── Cookies ──────────────────────────────────────────────────────────────
    "cookie_missing_httponly":       dict(severity=0.60, likelihood=0.65, impact=0.65, cvss_score=6.1,  exploit_available=True,  page_criticality=7.0),
    "cookie_missing_secure":         dict(severity=0.70, likelihood=0.60, impact=0.70, cvss_score=7.0,  exploit_available=True,  page_criticality=7.5),
    "cookie_missing_samesite":       dict(severity=0.55, likelihood=0.55, impact=0.55, cvss_score=5.4,  exploit_available=False, page_criticality=6.0),
    "cookie_samesite_none_insecure": dict(severity=0.75, likelihood=0.65, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=7.5),
    "cookie_no_expiry":              dict(severity=0.40, likelihood=0.50, impact=0.40, cvss_score=4.0,  exploit_available=False, page_criticality=5.0),
    "cookie_overly_broad_domain":    dict(severity=0.55, likelihood=0.55, impact=0.55, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "cookie_overly_broad_path":      dict(severity=0.40, likelihood=0.45, impact=0.40, cvss_score=4.0,  exploit_available=False, page_criticality=5.0),
    "session_cookie_not_httponly":   dict(severity=0.80, likelihood=0.75, impact=0.85, cvss_score=8.0,  exploit_available=True,  page_criticality=8.5),
    "session_cookie_not_secure":     dict(severity=0.85, likelihood=0.70, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=9.0),
    "cookie_weak_samesite_lax":      dict(severity=0.35, likelihood=0.40, impact=0.35, cvss_score=3.5,  exploit_available=False, page_criticality=4.0),
    "cookie_low_entropy":            dict(severity=0.70, likelihood=0.60, impact=0.70, cvss_score=7.0,  exploit_available=True,  page_criticality=7.5),
    "cookie_jwt_stored":             dict(severity=0.50, likelihood=0.55, impact=0.50, cvss_score=5.0,  exploit_available=False, page_criticality=6.0),
    "cookie_excessive_lifetime":     dict(severity=0.45, likelihood=0.50, impact=0.45, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "cookie_sensitive_value":        dict(severity=0.65, likelihood=0.60, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.0),

    # ── CORS ─────────────────────────────────────────────────────────────────
    "cors_wildcard":                 dict(severity=0.75, likelihood=0.70, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    "cors_reflect_origin":           dict(severity=0.85, likelihood=0.75, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=8.5),
    "cors_null_origin":              dict(severity=0.70, likelihood=0.65, impact=0.70, cvss_score=7.0,  exploit_available=True,  page_criticality=7.5),
    "cors_allow_credentials_wild":   dict(severity=0.90, likelihood=0.80, impact=0.90, cvss_score=9.0,  exploit_available=True,  page_criticality=9.0),
    "cors_http_origin_on_https":     dict(severity=0.65, likelihood=0.60, impact=0.65, cvss_score=6.5,  exploit_available=False, page_criticality=7.0),
    # FIX: cors.py uses cors_exposed_sensitive_headers — kept old name as alias
    # for any legacy data; cors.py will use the new canonical name going forward.
    "cors_sensitive_headers_exposed": dict(severity=0.75, likelihood=0.70, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    # NEW: canonical names used by cors.py checks 7 and 8
    "cors_dangerous_methods":        dict(severity=0.65, likelihood=0.65, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.0),
    "cors_exposed_sensitive_headers": dict(severity=0.75, likelihood=0.70, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    "cors_excessive_preflight":      dict(severity=0.30, likelihood=0.40, impact=0.25, cvss_score=3.0,  exploit_available=False, page_criticality=3.5),
    "cors_postmessage_wildcard":     dict(severity=0.65, likelihood=0.65, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.0),

    # ── Information Disclosure ───────────────────────────────────────────────
    "server_header_exposed":         dict(severity=0.35, likelihood=0.80, impact=0.30, cvss_score=3.5,  exploit_available=False, page_criticality=4.0),
    "x_powered_by_exposed":          dict(severity=0.35, likelihood=0.80, impact=0.30, cvss_score=3.5,  exploit_available=False, page_criticality=4.0),
    "cms_generator_exposed":         dict(severity=0.40, likelihood=0.85, impact=0.35, cvss_score=4.0,  exploit_available=False, page_criticality=4.5),
    "js_lib_version_exposed":        dict(severity=0.45, likelihood=0.80, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "server_header_version":         dict(severity=0.40, likelihood=0.85, impact=0.35, cvss_score=4.0,  exploit_available=False, page_criticality=5.0),
    "js_query_version_exposed":      dict(severity=0.25, likelihood=0.70, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.0),

    # ── CMS — WordPress ─────────────────────────────────────────────────────
    "wp_version_disclosure":         dict(severity=0.55, likelihood=0.90, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "wp_xmlrpc_exposed":             dict(severity=0.75, likelihood=0.85, impact=0.70, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    "wp_rest_api_exposed":           dict(severity=0.45, likelihood=0.80, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "wp_plugin_detected":            dict(severity=0.35, likelihood=0.80, impact=0.30, cvss_score=3.5,  exploit_available=False, page_criticality=4.0),
    "wp_readme_exposed":             dict(severity=0.40, likelihood=0.80, impact=0.35, cvss_score=4.0,  exploit_available=False, page_criticality=4.5),
    "wp_debug_enabled":              dict(severity=0.65, likelihood=0.75, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.0),
    "wp_theme_detected":             dict(severity=0.25, likelihood=0.75, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.0),
    "wp_user_enumeration":           dict(severity=0.60, likelihood=0.85, impact=0.55, cvss_score=6.0,  exploit_available=True,  page_criticality=6.5),
    "wp_uploads_dir_listing":        dict(severity=0.70, likelihood=0.80, impact=0.65, cvss_score=7.0,  exploit_available=True,  page_criticality=7.5),
    "wp_license_exposed":            dict(severity=0.20, likelihood=0.70, impact=0.15, cvss_score=2.0,  exploit_available=False, page_criticality=2.5),

    # ── CMS — Drupal ─────────────────────────────────────────────────────────
    "drupal_version_disclosure":     dict(severity=0.55, likelihood=0.90, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "drupal_header_disclosure":      dict(severity=0.45, likelihood=0.85, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "drupal_login_exposed":          dict(severity=0.40, likelihood=0.80, impact=0.35, cvss_score=4.0,  exploit_available=False, page_criticality=5.5),
    "drupal_changelog_exposed":      dict(severity=0.45, likelihood=0.80, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "drupal_sensitive_script":       dict(severity=0.75, likelihood=0.80, impact=0.70, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    "drupal_user_enumeration":       dict(severity=0.55, likelihood=0.80, impact=0.50, cvss_score=5.5,  exploit_available=True,  page_criticality=6.0),
    "drupal_devel_module":           dict(severity=0.60, likelihood=0.70, impact=0.60, cvss_score=6.0,  exploit_available=True,  page_criticality=6.5),
    "drupal_info_file_exposed":      dict(severity=0.25, likelihood=0.75, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.0),

    # ── CMS — Joomla ─────────────────────────────────────────────────────────
    "joomla_version_disclosure":     dict(severity=0.55, likelihood=0.90, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "joomla_admin_panel":            dict(severity=0.80, likelihood=0.85, impact=0.80, cvss_score=8.0,  exploit_available=True,  page_criticality=8.5),
    "joomla_config_exposed":         dict(severity=0.90, likelihood=0.85, impact=0.90, cvss_score=9.0,  exploit_available=True,  page_criticality=9.0),
    "joomla_component_detected":     dict(severity=0.25, likelihood=0.75, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.0),
    "joomla_info_file_exposed":      dict(severity=0.25, likelihood=0.70, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.0),

    # ── CMS — Shopify ────────────────────────────────────────────────────────
    "shopify_detected":              dict(severity=0.25, likelihood=0.85, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.0),
    "shopify_theme_detected":        dict(severity=0.20, likelihood=0.75, impact=0.15, cvss_score=2.0,  exploit_available=False, page_criticality=2.5),
    "shopify_api_token_exposed":     dict(severity=0.85, likelihood=0.80, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=9.0),

    # ── CMS — Generic ────────────────────────────────────────────────────────
    "cms_version_disclosure":        dict(severity=0.45, likelihood=0.85, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "cms_sensitive_endpoint":        dict(severity=0.55, likelihood=0.75, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.5),
    "html_comment_version_exposed":  dict(severity=0.30, likelihood=0.75, impact=0.25, cvss_score=3.0,  exploit_available=False, page_criticality=3.5),
    "stack_trace_exposed":           dict(severity=0.75, likelihood=0.70, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=7.5),
    "debug_info_exposed":            dict(severity=0.65, likelihood=0.65, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.0),
    "internal_ip_exposed":           dict(severity=0.55, likelihood=0.70, impact=0.50, cvss_score=5.3,  exploit_available=False, page_criticality=6.0),
    "email_exposed":                 dict(severity=0.40, likelihood=0.75, impact=0.35, cvss_score=4.0,  exploit_available=False, page_criticality=4.5),
    "jwt_exposed":                   dict(severity=0.85, likelihood=0.70, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=9.0),
    "api_key_exposed":               dict(severity=0.90, likelihood=0.75, impact=0.90, cvss_score=9.0,  exploit_available=True,  page_criticality=9.0),
    "aws_key_exposed":               dict(severity=0.95, likelihood=0.75, impact=0.95, cvss_score=9.5,  exploit_available=True,  page_criticality=9.5),

    # ── Injection ────────────────────────────────────────────────────────────
    "sqli_error_based":              dict(severity=0.90, likelihood=0.80, impact=0.95, cvss_score=9.8,  exploit_available=True,  page_criticality=9.5),
    "sqli_boolean_based":            dict(severity=0.85, likelihood=0.70, impact=0.90, cvss_score=8.8,  exploit_available=True,  page_criticality=9.0),
    "xss_reflected":                 dict(severity=0.70, likelihood=0.75, impact=0.70, cvss_score=7.2,  exploit_available=True,  page_criticality=7.5),
    "xss_stored":                    dict(severity=0.85, likelihood=0.80, impact=0.85, cvss_score=8.8,  exploit_available=True,  page_criticality=9.0),
    "xss_dom":                       dict(severity=0.75, likelihood=0.70, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    "command_injection":             dict(severity=0.95, likelihood=0.75, impact=0.98, cvss_score=9.8,  exploit_available=True,  page_criticality=9.5),
    "path_traversal":                dict(severity=0.85, likelihood=0.70, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=8.5),
    "xxe":                           dict(severity=0.85, likelihood=0.65, impact=0.85, cvss_score=8.5,  exploit_available=True,  page_criticality=8.5),
    "ssrf":                          dict(severity=0.90, likelihood=0.70, impact=0.90, cvss_score=9.0,  exploit_available=True,  page_criticality=9.0),
    "open_redirect":                 dict(severity=0.55, likelihood=0.70, impact=0.50, cvss_score=5.4,  exploit_available=True,  page_criticality=6.5),

    # ── TLS / Transport ──────────────────────────────────────────────────────
    "http_no_https":                 dict(severity=0.75, likelihood=0.70, impact=0.80, cvss_score=7.5,  exploit_available=False, page_criticality=8.0),
    "mixed_content":                 dict(severity=0.65, likelihood=0.65, impact=0.65, cvss_score=6.5,  exploit_available=False, page_criticality=7.0),
    "tls_deprecated_version":        dict(severity=0.70, likelihood=0.60, impact=0.70, cvss_score=7.0,  exploit_available=True,  page_criticality=7.5),
    "weak_cipher":                   dict(severity=0.65, likelihood=0.55, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.0),

    # ── Cross-Origin Isolation Headers ───────────────────────────────────────
    "coop_missing_or_unsafe":        dict(severity=0.50, likelihood=0.55, impact=0.50, cvss_score=5.0,  exploit_available=False, page_criticality=5.5),
    "coep_missing_or_unsafe":        dict(severity=0.40, likelihood=0.50, impact=0.40, cvss_score=4.0,  exploit_available=False, page_criticality=4.5),
    "corp_missing_or_unsafe":        dict(severity=0.45, likelihood=0.50, impact=0.45, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),

    # ── CSRF ─────────────────────────────────────────────────────────────────
    "csrf_no_token":                 dict(severity=0.75, likelihood=0.70, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    "csrf_weak_token":               dict(severity=0.65, likelihood=0.65, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.5),
    "csrf_token_in_url":             dict(severity=0.60, likelihood=0.65, impact=0.60, cvss_score=6.0,  exploit_available=True,  page_criticality=7.0),

    # ── Cache ────────────────────────────────────────────────────────────────
    "cache_control_missing":         dict(severity=0.45, likelihood=0.70, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.5),
    "cache_explicitly_public":       dict(severity=0.60, likelihood=0.75, impact=0.55, cvss_score=6.0,  exploit_available=False, page_criticality=6.5),
    "cache_missing_private_nostore": dict(severity=0.50, likelihood=0.70, impact=0.45, cvss_score=5.0,  exploit_available=False, page_criticality=6.0),
    "cache_max_age_sensitive":       dict(severity=0.45, likelihood=0.70, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.5),
    "cache_vary_wildcard":           dict(severity=0.40, likelihood=0.65, impact=0.35, cvss_score=4.0,  exploit_available=False, page_criticality=5.0),
    "cache_cookie_on_cacheable":     dict(severity=0.65, likelihood=0.75, impact=0.60, cvss_score=6.5,  exploit_available=False, page_criticality=7.0),
    "cache_legacy_pragma":           dict(severity=0.25, likelihood=0.60, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.0),
    "cache_served_from_cache":       dict(severity=0.55, likelihood=0.75, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "cache_etag_sensitive":          dict(severity=0.25, likelihood=0.65, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.5),
    "cache_s_maxage_sensitive":      dict(severity=0.65, likelihood=0.75, impact=0.60, cvss_score=6.5,  exploit_available=False, page_criticality=7.0),
    "cache_surrogate_control":       dict(severity=0.55, likelihood=0.70, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "cache_cdn_hit_sensitive":       dict(severity=0.70, likelihood=0.80, impact=0.65, cvss_score=7.0,  exploit_available=False, page_criticality=7.5),
    "cache_immutable_sensitive":     dict(severity=0.45, likelihood=0.70, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.5),
    "cache_no_cache_without_nostore":dict(severity=0.30, likelihood=0.65, impact=0.25, cvss_score=3.0,  exploit_available=False, page_criticality=4.0),

    # ── HTML Comments — Information Disclosure ────────────────────────────────
    "comment_sensitive_info":        dict(severity=0.65, likelihood=0.80, impact=0.60, cvss_score=6.5,  exploit_available=False, page_criticality=7.0),
    "comment_dev_marker":            dict(severity=0.25, likelihood=0.70, impact=0.20, cvss_score=2.5,  exploit_available=False, page_criticality=3.0),
    "comment_internal_ip":           dict(severity=0.55, likelihood=0.70, impact=0.50, cvss_score=5.3,  exploit_available=False, page_criticality=6.0),
    "comment_internal_url":          dict(severity=0.55, likelihood=0.70, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "comment_credential_pattern":    dict(severity=0.80, likelihood=0.80, impact=0.80, cvss_score=8.0,  exploit_available=True,  page_criticality=8.5),
    "comment_hidden_endpoint":       dict(severity=0.35, likelihood=0.65, impact=0.30, cvss_score=3.5,  exploit_available=False, page_criticality=4.5),
    "comment_version_disclosure":    dict(severity=0.30, likelihood=0.70, impact=0.25, cvss_score=3.0,  exploit_available=False, page_criticality=3.5),
    "comment_form_field":            dict(severity=0.50, likelihood=0.75, impact=0.45, cvss_score=5.0,  exploit_available=False, page_criticality=5.5),
    "comment_code_block":            dict(severity=0.55, likelihood=0.70, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),

    # ── Content / Page Change Monitoring ─────────────────────────────────────
    "page_content_changed":          dict(severity=0.45, likelihood=0.60, impact=0.45, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "page_new_detected":             dict(severity=0.30, likelihood=0.55, impact=0.30, cvss_score=3.0,  exploit_available=False, page_criticality=4.0),

    "suspicious_external_link":      dict(severity=0.45, likelihood=0.65, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.0),
    "form_external_submission":      dict(severity=0.60, likelihood=0.70, impact=0.55, cvss_score=6.0,  exploit_available=False, page_criticality=6.5),
    "form_external_submission_pw":   dict(severity=0.80, likelihood=0.75, impact=0.80, cvss_score=8.0,  exploit_available=True,  page_criticality=8.5),
    "internal_url_exposed":          dict(severity=0.45, likelihood=0.70, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.5),
    "mixed_content_active":          dict(severity=0.75, likelihood=0.70, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    "robots_sensitive_disallow":     dict(severity=0.45, likelihood=0.75, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.5),
    "robots_sitemap_exposed":        dict(severity=0.30, likelihood=0.75, impact=0.25, cvss_score=3.0,  exploit_available=False, page_criticality=4.0),
    "private_key_exposed":           dict(severity=0.95, likelihood=0.80, impact=0.95, cvss_score=9.5,  exploit_available=True,  page_criticality=9.5),
    "high_entropy_secret":           dict(severity=0.55, likelihood=0.65, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),

    "sitemap_sensitive_path":        dict(severity=0.45, likelihood=0.80, impact=0.40, cvss_score=4.5,  exploit_available=False, page_criticality=5.5),
    "sitemap_staging_domain":        dict(severity=0.55, likelihood=0.75, impact=0.50, cvss_score=5.5,  exploit_available=False, page_criticality=6.0),
    "sitemap_query_params":          dict(severity=0.35, likelihood=0.70, impact=0.30, cvss_score=3.5,  exploit_available=False, page_criticality=4.5),
    "sitemap_large_surface":         dict(severity=0.40, likelihood=0.75, impact=0.35, cvss_score=4.0,  exploit_available=False, page_criticality=5.0),

    "storage_jwt":                   dict(severity=0.65, likelihood=0.70, impact=0.65, cvss_score=6.5,  exploit_available=True,  page_criticality=7.5),
    "storage_sensitive_value":       dict(severity=0.55, likelihood=0.65, impact=0.55, cvss_score=5.5,  exploit_available=False, page_criticality=6.5),

    "ssl_wildcard_cert":             dict(severity=0.40, likelihood=0.60, impact=0.40, cvss_score=4.0,  exploit_available=False, page_criticality=5.0),
    "ssl_cert_expiring":             dict(severity=0.55, likelihood=0.80, impact=0.55, cvss_score=5.5,  exploit_available=False, page_criticality=6.5),
    "ssl_cert_expired":              dict(severity=0.80, likelihood=0.90, impact=0.80, cvss_score=8.0,  exploit_available=True,  page_criticality=8.5),
    "ssl_cert_invalid":              dict(severity=0.75, likelihood=0.85, impact=0.75, cvss_score=7.5,  exploit_available=True,  page_criticality=8.0),
    "session_cookie_no_samesite":    dict(severity=0.60, likelihood=0.70, impact=0.60, cvss_score=6.5,  exploit_available=True,  page_criticality=6.0),
    "csrf_missing":                  dict(severity=0.85, likelihood=0.80, impact=0.85, cvss_score=8.8,  exploit_available=True,  page_criticality=8.0
),    

}


# ─────────────────────────────────────────────────────────────────────────────
# PUBLIC API
# ─────────────────────────────────────────────────────────────────────────────

def build_ai_scores(profile_key: str, url: str) -> dict:
    """
    Return a dict of AI feature kwargs ready to unpack into reporter.report().

    Looks up the base profile, applies the path-sensitivity multiplier,
    and stores the path_tier in a metadata dict (returned separately
    via the '_meta' key — callers merge this into their raw_data).

    Example
    ───────
        scores = build_ai_scores("missing_csp_medium", url)
        await reporter.report(
            page_url   = url,
            title      = "Missing Content-Security-Policy",
            ...
            **scores,
        )

    Returns
    ───────
    {
        severity, likelihood, impact,
        cvss_score, exploit_available, page_criticality,
        _meta: {...}   ← pop and merge into raw_data before unpacking
    }

    Unknown profile_key: all score fields return None, _meta is empty dict.
    build_ai_scores() logs a warning so missing profiles are visible in logs.
    """
    base = PROFILES.get(profile_key)
    if base is None:
        logger_sentinel.warning(
            f"[Scoring] Unknown profile_key '{profile_key}' — all scores will be NULL. "
            "Add the profile to PROFILES in scoring.py."
        )
        return dict(
            severity=None, likelihood=None, impact=None,
            cvss_score=None, exploit_available=None, page_criticality=None,
            _meta={},
        )

    multiplier = get_path_multiplier(url)
    scored     = _apply(base, multiplier)

    scored["_meta"] = {
        "scoring_profile":    profile_key,
        "path_tier":          get_path_tier_name(url),
        "path_multiplier":    multiplier,
        "base_cvss":          base["cvss_score"],
        "adjusted_cvss":      scored["cvss_score"],
    }

    return scored


def cvss_to_severity_band(cvss: Optional[float]) -> str:
    """
    CVSS v3.1 severity band label.
    Useful for logging and evidence dicts.
    """
    if cvss is None:
        return "unknown"
    if cvss >= 9.0:
        return "critical"
    if cvss >= 7.0:
        return "high"
    if cvss >= 4.0:
        return "medium"
    return "low"


# Module-level logger used inside build_ai_scores for unknown profile warnings.
import logging as _logging
logger_sentinel = _logging.getLogger("webxguard.scoring")