import ssl
import socket
import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import urlparse

from ..scoring import build_ai_scores

logger = logging.getLogger("webxguard.ssl_tls")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────

CERT_EXPIRY_CRITICAL_DAYS = 7
CERT_EXPIRY_WARNING_DAYS  = 30
CERT_EXPIRY_NOTICE_DAYS   = 60

WEAK_CIPHERS: frozenset[str] = frozenset({
    "rc4", "des", "3des", "md5", "null", "anon", "export"
})

MAX_SNIPPET_LEN = 200

# ─────────────────────────────────────────────────────────────────────────────
# REFERENCES
# ─────────────────────────────────────────────────────────────────────────────

REF_CERT   = "https://owasp.org/www-community/vulnerabilities/Improper_Certificate_Validation"
REF_CIPHER = "https://owasp.org/www-community/vulnerabilities/Use_of_Weak_TLS_Cipher_Suites"
REF_CRYPTO = "https://bettercrypto.org/"
REF_HTTP   = (
    "https://owasp.org/www-project-web-security-testing-guide/latest"
    "/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography"
    "/01-Testing_for_Weak_Transport_Layer_Security"
)
REF_HSTS   = (
    "https://cheatsheetseries.owasp.org/cheatsheets"
    "/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────

def _snip(text: str) -> str:
    return str(text)[:MAX_SNIPPET_LEN] if text else ""


# ─────────────────────────────────────────────────────────────────────────────
# BLOCKING SSL PROBE
# Returns a list of finding dicts — never calls reporter directly.
# Each dict carries a `profile_key` field so the async reporter loop
# can call build_ai_scores() correctly per finding.
# ─────────────────────────────────────────────────────────────────────────────

def _probe_ssl(hostname: str, port: int) -> list[dict]:
    """
    Perform all SSL/TLS checks synchronously in a thread executor.
    Returns finding dicts — never raises.
    """
    findings: list[dict] = []

    def finding(
        title:       str,
        confidence:  str,
        evidence:    dict,
        profile_key: str,
        cwe:         str,
        wasc:        str,
        reference:   str,
    ) -> None:
        findings.append({
            "title":       title,
            "confidence":  confidence,
            "evidence":    evidence,
            "profile_key": profile_key,   # ← carries scoring identity to async loop
            "cwe":         cwe,
            "wasc":        wasc,
            "reference":   reference,
        })

    # ── Main TLS connection ───────────────────────────────────────────────
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode    = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert        = ssock.getpeercert()
                cipher      = ssock.cipher()       # (name, protocol, bits)
                tls_version = ssock.version()      # e.g. "TLSv1.3"

                # ── Certificate validity window ───────────────────────────
                not_before_raw = cert.get("notBefore")
                not_after_raw  = cert.get("notAfter")

                if not_before_raw:
                    try:
                        not_before = datetime.strptime(
                            not_before_raw, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        if not_before > datetime.now(timezone.utc):
                            finding(
                                "SSL Certificate Not Yet Valid",
                                "high",
                                {
                                    "not_before": not_before.isoformat(),
                                    "reason":     "Certificate validity has not started yet",
                                },
                                profile_key = "ssl_cert_invalid",
                                cwe         = "CWE-295",
                                wasc        = "WASC-4",
                                reference   = REF_CERT,
                            )
                    except Exception:
                        pass

                if not_after_raw:
                    try:
                        expiry    = datetime.strptime(
                            not_after_raw, "%b %d %H:%M:%S %Y %Z"
                        ).replace(tzinfo=timezone.utc)
                        days_left = (expiry - datetime.now(timezone.utc)).days

                        if days_left <= 0:
                            finding(
                                "SSL Certificate Expired",
                                "high",
                                {"expiry_date": expiry.isoformat(), "days_left": days_left},
                                profile_key = "ssl_cert_expired",
                                cwe         = "CWE-295",
                                wasc        = "WASC-4",
                                reference   = REF_CERT,
                            )
                        elif days_left <= CERT_EXPIRY_CRITICAL_DAYS:
                            finding(
                                "SSL Certificate Expiring Within 7 Days",
                                "high",
                                {"expiry_date": expiry.isoformat(), "days_left": days_left},
                                profile_key = "ssl_cert_expiring",
                                cwe         = "CWE-295",
                                wasc        = "WASC-4",
                                reference   = REF_CERT,
                            )
                        elif days_left <= CERT_EXPIRY_WARNING_DAYS:
                            finding(
                                "SSL Certificate Expiring Soon",
                                "medium",
                                {"expiry_date": expiry.isoformat(), "days_left": days_left},
                                profile_key = "ssl_cert_expiring",
                                cwe         = "CWE-295",
                                wasc        = "WASC-4",
                                reference   = REF_CERT,
                            )
                        elif days_left <= CERT_EXPIRY_NOTICE_DAYS:
                            finding(
                                "SSL Certificate Expiring Within 60 Days",
                                "medium",
                                {"expiry_date": expiry.isoformat(), "days_left": days_left},
                                profile_key = "ssl_cert_expiring",
                                cwe         = "CWE-295",
                                wasc        = "WASC-4",
                                reference   = REF_CERT,
                            )
                    except Exception:
                        pass

                # ── Wildcard certificate ──────────────────────────────────
                wildcard_names = [
                    v for t, v in cert.get("subjectAltName", [])
                    if t == "DNS" and v.startswith("*.")
                ]
                if wildcard_names:
                    finding(
                        "Wildcard SSL Certificate Detected",
                        "medium",
                        {
                            "wildcard_names": wildcard_names,
                            "reason":         "Wildcard certs cover all subdomains — compromise affects all",
                        },
                        profile_key = "ssl_wildcard_cert",
                        cwe         = "CWE-295",
                        wasc        = "WASC-4",
                        reference   = REF_CERT,
                    )

                # ── Weak TLS version (negotiated) ─────────────────────────
                if tls_version in ("TLSv1", "TLSv1.1"):
                    finding(
                        "Weak TLS Version Negotiated",
                        "high",
                        {
                            "tls_version": tls_version,
                            "reason":      f"{tls_version} is deprecated (POODLE/BEAST)",
                        },
                        profile_key = "tls_deprecated_version",
                        cwe         = "CWE-326",
                        wasc        = "WASC-4",
                        reference   = REF_CIPHER,
                    )

                # ── Weak cipher suite ─────────────────────────────────────
                if cipher:
                    cipher_name = cipher[0].lower()
                    if any(w in cipher_name for w in WEAK_CIPHERS):
                        finding(
                            "Weak SSL Cipher Suite Negotiated",
                            "high",
                            {
                                "cipher":   cipher[0],
                                "protocol": cipher[1],
                                "key_bits": cipher[2],
                                "reason":   "Cipher suite provides insufficient cryptographic strength",
                            },
                            profile_key = "weak_cipher",
                            cwe         = "CWE-326",
                            wasc        = "WASC-4",
                            reference   = REF_CIPHER,
                        )

                    # Forward secrecy absent — TLS 1.3 always uses ECDHE
                    # so skip to avoid false positives
                    is_tls13 = tls_version == "TLSv1.3"
                    if not is_tls13 and not any(
                        fs in cipher_name for fs in ("ecdhe", "dhe")
                    ):
                        finding(
                            "SSL Cipher Without Forward Secrecy",
                            "medium",
                            {
                                "cipher":      cipher[0],
                                "tls_version": tls_version,
                                "reason":      "Non-ECDHE/DHE cipher does not provide forward secrecy",
                            },
                            profile_key = "weak_cipher",
                            cwe         = "CWE-326",
                            wasc        = "WASC-4",
                            reference   = REF_CRYPTO,
                        )

    except ssl.SSLCertVerificationError as e:
        err = str(e).lower()
        if "self signed" in err or "self-signed" in err:
            finding(
                "Self-Signed SSL Certificate",
                "high",
                {"reason": _snip(str(e))},
                profile_key = "ssl_cert_invalid",
                cwe         = "CWE-295",
                wasc        = "WASC-4",
                reference   = REF_CERT,
            )
        elif "hostname" in err or "does not match" in err:
            finding(
                "SSL Certificate Hostname Mismatch",
                "high",
                {"reason": _snip(str(e))},
                profile_key = "ssl_cert_invalid",
                cwe         = "CWE-297",
                wasc        = "WASC-4",
                reference   = "https://cwe.mitre.org/data/definitions/297.html",
            )
        elif "expired" in err:
            finding(
                "SSL Certificate Expired",
                "high",
                {"reason": _snip(str(e))},
                profile_key = "ssl_cert_expired",
                cwe         = "CWE-295",
                wasc        = "WASC-4",
                reference   = REF_CERT,
            )
        elif "unable to get local issuer" in err or "certificate verify failed" in err:
            finding(
                "SSL Certificate Chain Validation Failed",
                "high",
                {"reason": _snip(str(e))},
                profile_key = "ssl_cert_invalid",
                cwe         = "CWE-295",
                wasc        = "WASC-4",
                reference   = REF_CERT,
            )
        else:
            finding(
                "SSL Certificate Validation Error",
                "medium",
                {"reason": _snip(str(e))},
                profile_key = "ssl_cert_invalid",
                cwe         = "CWE-295",
                wasc        = "WASC-4",
                reference   = REF_CERT,
            )

    except ssl.SSLError as e:
        finding(
            "SSL Handshake Failed",
            "high",
            {"reason": _snip(str(e))},
            profile_key = "tls_deprecated_version",
            cwe         = "CWE-326",
            wasc        = "WASC-4",
            reference   = REF_CIPHER,
        )

    except socket.timeout:
        logger.debug(f"[SSL] Connection timed out for {hostname}:{port}")

    except Exception as e:
        logger.debug(f"[SSL] Probe error for {hostname}:{port}: {e}")

    # ── Probe: does server accept TLS 1.0 / 1.1? ─────────────────────────
    for old_label, old_attr in (
        ("TLSv1",   "TLSv1"),
        ("TLSv1.1", "TLSv1_1"),
    ):
        tls_version_enum = getattr(
            getattr(ssl, "TLSVersion", None), old_attr, None
        )
        if tls_version_enum is None:
            continue

        try:
            probe_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            probe_ctx.check_hostname  = False
            probe_ctx.verify_mode     = ssl.CERT_NONE
            probe_ctx.minimum_version = tls_version_enum
            probe_ctx.maximum_version = tls_version_enum

            with socket.create_connection((hostname, port), timeout=5) as ps:
                with probe_ctx.wrap_socket(ps, server_hostname=hostname):
                    finding(
                        "Legacy TLS Version Accepted by Server",
                        "high",
                        {
                            "tls_version": old_label,
                            "reason":      f"Server accepted {old_label} — should be disabled",
                        },
                        profile_key = "tls_deprecated_version",
                        cwe         = "CWE-326",
                        wasc        = "WASC-4",
                        reference   = REF_HTTP,
                    )
        except Exception:
            pass  # Server correctly rejected it

    # ── Probe: HTTP port 80 accessible without HTTPS redirect? ───────────
    try:
        with socket.create_connection((hostname, 80), timeout=4) as http_sock:
            http_sock.sendall(
                f"GET / HTTP/1.1\r\nHost: {hostname}\r\nConnection: close\r\n\r\n"
                .encode()
            )
            resp = http_sock.recv(512).decode("utf-8", errors="ignore")

        if resp.startswith("HTTP/") and not any(
            code in resp for code in (" 301 ", " 302 ", " 308 ")
        ):
            status_line = resp.split("\r\n")[0]
            finding(
                "HTTP Port 80 Accessible Without HTTPS Redirect",
                "high",
                {
                    "hostname":    hostname,
                    "status_line": _snip(status_line),
                    "reason":      "Server responds on HTTP without redirecting to HTTPS",
                },
                profile_key = "http_no_https",
                cwe         = "CWE-319",
                wasc        = "WASC-4",
                reference   = REF_HSTS,
            )
    except Exception:
        pass  # Port 80 not open — fine

    return findings


# ─────────────────────────────────────────────────────────────────────────────
# ASYNC ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

async def analyze_ssl_tls(
    entry:         dict,
    reporter,
    page_id:       Optional[int] = None,
    session_cache: Optional[set] = None,
) -> None:
    """
    Run a full SSL/TLS probe against the host in `entry["url"]` and
    report all findings.

    Parameters
    ──────────
    entry          — any network event with a populated "url" field.
    reporter       — Reporter instance (webxguard.reporter.Reporter).
    page_id        — pages.id FK forwarded to reporter.
    session_cache  — caller-supplied set for per-session hostname dedup.
                     If None a module-level fallback is used (less safe
                     in long-running multi-session processes).
    """
    url = entry.get("url", "")
    if not url:
        return

    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return

    hostname = parsed.hostname
    port     = parsed.port or 443

    if not hostname:
        return

    # Per-session dedup — one SSL probe per hostname per scan session
    cache = session_cache if session_cache is not None else _SESSION_FALLBACK_CACHE
    if hostname in cache:
        return
    cache.add(hostname)

    try:
        loop     = asyncio.get_running_loop()   # 3.10+-safe; replaces get_event_loop()
        findings = await loop.run_in_executor(
            None, _probe_ssl, hostname, port
        )
    except Exception as e:
        logger.warning(f"[SSL] Executor failed for {hostname}: {e}")
        return

    base_url = f"https://{hostname}"

    for f in findings:
        try:
            profile_key = f.pop("profile_key", None)
            scores      = build_ai_scores(profile_key, base_url) if profile_key else {}
            meta        = scores.pop("_meta", {})

            await reporter.report(
                page_url   = base_url,
                title      = f["title"],
                category   = "ssl_tls",
                confidence = f["confidence"],
                page_id    = page_id,
                evidence   = f["evidence"],
                raw_data   = {
                    "hostname": hostname,
                    "port":     port,
                    **meta,
                },
                cwe       = f["cwe"],
                wasc      = f["wasc"],
                reference = f["reference"],
                dedup_key = (base_url, f["title"], "ssl_tls"),
                **scores,
            )
        except Exception as e:
            logger.error(f"[SSL] reporter.report failed for '{f.get('title')}': {e}")


# Module-level fallback cache — only used when no session_cache is passed.
# Callers should prefer passing an explicit set scoped to the scan session.
_SESSION_FALLBACK_CACHE: set[str] = set()