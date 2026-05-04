"""
backend/Scanner/scanner/alerts/email_sender.py
==============================================
Sends security-alert emails to users.

Why not Flask-Mail?
-------------------
Flask-Mail needs `current_app` + Flask app context. Our alert code runs in
3 different contexts:
    - FastAPI request handlers (no Flask context)
    - asyncpg connections in lifespan
    - psycopg2 + threadpool from monitoring engines (no Flask context)

So we use plain `smtplib` directly — same SMTP creds from .env, no Flask
dependency, callable from any context, sync or async.

Flow
----
1. Alert created in DB by alerts.manager
2. After insert, we call try_send_email_for_alert_sync() / _async()
3. It checks user prefs + rate limit → sends → updates alerts.email_sent
4. All errors swallowed (alert creation must never fail because of email)

Rate limit
----------
1 email per (user_id, domain) per hour, regardless of severity. Prevents
inbox flooding when posture engine fires every cycle.

Templates
---------
HTML email with severity-color header, finding details, "View Dashboard"
CTA. Plain-text fallback for clients that don't render HTML.
"""
from __future__ import annotations

import logging
import os
import smtplib
import ssl
from contextlib import contextmanager
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from typing import Any
from urllib.parse import urlparse

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("webxguard.alerts.email")


# ─────────────────────────────────────────────────────────────────────────────
# Config from .env
# ─────────────────────────────────────────────────────────────────────────────

SMTP_HOST = os.getenv("MAIL_SERVER",   "smtp.gmail.com")
SMTP_PORT = int(os.getenv("MAIL_PORT", "587"))
SMTP_TLS  = (os.getenv("MAIL_USE_TLS", "True").lower() == "true")
SMTP_USER = os.getenv("MAIL_USERNAME", "")
SMTP_PASS = os.getenv("MAIL_PASSWORD", "")
SMTP_FROM = os.getenv("MAIL_DEFAULT_SENDER") or SMTP_USER or "noreply@webxguard.local"

FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5173").rstrip("/")
APP_NAME     = os.getenv("APP_NAME",     "WebXGuard")

# DSN reuse from alerts.manager pattern
_DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:5353@127.0.0.1:5432/Webxguard",
)


def _pg_kwargs() -> dict:
    p = urlparse(_DATABASE_URL)
    return {
        "host":     p.hostname or "localhost",
        "port":     p.port     or 5432,
        "database": (p.path or "/Webxguard").lstrip("/"),
        "user":     p.username or "postgres",
        "password": p.password or "",
    }


@contextmanager
def _conn():
    c = psycopg2.connect(**_pg_kwargs())
    try:
        yield c
    finally:
        try:
            c.close()
        except Exception:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Severity → color (used in HTML template)
# ─────────────────────────────────────────────────────────────────────────────

_SEVERITY_COLORS = {
    "Critical": ("#dc2626", "#fee2e2"),  # (border/text, bg)
    "High":     ("#ea580c", "#ffedd5"),
    "Medium":   ("#d97706", "#fef3c7"),
    "Low":      ("#2563eb", "#dbeafe"),
    "Info":     ("#475569", "#f1f5f9"),
}


def _severity_priority(sev: str) -> int:
    """Critical=4, High=3, Medium=2, Low=1, Info=0 — used for threshold check."""
    return {
        "Critical": 4, "High": 3, "Medium": 2, "Low": 1, "Info": 0,
    }.get(sev, 0)


# ─────────────────────────────────────────────────────────────────────────────
# User preferences + rate limit
# ─────────────────────────────────────────────────────────────────────────────

def _get_user_prefs_sync(user_id: int) -> dict:
    """Return prefs dict (with defaults if user has no row)."""
    defaults = {"email_enabled": True, "min_severity": "High", "email": None}
    try:
        with _conn() as c:
            cur = c.cursor(cursor_factory=RealDictCursor)
            cur.execute(
                """
                SELECT u.email,
                       COALESCE(p.email_enabled, TRUE)  AS email_enabled,
                       COALESCE(p.min_severity, 'High') AS min_severity
                FROM   users u
                LEFT   JOIN user_notification_preferences p
                       ON p.user_id = u.id
                WHERE  u.id = %s
                """,
                (user_id,),
            )
            row = cur.fetchone()
            cur.close()
            if not row:
                return defaults
            return {
                "email":         row.get("email"),
                "email_enabled": bool(row.get("email_enabled", True)),
                "min_severity":  row.get("min_severity") or "High",
            }
    except Exception as e:
        logger.warning("[EmailAlerts] prefs lookup failed for user=%s: %s", user_id, e)
        return defaults


def _hit_rate_limit_sync(user_id: int, domain: str, hours: int = 1) -> bool:
    """Return True if we've already sent an email to this user for this domain
    in the last `hours` hours."""
    try:
        with _conn() as c:
            cur = c.cursor()
            cur.execute(
                """
                SELECT 1 FROM alerts
                WHERE  user_id   = %s
                  AND  domain    = %s
                  AND  email_sent = TRUE
                  AND  email_sent_at >= NOW() - (%s || ' hours')::INTERVAL
                LIMIT 1
                """,
                (user_id, domain, str(hours)),
            )
            hit = cur.fetchone() is not None
            cur.close()
            return hit
    except Exception as e:
        logger.warning("[EmailAlerts] rate-limit check failed: %s", e)
        return False  # fail open — email allowed


def _mark_emailed_sync(alert_id: int, error: str | None = None) -> None:
    """Update alerts row with email status."""
    try:
        with _conn() as c:
            cur = c.cursor()
            if error:
                cur.execute(
                    """
                    UPDATE alerts
                    SET    email_sent     = FALSE,
                           email_sent_at  = NOW(),
                           email_error    = %s
                    WHERE  id = %s
                    """,
                    (error[:500], alert_id),
                )
            else:
                cur.execute(
                    """
                    UPDATE alerts
                    SET    email_sent     = TRUE,
                           email_sent_at  = NOW(),
                           email_error    = NULL
                    WHERE  id = %s
                    """,
                    (alert_id,),
                )
            c.commit()
            cur.close()
    except Exception as e:
        logger.warning("[EmailAlerts] mark_emailed failed: %s", e)


# ─────────────────────────────────────────────────────────────────────────────
# Email templates
# ─────────────────────────────────────────────────────────────────────────────

def _build_html(alert: dict) -> str:
    sev = str(alert.get("severity") or "Info")
    color, bg = _SEVERITY_COLORS.get(sev, _SEVERITY_COLORS["Info"])
    title = str(alert.get("title") or "Security alert")
    desc  = str(alert.get("description") or "")
    domain = str(alert.get("domain") or "")
    src    = str(alert.get("source")  or "scan")
    link   = f"{FRONTEND_URL}/dashboard/alerts"

    return f"""
<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#0f172a;font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#e2e8f0;">
  <div style="max-width:600px;margin:0 auto;padding:24px;">
    <div style="background:#1e293b;border:1px solid #334155;border-radius:14px;overflow:hidden;">

      <div style="padding:24px 28px;border-bottom:4px solid {color};background:{bg};">
        <div style="font-size:12px;letter-spacing:1px;color:{color};font-weight:700;">
          {APP_NAME.upper()} · {sev.upper()} ALERT
        </div>
        <div style="font-size:20px;color:#0f172a;font-weight:700;margin-top:6px;">
          {title}
        </div>
      </div>

      <div style="padding:24px 28px;">
        <p style="margin:0 0 12px 0;color:#94a3b8;font-size:13px;">
          A new {sev.lower()}-severity finding was detected on
          <strong style="color:#e2e8f0;">{domain}</strong>.
        </p>

        {f'<p style="margin:0 0 18px 0;color:#cbd5e1;font-size:14px;line-height:1.55;">{desc}</p>' if desc else ''}

        <table cellpadding="0" cellspacing="0" border="0" style="width:100%;font-size:13px;">
          <tr><td style="padding:6px 0;color:#64748b;width:120px;">Source</td>
              <td style="padding:6px 0;color:#cbd5e1;">{src}</td></tr>
          <tr><td style="padding:6px 0;color:#64748b;">Severity</td>
              <td style="padding:6px 0;"><span style="display:inline-block;padding:2px 10px;border-radius:6px;background:{bg};color:{color};font-weight:600;">{sev}</span></td></tr>
          <tr><td style="padding:6px 0;color:#64748b;">Domain</td>
              <td style="padding:6px 0;color:#cbd5e1;font-family:Menlo,Consolas,monospace;">{domain}</td></tr>
        </table>

        <div style="margin-top:24px;">
          <a href="{link}"
             style="display:inline-block;padding:12px 22px;background:#10b981;color:#0f172a;text-decoration:none;border-radius:10px;font-weight:600;font-size:14px;">
            View in Dashboard →
          </a>
        </div>
      </div>

      <div style="padding:16px 28px;background:#0f172a;border-top:1px solid #334155;font-size:11px;color:#64748b;">
        You are receiving this because security alerts are enabled for your account.
        <a href="{FRONTEND_URL}/dashboard/settings" style="color:#10b981;text-decoration:none;">Manage preferences</a>
      </div>
    </div>
    <div style="text-align:center;font-size:11px;color:#475569;margin-top:14px;">
      © {APP_NAME} · Continuous web security monitoring
    </div>
  </div>
</body></html>"""


def _build_plain(alert: dict) -> str:
    sev    = str(alert.get("severity")    or "Info")
    title  = str(alert.get("title")       or "Security alert")
    desc   = str(alert.get("description") or "")
    domain = str(alert.get("domain")      or "")
    src    = str(alert.get("source")      or "scan")
    link   = f"{FRONTEND_URL}/dashboard/alerts"

    body  = f"[{sev.upper()}] {title}\n\n"
    body += f"Domain:   {domain}\n"
    body += f"Source:   {src}\n\n"
    if desc:
        body += desc + "\n\n"
    body += f"View in dashboard: {link}\n\n"
    body += f"--\n{APP_NAME}"
    return body


# ─────────────────────────────────────────────────────────────────────────────
# SMTP send
# ─────────────────────────────────────────────────────────────────────────────

def _send_smtp(to: str, subject: str, html: str, plain: str) -> str | None:
    """Send via SMTP. Returns None on success, error string on failure."""
    if not SMTP_USER or not SMTP_PASS:
        return "SMTP credentials not configured (.env MAIL_USERNAME/MAIL_PASSWORD)"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = SMTP_FROM
    msg["To"]      = to
    msg.attach(MIMEText(plain, "plain", "utf-8"))
    msg.attach(MIMEText(html,  "html",  "utf-8"))

    try:
        if SMTP_PORT == 465:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, context=ctx, timeout=15) as s:
                s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_FROM, [to], msg.as_string())
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as s:
                s.ehlo()
                if SMTP_TLS:
                    s.starttls(context=ssl.create_default_context())
                    s.ehlo()
                s.login(SMTP_USER, SMTP_PASS)
                s.sendmail(SMTP_FROM, [to], msg.as_string())
        return None
    except Exception as e:
        return str(e)


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def try_send_email_for_alert_sync(alert: dict) -> bool:
    """
    Best-effort: send an email for one alert dict.
      `alert` should contain: id, user_id, severity, title, description,
                              domain, source.
    Returns True if email actually sent, False otherwise.
    Never raises — alert creation must never break.
    """
    alert_id = alert.get("id")
    user_id  = alert.get("user_id")
    sev      = alert.get("severity") or "Info"
    domain   = alert.get("domain")   or ""

    if not user_id:
        return False  # system-level alert (no user_id) — no recipient

    prefs = _get_user_prefs_sync(int(user_id))
    if not prefs.get("email"):
        logger.debug("[EmailAlerts] no email on file for user=%s", user_id)
        return False
    if not prefs.get("email_enabled"):
        return False

    threshold = prefs.get("min_severity", "High")
    if _severity_priority(sev) < _severity_priority(threshold):
        return False

    if domain and _hit_rate_limit_sync(int(user_id), domain, hours=1):
        logger.info(
            "[EmailAlerts] rate-limited  user=%s  domain=%s", user_id, domain,
        )
        return False

    subject = f"[{sev}] {alert.get('title', 'Security alert')[:120]}"
    html    = _build_html(alert)
    plain   = _build_plain(alert)

    err = _send_smtp(prefs["email"], subject, html, plain)

    if alert_id:
        _mark_emailed_sync(int(alert_id), error=err)

    if err is None:
        logger.info(
            "[EmailAlerts] ✓ sent  user=%s  to=%s  sev=%s",
            user_id, prefs["email"], sev,
        )
        return True
    else:
        logger.warning(
            "[EmailAlerts] send failed  user=%s  err=%s",
            user_id, err,
        )
        return False


async def try_send_email_for_alert_async(alert: dict) -> bool:
    """
    Async wrapper — runs the sync sender in a thread executor so the
    FastAPI event loop isn't blocked by SMTP.
    """
    import asyncio
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, try_send_email_for_alert_sync, alert)