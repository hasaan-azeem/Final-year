"""
backend/Scanner/app.py

WebXGuard FastAPI scanner. Saari endpoints idhar hain:
  - Scan kick off + status + results + report (CSV)
  - Scan history per user
  - Dashboard stats (KPI, weekly chart, breakdown, recent scans)
  - Continuous monitoring (add/remove sites, list)
  - Crawler queue live feed

★ NEW (real-time additions):
  - extras_router mount: alerts, compliance, predictive, crawler endpoints
  - Auto-alert hook on scan completion (Critical/High findings)

Auth: har protected endpoint Authorization: Bearer <JWT> expect karta hai.
JWT same secret use karta hai jo Flask wala (env: JWT_SECRET_KEY).

Run from backend/ folder:
    uvicorn Scanner.app:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import sys
import asyncio
import logging
import uuid
import io
import csv
from contextlib import asynccontextmanager
from typing import Dict, Optional
from urllib.parse import urlparse
from datetime import datetime

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())

import uvicorn
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# JWT helper from sibling app/ package (Flask auth side)
from app.auth_jwt import get_current_user_id

# Scanner submodules (relative imports inside Scanner/scanner/)
from .scanner.db import init_db, close_db, fetch, fetchrow, execute
from .scanner.main import main as run_scan_pipeline
from .scanner.repositories.sessions import (
    session_belongs_to_user,
    get_user_scan_sessions,
)
from .scanner.repositories.monitored_sites import (
    add_monitored_site,
    remove_monitored_site,
    get_user_monitored_sites,
    update_site_session,
)

# ★ NEW — extras router (alerts / compliance / predictive / crawler)
from .extras_routes import router as extras_router

# ★ NEW — alert hook for scan completion
from .scanner.alerts import alert_from_scan_completion_async

logger = logging.getLogger("webxguard.api")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s",
)

# In-memory live progress tracker (status + message). DB me final result jaata hai.
# { session_id: { status, message, url, error } }
_scans: Dict[str, dict] = {}


# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    logger.info("[API] DB pool ready")
    yield
    await close_db()
    logger.info("[API] DB pool closed")


app = FastAPI(title="WebXGuard API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # dev
    allow_methods=["*"],
    allow_headers=["*"],
)

# ★ NEW — mount extras router (/api/alerts, /api/compliance, /api/predictive, /api/scan/crawler)
app.include_router(extras_router)


# ─── Pydantic models ──────────────────────────────────────────────────────────

class LoginConfig(BaseModel):
    login_enabled:    bool          = False
    auth_type:        Optional[str] = None
    login_url:        Optional[str] = None
    login_username:   Optional[str] = None
    login_password:   Optional[str] = None
    login_user_field: Optional[str] = None
    login_pass_field: Optional[str] = None


class ScanRequest(BaseModel):
    url: str
    login_enabled:    bool          = False
    auth_type:        Optional[str] = None
    login_url:        Optional[str] = None
    login_username:   Optional[str] = None
    login_password:   Optional[str] = None
    login_user_field: Optional[str] = None
    login_pass_field: Optional[str] = None

    def login_config(self) -> LoginConfig:
        return LoginConfig(
            login_enabled    = self.login_enabled,
            auth_type        = self.auth_type,
            login_url        = self.login_url,
            login_username   = self.login_username,
            login_password   = self.login_password,
            login_user_field = self.login_user_field,
            login_pass_field = self.login_pass_field,
        )


class AddSiteRequest(BaseModel):
    url: str


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _domain_from_url(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def _security_score(critical: int, high: int, medium: int, low: int) -> int:
    """100 = perfect, 0 = worst. Critical/High zyada count zyada penalty."""
    return max(0, 100 - critical * 15 - high * 8 - medium * 3 - low * 1)


async def _ensure_session_owned(session_id: str, user_id: int) -> None:
    """Session is logged-in user ki ho, warna 404 (info leak avoid karne k liye)."""
    if not await session_belongs_to_user(session_id, user_id):
        raise HTTPException(status_code=404, detail="Session not found")


# ─── Background scan task ─────────────────────────────────────────────────────

async def _run_scan_bg(
    session_id:   str,
    url:          str,
    login_config: LoginConfig,
    user_id:      int,
    site_id:      int | None = None,   # set when started from /api/monitor/sites
) -> None:
    _scans[session_id]["status"]  = "running"
    _scans[session_id]["message"] = "Initializing Scanner"

    # Status callback updates _scans[message] live so frontend loader steps work.
    # main.py bhi yeh accept karta hai (we updated it).
    def status_cb(msg: str):
        if session_id in _scans:
            _scans[session_id]["message"] = msg

    try:
        await run_scan_pipeline(
            start_url       = url,
            session_id      = session_id,
            login_config    = login_config,
            user_id         = user_id,
            status_callback = status_cb,
        )
        _scans[session_id]["status"]  = "complete"
        _scans[session_id]["message"] = "Scan complete"

        # Agar yeh monitor flow se aaya tha to monitored_sites update karein
        if site_id:
            await update_site_session(site_id, session_id)

        # ★ NEW — auto-alert generation on scan completion
        # Critical/High findings DB me likhe ja chuke hain → alerts banao user ke liye
        try:
            domain = _domain_from_url(url)
            count  = await alert_from_scan_completion_async(
                user_id    = user_id,
                session_id = session_id,
                domain     = domain,
            )
            if count:
                logger.info(
                    "[API] Scan-completion alerts: %d created  session=%s",
                    count, session_id,
                )
        except Exception as e:
            logger.warning("[API] Scan-completion alert hook failed: %s", e)

        logger.info("[API] Scan complete session=%s", session_id)

    except Exception as exc:
        _scans[session_id]["status"]  = "failed"
        _scans[session_id]["error"]   = str(exc)
        _scans[session_id]["message"] = "Scan failed"
        logger.error("[API] Scan failed session=%s: %s", session_id, exc, exc_info=True)


# ═════════════════════════════════════════════════════════════════════════════
# SCAN ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.post("/api/scan", status_code=202)
async def start_scan(
    body:    ScanRequest,
    user_id: int = Depends(get_current_user_id),
):
    url        = body.url.strip().rstrip("/")
    session_id = str(uuid.uuid4())
    login_cfg  = body.login_config()

    # DB me row fauran insert karein (poll + history k liye useful)
    await execute(
        """
        INSERT INTO scan_sessions (id, status, started_at, user_id, url, scan_type)
        VALUES ($1::uuid, 'pending', NOW(), $2, $3, 'standard')
        ON CONFLICT (id) DO NOTHING
        """,
        session_id, user_id, url,
    )

    _scans[session_id] = {
        "status":  "pending",
        "url":     url,
        "error":   None,
        "message": "Scan queued",
    }

    asyncio.create_task(_run_scan_bg(session_id, url, login_cfg, user_id))

    logger.info("[API] Scan queued session=%s user=%s url=%s", session_id, user_id, url)
    return {
        "session_id": session_id,
        "status":     "pending",
        "message":    f"Scan queued for {url}",
    }


@app.get("/api/scan/{session_id}")
async def get_scan_status(
    session_id: str,
    user_id:    int = Depends(get_current_user_id),
):
    """Live status (memory me) + DB fallback for after-restart cases."""
    await _ensure_session_owned(session_id, user_id)

    scan = _scans.get(session_id)
    if scan:
        return {
            "session_id": session_id,
            "url":        scan["url"],
            "status":     scan["status"],
            "message":    scan.get("message", ""),
            "error":      scan.get("error"),
        }

    # Memory me nahi to DB se status pull karein
    row = await fetchrow(
        "SELECT id::text AS id, url, status FROM scan_sessions WHERE id = $1::uuid",
        session_id,
    )
    if not row:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": row["id"],
        "url":        row["url"],
        "status":     row["status"],
        "message":    row["status"],
        "error":      None,
    }


@app.get("/api/scan/results/{session_id}")
async def get_scan_results(
    session_id: str,
    user_id:    int = Depends(get_current_user_id),
):
    """Saari vulnerabilities for one scan (severity desc)."""
    await _ensure_session_owned(session_id, user_id)

    rows = await fetch(
        """
        SELECT
            id,
            page_url,
            title,
            category,
            confidence,
            cwe,
            wasc,
            reference,
            severity,
            likelihood,
            impact,
            cvss_score,
            exploit_available,
            page_criticality,
            severity_level,
            target_priority,
            priority_category,
            created_at
        FROM   vulnerabilities
        WHERE  session_id = $1::uuid
        ORDER  BY COALESCE(target_priority, cvss_score, 0) DESC, id ASC
        """,
        session_id,
    )
    return [dict(r) for r in rows]


@app.get("/api/scan/crawler-queue/{session_id}")
async def get_crawler_queue(
    session_id: str,
    user_id:    int = Depends(get_current_user_id),
):
    await _ensure_session_owned(session_id, user_id)

    rows = await fetch(
        """
        SELECT id, url, depth, status
        FROM   crawler_queue
        WHERE  session_id = $1::uuid
        ORDER  BY updated_at DESC
        LIMIT  20
        """,
        session_id,
    )
    return list(reversed([dict(r) for r in rows]))


@app.get("/api/scan/report/{session_id}")
async def download_report(
    session_id: str,
    user_id:    int = Depends(get_current_user_id),
):
    """Scan vulnerabilities ki CSV download."""
    await _ensure_session_owned(session_id, user_id)

    rows = await fetch(
        """
        SELECT page_url, title, category, confidence, cwe,
               severity, cvss_score, severity_level, target_priority,
               priority_category, created_at
        FROM   vulnerabilities
        WHERE  session_id = $1::uuid
        ORDER  BY COALESCE(target_priority, cvss_score, 0) DESC
        """,
        session_id,
    )

    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow([
        "Page URL", "Title", "Category", "Confidence", "CWE",
        "Severity", "CVSS", "Severity Level", "Risk Score",
        "Risk Category", "Found At",
    ])
    for r in rows:
        writer.writerow([
            r["page_url"], r["title"], r["category"], r["confidence"], r["cwe"] or "",
            r["severity"] or "", r["cvss_score"] or "", r["severity_level"] or "",
            r["target_priority"] or "", r["priority_category"] or "",
            r["created_at"].isoformat() if r["created_at"] else "",
        ])

    buf.seek(0)
    filename = f"webxguard-report-{session_id[:8]}.csv"
    return StreamingResponse(
        iter([buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scans/history")
async def scans_history(
    user_id: int = Depends(get_current_user_id),
):
    """User ki saari scans + score + counts. Vulnerability page yeh use karta hai."""
    rows = await fetch(
        """
        SELECT
            s.id::text                                                          AS session_id,
            s.url,
            s.status,
            s.started_at                                                        AS created_at,
            s.scan_type,
            COUNT(v.id)                                                         AS total_vulns,
            COUNT(CASE WHEN v.priority_category = 'Critical' THEN 1 END)        AS critical,
            COUNT(CASE WHEN v.priority_category = 'High'     THEN 1 END)        AS high,
            COUNT(CASE WHEN v.priority_category = 'Medium'   THEN 1 END)        AS medium,
            COUNT(CASE WHEN v.priority_category = 'Low'      THEN 1 END)        AS low
        FROM     scan_sessions  s
        LEFT JOIN vulnerabilities v ON v.session_id = s.id
        WHERE    s.user_id = $1
        GROUP BY s.id
        ORDER BY s.started_at DESC
        LIMIT 100
        """,
        user_id,
    )

    out = []
    for r in rows:
        d = dict(r)
        d["domain"] = _domain_from_url(d["url"] or "")
        d["score"]  = _security_score(d["critical"], d["high"], d["medium"], d["low"])
        out.append(d)
    return out


# ═════════════════════════════════════════════════════════════════════════════
# DASHBOARD ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/dashboard/stats")
async def dashboard_stats(
    user_id: int = Depends(get_current_user_id),
):
    """KPI cards k liye."""
    row = await fetchrow(
        """
        SELECT
            (SELECT COUNT(*)
               FROM scan_sessions WHERE user_id = $1)                        AS total_scans,
            (SELECT COUNT(*)
               FROM vulnerabilities v
               JOIN scan_sessions   s ON s.id = v.session_id
               WHERE s.user_id = $1)                                         AS total_vulns,
            (SELECT COUNT(*)
               FROM vulnerabilities v
               JOIN scan_sessions   s ON s.id = v.session_id
               WHERE s.user_id = $1 AND v.priority_category = 'Critical')    AS critical_vulns,
            (SELECT COUNT(*)
               FROM monitored_sites
               WHERE user_id = $1 AND is_active = TRUE)                      AS monitored_sites
        """,
        user_id,
    )
    return {
        "total_scans":     int(row["total_scans"]     or 0),
        "total_vulns":     int(row["total_vulns"]     or 0),
        "critical_vulns":  int(row["critical_vulns"]  or 0),
        "monitored_sites": int(row["monitored_sites"] or 0),
    }


@app.get("/api/dashboard/recent-scans")
async def dashboard_recent_scans(
    user_id: int = Depends(get_current_user_id),
):
    rows = await fetch(
        """
        SELECT
            s.id::text                                                       AS session_id,
            s.url,
            s.status,
            s.started_at,
            COUNT(v.id)                                                      AS vuln_count,
            COUNT(CASE WHEN v.priority_category='Critical' THEN 1 END)       AS critical,
            COUNT(CASE WHEN v.priority_category='High'     THEN 1 END)       AS high,
            COUNT(CASE WHEN v.priority_category='Medium'   THEN 1 END)       AS medium,
            COUNT(CASE WHEN v.priority_category='Low'      THEN 1 END)       AS low
        FROM     scan_sessions  s
        LEFT JOIN vulnerabilities v ON v.session_id = s.id
        WHERE    s.user_id = $1
        GROUP BY s.id
        ORDER BY s.started_at DESC
        LIMIT 8
        """,
        user_id,
    )
    out = []
    for r in rows:
        d = dict(r)
        d["domain"] = _domain_from_url(d["url"] or "")
        d["score"]  = _security_score(d["critical"], d["high"], d["medium"], d["low"])
        out.append(d)
    return out


@app.get("/api/dashboard/weekly-activity")
async def dashboard_weekly_activity(
    user_id: int = Depends(get_current_user_id),
):
    """Last 7 days, scan count per day."""
    rows = await fetch(
        """
        SELECT
            TO_CHAR(d::date, 'Dy')              AS day,
            COALESCE(COUNT(s.id), 0)::int       AS scans
        FROM   generate_series(
                   CURRENT_DATE - INTERVAL '6 days',
                   CURRENT_DATE,
                   INTERVAL '1 day'
               ) d
        LEFT JOIN scan_sessions s
               ON DATE(s.started_at) = d::date
              AND s.user_id          = $1
        GROUP BY d
        ORDER BY d
        """,
        user_id,
    )
    return [dict(r) for r in rows]


@app.get("/api/dashboard/vuln-breakdown")
async def dashboard_vuln_breakdown(
    user_id: int = Depends(get_current_user_id),
):
    """Vulnerabilities by category (top 10)."""
    rows = await fetch(
        """
        SELECT v.category, COUNT(*)::int AS count
        FROM   vulnerabilities v
        JOIN   scan_sessions   s ON s.id = v.session_id
        WHERE  s.user_id = $1
        GROUP  BY v.category
        ORDER  BY count DESC
        LIMIT 10
        """,
        user_id,
    )
    return [dict(r) for r in rows]


# ═════════════════════════════════════════════════════════════════════════════
# CONTINUOUS MONITORING ENDPOINTS
# ═════════════════════════════════════════════════════════════════════════════

@app.get("/api/monitor/sites")
async def list_monitor_sites(
    user_id: int = Depends(get_current_user_id),
):
    return await get_user_monitored_sites(user_id)


@app.post("/api/monitor/sites", status_code=201)
async def add_monitor_site(
    body:    AddSiteRequest,
    user_id: int = Depends(get_current_user_id),
):
    """
    Site monitored_sites me add karein, aur fauran ek scan start karein
    (background me). Frontend list refresh karega to data dikh jayega.
    """
    url = body.url.strip().rstrip("/")
    if not url.startswith("http"):
        raise HTTPException(status_code=400, detail="URL must start with http:// or https://")

    site = await add_monitored_site(user_id, url)
    if not site:
        raise HTTPException(status_code=500, detail="Failed to add site")

    # Initial scan kick off
    session_id = str(uuid.uuid4())
    await execute(
        """
        INSERT INTO scan_sessions (id, status, started_at, user_id, url, scan_type)
        VALUES ($1::uuid, 'pending', NOW(), $2, $3, 'monitor')
        ON CONFLICT (id) DO NOTHING
        """,
        session_id, user_id, url,
    )
    await update_site_session(site["id"], session_id)

    _scans[session_id] = {
        "status":  "pending",
        "url":     url,
        "error":   None,
        "message": "Monitoring scan queued",
    }

    asyncio.create_task(
        _run_scan_bg(session_id, url, LoginConfig(), user_id, site_id=site["id"])
    )

    return {
        "id":         site["id"],
        "url":        site["url"],
        "domain":     site["domain"],
        "session_id": session_id,
        "status":     "pending",
    }


@app.delete("/api/monitor/sites/{site_id}")
async def delete_monitor_site(
    site_id: int,
    user_id: int = Depends(get_current_user_id),
):
    ok = await remove_monitored_site(user_id, site_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Site not found")
    return {"message": "Removed"}


# Frontend k purane endpoints (alias to scan endpoints) ─────────────────────
@app.get("/api/monitor/{session_id}")
async def monitor_status(session_id: str, user_id: int = Depends(get_current_user_id)):
    return await get_scan_status(session_id, user_id)


@app.get("/api/monitor/results/{session_id}")
async def monitor_results(session_id: str, user_id: int = Depends(get_current_user_id)):
    return await get_scan_results(session_id, user_id)


# ─── Health check ─────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return {"status": "ok", "service": "WebXGuard API"}


if __name__ == "__main__":
    uvicorn.run("Scanner.app:app", host="0.0.0.0", port=8000, reload=False)