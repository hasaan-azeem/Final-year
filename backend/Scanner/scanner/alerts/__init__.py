"""
app/scanner/alerts
==================
Centralised alert stream: one place to create + read security alerts.

Two faces:
    create_alert_sync()    → for posture engine + ai_anomaly engine
                             (they run in thread executors with psycopg2)
    create_alert_async()   → for FastAPI request handlers
                             (use the asyncpg pool already in scanner.db)

Public helpers in triggers.py wrap business rules:
    alert_from_posture_sync(domain, payload)
    alert_from_ai_anomaly_sync(domain, result)
    alert_from_scan_completion_async(user_id, session_id, domain)
"""
from .manager import (
    create_alert_sync,
    create_alert_async,
    list_user_alerts,
    mark_alert_read,
    mark_all_read,
    clear_all_user_alerts,
    get_unread_count,
)
from .triggers import (
    alert_from_posture_sync,
    alert_from_ai_anomaly_sync,
    alert_from_scan_completion_async,
)

__all__ = [
    "create_alert_sync",
    "create_alert_async",
    "list_user_alerts",
    "mark_alert_read",
    "mark_all_read",
    "clear_all_user_alerts",
    "get_unread_count",
    "alert_from_posture_sync",
    "alert_from_ai_anomaly_sync",
    "alert_from_scan_completion_async",
]