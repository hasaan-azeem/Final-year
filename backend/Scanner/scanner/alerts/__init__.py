"""
Scanner/scanner/alerts package
==============================
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
# ★ NEW
from .email_sender import (
    try_send_email_for_alert_sync,
    try_send_email_for_alert_async,
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
    "try_send_email_for_alert_sync",     # ★ NEW
    "try_send_email_for_alert_async",    # ★ NEW
]