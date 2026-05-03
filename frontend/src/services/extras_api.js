/* eslint-disable no-unused-vars */
// src/services/extras_api.js
// ─────────────────────────────────────────────────────────────────────────────
// REAL BACKEND VERSION — saara data ab DB se aata hai.
// Mocks aur localStorage alerts wala fallback hata diya gaya hai.
//
// Endpoints:
//   GET    /api/alerts                    → list
//   GET    /api/alerts/unread-count       → count
//   POST   /api/alerts/{id}/read          → mark one read
//   POST   /api/alerts/read-all           → mark all read
//   DELETE /api/alerts                    → dismiss all
//
//   GET    /api/compliance/{session_id}   → real compliance for one scan
//   GET    /api/compliance/latest         → latest for current user
//
//   GET    /api/predictive/{session_id}   → real posture forecast
//   GET    /api/predictive/latest         → latest posture for user
//
//   GET    /api/scan/crawler/{session_id} → real crawler view
// ─────────────────────────────────────────────────────────────────────────────

const BASE = "http://localhost:8000";

// ─── Core fetch (returns null on any failure, never throws) ─────────────────
async function safeFetch(path, options = {}) {
  try {
    const res = await fetch(`${BASE}${path}`, {
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${localStorage.getItem("token") || ""}`,
      },
      ...options,
    });
    if (!res.ok) {
      // 404 = "no data yet" — UI handles that as null
      if (res.status === 404) return null;
      const body = await res.json().catch(() => ({}));
      console.warn(
        `[extras_api] ${path} → HTTP ${res.status}`,
        body.detail || body.message || "",
      );
      return null;
    }
    return await res.json();
  } catch (e) {
    console.warn(`[extras_api] ${path} → network error:`, e.message);
    return null;
  }
}

// ═════════════════════════════════════════════════════════════════════════════
// ALERTS
// ═════════════════════════════════════════════════════════════════════════════

export async function getAlerts({ severity, unreadOnly, limit } = {}) {
  const qs = new URLSearchParams();
  if (severity) qs.append("severity", severity);
  if (unreadOnly) qs.append("unread_only", "true");
  if (limit) qs.append("limit", String(limit));
  const path = qs.toString() ? `/api/alerts?${qs}` : "/api/alerts";

  const data = await safeFetch(path);
  return Array.isArray(data) ? data : [];
}

export async function getUnreadAlertsCount() {
  const data = await safeFetch("/api/alerts/unread-count");
  return data?.unread ?? 0;
}

export async function markAlertRead(id) {
  return await safeFetch(`/api/alerts/${id}/read`, { method: "POST" });
}

export async function markAllAlertsRead() {
  return await safeFetch("/api/alerts/read-all", { method: "POST" });
}

export async function clearAlerts() {
  return await safeFetch("/api/alerts", { method: "DELETE" });
}

/**
 * pushAlert — kept as no-op for backward compatibility.
 * Alerts are now created server-side automatically when a scan finishes
 * (Critical/High findings) or when the posture/anomaly engines flag an issue.
 * Frontend code calling pushAlert(...) doesn't need to change.
 */
export function pushAlert(_alert) {
  // intentionally no-op — server creates alerts now
  return [];
}

// ═════════════════════════════════════════════════════════════════════════════
// COMPLIANCE
// ═════════════════════════════════════════════════════════════════════════════

export async function getCompliance(sessionId) {
  if (!sessionId) {
    return await safeFetch("/api/compliance/latest");
  }
  return await safeFetch(`/api/compliance/${sessionId}`);
}

// ═════════════════════════════════════════════════════════════════════════════
// PREDICTIVE
// ═════════════════════════════════════════════════════════════════════════════

export async function getPredictive(sessionId) {
  if (!sessionId) {
    return await safeFetch("/api/predictive/latest");
  }
  return await safeFetch(`/api/predictive/${sessionId}`);
}

// ═════════════════════════════════════════════════════════════════════════════
// CRAWLER
// ═════════════════════════════════════════════════════════════════════════════

export async function getCrawlerData(sessionId) {
  if (!sessionId) return null;
  return await safeFetch(`/api/scan/crawler/${sessionId}`);
}
