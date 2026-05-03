const BASE = "http://localhost:8000";

// ─────────────────────────────────────────────────────────────────────────────
// CORE FETCH
// ─────────────────────────────────────────────────────────────────────────────
async function apiFetch(path, options = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      // 🔐 JWT TOKEN (IMPORTANT)
      Authorization: `Bearer ${localStorage.getItem("token") || ""}`,
    },
    ...options,
  });

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || body.message || `HTTP ${res.status}`);
  }

  return res.json();
}

// ─────────────────────────────────────────────────────────────────────────────
// SCAN API
// ─────────────────────────────────────────────────────────────────────────────
export async function startScan(payload) {
  return apiFetch("/api/scan", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getScanStatus(sessionId) {
  return apiFetch(`/api/scan/${sessionId}`);
}

export async function getScanResults(sessionId) {
  return apiFetch(`/api/scan/results/${sessionId}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// 🔥 NEW: SCAN HISTORY (USER BASED)
// ─────────────────────────────────────────────────────────────────────────────
export async function getScanHistory() {
  return apiFetch("/api/scans/history");
}

// ─────────────────────────────────────────────────────────────────────────────
// 🔥 NEW: SINGLE SCAN DETAILS (for vulnerability page)
// ─────────────────────────────────────────────────────────────────────────────
export async function getScanDetails(sessionId) {
  return apiFetch(`/api/scan/${sessionId}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// 🔥 NEW: DOWNLOAD PDF REPORT
// ─────────────────────────────────────────────────────────────────────────────
export function downloadReport(sessionId) {
  window.open(`${BASE}/api/scan/report/${sessionId}`, "_blank");
}

// ─────────────────────────────────────────────────────────────────────────────
// MONITOR API
// ─────────────────────────────────────────────────────────────────────────────
export async function startMonitor(payload) {
  return apiFetch("/api/monitor/start", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function getMonitorStatus(sessionId) {
  return apiFetch(`/api/monitor/${sessionId}`);
}

export async function getMonitorResults(sessionId) {
  return apiFetch(`/api/monitor/results/${sessionId}`);
}

export async function getMonitorTrend(domain) {
  return apiFetch(`/api/monitor/trend?domain=${encodeURIComponent(domain)}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// CRAWLER QUEUE
// ─────────────────────────────────────────────────────────────────────────────
export async function getCrawlerQueue(sessionId) {
  return apiFetch(`/api/scan/crawler-queue/${sessionId}`);
}

// ─────────────────────────────────────────────────────────────────────────────
// DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────
export async function getDashboardStats() {
  return apiFetch("/api/dashboard/stats");
}

export async function getRecentScans() {
  return apiFetch("/api/dashboard/recent-scans");
}

export async function getWeeklyActivity() {
  return apiFetch("/api/dashboard/weekly-activity");
}

export async function getVulnBreakdown() {
  return apiFetch("/api/dashboard/vuln-breakdown");
}
