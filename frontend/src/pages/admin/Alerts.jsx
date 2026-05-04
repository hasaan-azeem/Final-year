// Full alerts page: filter by severity, list with details.

import { useState, useEffect } from "react";
import {
  Bell,
  AlertTriangle,
  Loader2,
  RefreshCw,
  CheckCircle,
  Filter,
  Globe,
  ExternalLink,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { getAlerts, markAlertRead } from "../../services/extras_api";

const SEVERITIES = ["All", "Critical", "High", "Medium", "Low"];

function severityBadge(sev) {
  switch (sev) {
    case "Critical":
      return "text-red-400 bg-red-500/10 border-red-500/20";
    case "High":
      return "text-orange-400 bg-orange-500/10 border-orange-500/20";
    case "Medium":
      return "text-amber-400 bg-amber-500/10 border-amber-500/20";
    default:
      return "text-blue-400 bg-blue-500/10 border-blue-500/20";
  }
}

function timeAgo(iso) {
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("All");
  const navigate = useNavigate();

  const load = async () => {
    setLoading(true);
    try {
      const data = await getAlerts();
      setAlerts(Array.isArray(data) ? data : []);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const filtered =
    filter === "All" ? alerts : alerts.filter((a) => a.severity === filter);

  const stats = {
    total: alerts.length,
    unread: alerts.filter((a) => !a.read).length,
    critical: alerts.filter((a) => a.severity === "Critical").length,
    high: alerts.filter((a) => a.severity === "High").length,
  };

  const handleMarkRead = async (alert) => {
    if (alert.read) return;
    await markAlertRead(alert.id);
    setAlerts((prev) =>
      prev.map((a) => (a.id === alert.id ? { ...a, read: true } : a)),
    );
  };

  return (
    <section className="min-h-screen text-white">
      {/* Header */}
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                <Bell size={18} className="text-emerald-400" />
              </div>
              <h1 className="text-3xl font-bold text-white">Security Alerts</h1>
            </div>
            <p className="text-slate-400 text-sm ml-12">
              Real-time vulnerability notifications across your scans
            </p>
          </div>

          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700
              text-slate-400 text-sm hover:text-white hover:border-slate-500 transition
              disabled:opacity-40 cursor-pointer"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {/* Stat strip */}
      <div className="max-w-6xl mx-auto grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Total Alerts", value: stats.total, color: "text-white" },
          { label: "Unread", value: stats.unread, color: "text-emerald-400" },
          { label: "Critical", value: stats.critical, color: "text-red-400" },
          { label: "High", value: stats.high, color: "text-orange-400" },
        ].map((s) => (
          <div
            key={s.label}
            className="bg-[#111827] border border-slate-800 rounded-xl p-4"
          >
            <p className="text-xs text-slate-500 mb-1">{s.label}</p>
            <p className={`text-2xl font-bold ${s.color}`}>{s.value}</p>
          </div>
        ))}
      </div>

      {/* Filter chips */}
      <div className="max-w-6xl mx-auto flex items-center gap-2 mb-4 flex-wrap">
        <Filter size={14} className="text-slate-500" />
        {SEVERITIES.map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium border transition cursor-pointer ${
              filter === sev
                ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-400"
                : "bg-transparent border-slate-700 text-slate-400 hover:text-slate-200"
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Loading / Empty / List */}
      {loading ? (
        <div className="max-w-6xl mx-auto flex justify-center py-20 text-slate-400">
          <Loader2 className="animate-spin mr-2" size={20} />
          <span>Loading alerts...</span>
        </div>
      ) : filtered.length === 0 ? (
        <div className="max-w-6xl mx-auto">
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-12 text-center">
            <CheckCircle size={40} className="text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 font-medium">All caught up</p>
            <p className="text-slate-600 text-sm mt-1">
              No alerts in this category.
            </p>
          </div>
        </div>
      ) : (
        <div className="max-w-6xl mx-auto space-y-3">
          {filtered.map((alert) => (
            <div
              key={alert.id}
              onClick={() => handleMarkRead(alert)}
              className={`bg-[#111827] border rounded-xl p-4 hover:border-slate-700 transition cursor-pointer ${
                alert.read
                  ? "border-slate-800/60"
                  : "border-emerald-500/20 bg-emerald-500/2"
              }`}
            >
              <div className="flex items-start gap-4">
                {!alert.read && (
                  <div className="w-2 h-2 rounded-full bg-emerald-400 mt-2 shrink-0" />
                )}

                <div className={`flex-1 min-w-0 ${alert.read ? "ml-5" : ""}`}>
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${severityBadge(
                        alert.severity,
                      )}`}
                    >
                      {alert.severity}
                    </span>
                    <span className="text-[10px] text-slate-600">
                      {timeAgo(alert.created_at)}
                    </span>
                    {!alert.read && (
                      <span className="text-[10px] text-emerald-400 font-medium">
                        NEW
                      </span>
                    )}
                  </div>

                  <h3 className="text-sm font-semibold text-white mb-1.5">
                    {alert.title}
                  </h3>

                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <Globe size={11} className="shrink-0" />
                    <span className="truncate font-mono">{alert.url}</span>
                  </div>
                </div>

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    navigate(`/dashboard/vulnerability/${alert.scan_session}`);
                  }}
                  className="shrink-0 p-2 rounded-lg border border-slate-700 text-slate-400
                    hover:text-white hover:border-slate-500 transition cursor-pointer"
                  title="View scan details"
                >
                  <ExternalLink size={13} />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
