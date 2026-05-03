// Bell icon + dropdown for AdminLayout topbar.
// Click karke unread alerts dikhata hai, "View all" Alerts page le jaata hai.

import { useState, useEffect, useRef } from "react";
import { Bell, X, AlertTriangle } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { getAlerts, markAlertRead } from "../../services/extras_api";

function severityColor(sev) {
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
  if (diff < 60) return `${diff}s`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h`;
  return `${Math.floor(diff / 86400)}d`;
}

export default function AlertsBell() {
  const [open, setOpen] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const wrapperRef = useRef(null);
  const navigate = useNavigate();

  // Load alerts on mount and every 30s
  useEffect(() => {
    const load = async () => {
      const data = await getAlerts();
      setAlerts(data || []);
    };
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, []);

  // Close on outside click
  useEffect(() => {
    if (!open) return;
    const handler = (e) => {
      if (wrapperRef.current && !wrapperRef.current.contains(e.target))
        setOpen(false);
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [open]);

  const unreadCount = alerts.filter((a) => !a.read).length;
  const recent = alerts.slice(0, 5);

  const handleClick = async (alert) => {
    if (!alert.read) {
      await markAlertRead(alert.id);
      setAlerts((prev) =>
        prev.map((a) => (a.id === alert.id ? { ...a, read: true } : a)),
      );
    }
    setOpen(false);
    navigate("/dashboard/alerts");
  };

  return (
    <div ref={wrapperRef} className="relative">
      <button
        onClick={() => setOpen((o) => !o)}
        className="relative p-2 rounded-xl hover:bg-slate-800 transition cursor-pointer"
      >
        <Bell size={18} className="text-slate-300" />
        {unreadCount > 0 && (
          <span className="absolute -top-0.5 -right-0.5 w-5 h-5 rounded-full bg-red-500 text-white text-[10px] font-bold flex items-center justify-center border-2 border-slate-900">
            {unreadCount > 9 ? "9+" : unreadCount}
          </span>
        )}
      </button>

      {open && (
        <div className="absolute right-0 mt-2 w-80 sm:w-96 rounded-xl bg-[#0d1117] border border-slate-700 shadow-2xl shadow-black/60 overflow-hidden z-50">
          {/* Header */}
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <AlertTriangle size={14} className="text-emerald-400" />
              <span className="text-sm font-semibold text-white">
                Security Alerts
              </span>
              {unreadCount > 0 && (
                <span className="text-[10px] bg-red-500/20 text-red-400 border border-red-500/30 px-2 py-0.5 rounded-full">
                  {unreadCount} new
                </span>
              )}
            </div>
            <button
              onClick={() => setOpen(false)}
              className="text-slate-500 hover:text-white transition cursor-pointer"
            >
              <X size={14} />
            </button>
          </div>

          {/* List */}
          <div className="max-h-96 overflow-y-auto">
            {recent.length === 0 ? (
              <div className="text-center py-12 text-slate-500 text-sm">
                No alerts yet
              </div>
            ) : (
              recent.map((alert) => (
                <button
                  key={alert.id}
                  onClick={() => handleClick(alert)}
                  className={`w-full text-left px-4 py-3 border-b border-slate-800/60 last:border-0 hover:bg-slate-800/40 transition cursor-pointer ${
                    !alert.read ? "bg-slate-800/20" : ""
                  }`}
                >
                  <div className="flex items-start gap-3">
                    {!alert.read && (
                      <div className="w-2 h-2 rounded-full bg-emerald-400 mt-1.5 shrink-0" />
                    )}
                    <div className={`flex-1 min-w-0 ${alert.read ? "ml-5" : ""}`}>
                      <div className="flex items-center gap-2 mb-1">
                        <span
                          className={`text-[10px] px-1.5 py-0.5 rounded border ${severityColor(
                            alert.severity,
                          )}`}
                        >
                          {alert.severity}
                        </span>
                        <span className="text-[10px] text-slate-600">
                          {timeAgo(alert.created_at)} ago
                        </span>
                      </div>
                      <p className="text-xs text-white font-medium truncate">
                        {alert.title}
                      </p>
                      <p className="text-[10px] text-slate-500 truncate font-mono mt-0.5">
                        {alert.url}
                      </p>
                    </div>
                  </div>
                </button>
              ))
            )}
          </div>

          {/* Footer */}
          <button
            onClick={() => {
              setOpen(false);
              navigate("/dashboard/alerts");
            }}
            className="w-full px-4 py-2.5 text-xs text-emerald-400 hover:bg-slate-800/40 border-t border-slate-800 transition cursor-pointer"
          >
            View all alerts →
          </button>
        </div>
      )}
    </div>
  );
}