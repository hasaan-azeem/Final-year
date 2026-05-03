/* eslint-disable no-unused-vars */
// Frontend/src/pages/dashboard/Dashboard.jsx
// ─────────────────────────────────────────────────────────────────────────────
// Real-time dashboard — all data from PostgreSQL via the scanner API.
// Auto-refreshes every 30 seconds.
// ─────────────────────────────────────────────────────────────────────────────

import { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  Activity,
  AlertTriangle,
  Eye,
  TrendingUp,
  RefreshCw,
  ExternalLink,
  Clock,
} from "lucide-react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  getDashboardStats,
  getRecentScans,
  getWeeklyActivity,
  getVulnBreakdown,
} from "../../services/scanner_api";

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

const scoreColor = (s) =>
  s >= 80 ? "text-emerald-400" : s >= 60 ? "text-amber-400" : "text-red-400";
const scoreBar = (s) =>
  s >= 80 ? "bg-emerald-500" : s >= 60 ? "bg-amber-500" : "bg-red-500";

const statusStyle = (st) => {
  switch (st) {
    case "completed":
      return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    case "running":
      return "bg-blue-500/10 text-blue-400 border border-blue-500/20";
    default:
      return "bg-slate-800 text-slate-400 border border-slate-700";
  }
};

function timeAgo(iso) {
  if (!iso) return "—";
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

// ─────────────────────────────────────────────────────────────────────────────
// SKELETON
// ─────────────────────────────────────────────────────────────────────────────

function Sk({ className = "" }) {
  return <div className={`animate-pulse bg-slate-800 rounded ${className}`} />;
}

// ─────────────────────────────────────────────────────────────────────────────
// STAT CARD
// ─────────────────────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, color, loading }) {
  return (
    <div className="bg-[#111827] p-5 rounded-2xl border border-slate-800 flex items-start gap-4">
      <div className={`p-3 rounded-xl shrink-0 ${color}`}>
        <Icon size={20} />
      </div>
      <div className="min-w-0">
        <p className="text-xs text-slate-500 mb-1">{label}</p>
        {loading ? (
          <Sk className="h-8 w-16 mb-1" />
        ) : (
          <p className="text-2xl font-bold text-white">{value ?? "—"}</p>
        )}
        {sub && <p className="text-xs text-slate-600 mt-0.5">{sub}</p>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// SECURITY GAUGE  (SVG arc)
// ─────────────────────────────────────────────────────────────────────────────

function SecurityGauge({ score }) {
  const s = Math.max(0, Math.min(100, score));
  const color = s >= 70 ? "#ef4444" : s >= 40 ? "#f59e0b" : "#10b981";
  const label = s >= 70 ? "High Risk" : s >= 40 ? "Moderate" : "Low Risk";
  const r = 52;
  const cx = 68,
    cy = 68;
  const sweep = 240;
  const start = -210;
  const toR = (d) => (d * Math.PI) / 180;
  const angle = start + (s / 100) * sweep;
  const nx = cx + r * Math.cos(toR(angle));
  const ny = cy + r * Math.sin(toR(angle));
  const arcLen = (sweep / 360) * 2 * Math.PI * r;
  const fillLen = (((s / 100) * sweep) / 360) * 2 * Math.PI * r;

  return (
    <div className="flex flex-col items-center">
      <svg width="136" height="108" viewBox="0 0 136 108">
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke="#1e293b"
          strokeWidth="10"
          strokeDasharray={`${arcLen} 999`}
          strokeLinecap="round"
          transform={`rotate(${start} ${cx} ${cy})`}
        />
        <circle
          cx={cx}
          cy={cy}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeDasharray={`${fillLen} 999`}
          strokeLinecap="round"
          transform={`rotate(${start} ${cx} ${cy})`}
        />
        <circle cx={nx} cy={ny} r="5" fill={color} />
        <text
          x={cx}
          y={cy + 4}
          textAnchor="middle"
          fill="white"
          fontSize="20"
          fontWeight="700"
        >
          {s}
        </text>
      </svg>
      <span className="text-sm font-semibold mt-1" style={{ color }}>
        {label}
      </span>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MAIN DASHBOARD
// ─────────────────────────────────────────────────────────────────────────────

export default function Dashboard() {
  const navigate = useNavigate();

  const [stats, setStats] = useState(null);
  const [recents, setRecents] = useState([]);
  const [weekly, setWeekly] = useState([]);
  const [breakdown, setBreakdown] = useState([]);
  const [loading, setLoading] = useState(true);
  const [lastRefresh, setLastRefresh] = useState(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [s, r, w, b] = await Promise.all([
        getDashboardStats(),
        getRecentScans(),
        getWeeklyActivity(),
        getVulnBreakdown(),
      ]);
      setStats(s);
      setRecents(r);
      setWeekly(w);
      setBreakdown(b);
      setLastRefresh(new Date());
    } catch (e) {
      console.error("Dashboard load error:", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 300_000);
    return () => clearInterval(t);
  }, [load]);

  // Threat score based on critical vuln ratio
  const threatScore = stats
    ? Math.min(
        100,
        Math.round(
          ((stats.critical_vulns || 0) / Math.max(stats.total_vulns || 1, 1)) *
            100,
        ),
      )
    : 0;

  const maxBreakdown = Math.max(...breakdown.map((b) => b.count), 1);

  const CATEGORY_COLORS = [
    "#10b981",
    "#3b82f6",
    "#f59e0b",
    "#ef4444",
    "#8b5cf6",
    "#06b6d4",
    "#f97316",
    "#ec4899",
    "#84cc16",
    "#a78bfa",
  ];

  return (
    <div className="w-full text-slate-100 space-y-6">
      {/* ── Header ───────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Security Dashboard</h1>
          <p className="text-xs text-slate-500 mt-0.5">
            {lastRefresh
              ? `Updated ${lastRefresh.toLocaleTimeString()} · auto-refresh every 30s`
              : "Loading…"}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate("/dashboard/scanner")}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-500 text-slate-900
              text-sm font-semibold hover:bg-emerald-400 transition cursor-pointer"
          >
            <Shield size={14} /> New Scan
          </button>
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl bg-slate-800 border border-slate-700
              text-sm text-slate-300 hover:text-white hover:bg-slate-700 transition disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {/* ── KPI cards ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-5">
        <StatCard
          icon={Shield}
          label="Total Scans"
          value={stats?.total_scans}
          sub="All time"
          color="bg-blue-500/10 text-blue-400"
          loading={loading}
        />
        <StatCard
          icon={AlertTriangle}
          label="Vulnerabilities"
          value={stats?.total_vulns}
          sub="Across all scans"
          color="bg-amber-500/10 text-amber-400"
          loading={loading}
        />
        <StatCard
          icon={Activity}
          label="Critical Findings"
          value={stats?.critical_vulns}
          sub="High-confidence vulns"
          color="bg-red-500/10 text-red-400"
          loading={loading}
        />
        <StatCard
          icon={Eye}
          label="Monitored Sites"
          value={stats?.monitored_sites}
          sub="Under monitoring"
          color="bg-emerald-500/10 text-emerald-400"
          loading={loading}
        />
      </div>

      {/* ── Main grid ────────────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* LEFT ─────────────────────────────────────────────────────── */}
        <div className="col-span-1 lg:col-span-2 flex flex-col gap-5">
          {/* Weekly bar chart */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-6">
              <h3 className="text-base font-semibold flex items-center gap-2">
                <TrendingUp size={16} className="text-emerald-400" /> Scan
                Activity
              </h3>
              <span className="text-xs text-slate-500">Last 7 days</span>
            </div>
            {loading ? (
              <Sk className="h-48 w-full" />
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart
                  data={weekly}
                  margin={{ top: 5, right: 10, left: -20, bottom: 5 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="day"
                    tick={{ fill: "#64748b", fontSize: 11 }}
                  />
                  <YAxis
                    tick={{ fill: "#64748b", fontSize: 11 }}
                    allowDecimals={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0d1117",
                      border: "1px solid #1e293b",
                      borderRadius: 8,
                    }}
                    cursor={{ fill: "#1e293b" }}
                  />
                  <Bar dataKey="scans" radius={[4, 4, 0, 0]}>
                    {weekly.map((_, i) => (
                      <Cell
                        key={i}
                        fill={_.scans > 0 ? "#10b981" : "#1e293b"}
                      />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>

          {/* Recent scans table */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 overflow-x-auto">
            <div className="flex items-center justify-between mb-5">
              <h3 className="text-base font-semibold">Recent Scans</h3>
              <span className="text-xs text-slate-500">
                {loading ? "…" : `${recents.length} sessions`}
              </span>
            </div>

            {loading ? (
              <div className="space-y-3">
                {Array(5)
                  .fill(0)
                  .map((_, i) => (
                    <Sk key={i} className="h-10 w-full rounded-xl" />
                  ))}
              </div>
            ) : recents.length === 0 ? (
              <div className="text-center py-10">
                <Shield size={28} className="text-slate-700 mx-auto mb-2" />
                <p className="text-slate-600 text-sm">No scans yet.</p>
                <button
                  onClick={() => navigate("/dashboard/scanner")}
                  className="mt-3 text-xs text-emerald-400 hover:underline cursor-pointer"
                >
                  Start your first scan →
                </button>
              </div>
            ) : (
              <table className="min-w-full">
                <thead>
                  <tr className="border-b border-slate-800">
                    {["Website", "Status", "Vulns", "Score", "When"].map(
                      (h) => (
                        <th
                          key={h}
                          className="text-left pb-3 text-xs text-slate-500 font-medium px-2"
                        >
                          {h}
                        </th>
                      ),
                    )}
                  </tr>
                </thead>
                <tbody>
                  {recents.map((r, i) => (
                    <tr
                      key={r.session_id || i}
                      className="border-b border-slate-800/50 hover:bg-slate-800/20 transition"
                    >
                      <td className="px-2 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-6 h-6 rounded bg-slate-800 flex items-center justify-center shrink-0">
                            <Globe size={11} className="text-slate-500" />
                          </div>
                          <span
                            className="text-sm text-slate-300 truncate max-w-[140px]"
                            title={r.domain}
                          >
                            {r.domain}
                          </span>
                        </div>
                      </td>
                      <td className="px-2 py-3">
                        <span
                          className={`px-2 py-0.5 rounded-md text-xs capitalize ${statusStyle(r.status)}`}
                        >
                          {r.status}
                        </span>
                      </td>
                      <td className="px-2 py-3">
                        <div className="flex items-center gap-1.5">
                          {r.critical > 0 && (
                            <span className="text-xs text-red-400 font-medium">
                              {r.critical}C
                            </span>
                          )}
                          {r.high > 0 && (
                            <span className="text-xs text-amber-400 font-medium">
                              {r.high}H
                            </span>
                          )}
                          {r.medium > 0 && (
                            <span className="text-xs text-blue-400 font-medium">
                              {r.medium}M
                            </span>
                          )}
                          {r.vuln_count === 0 && (
                            <span className="text-xs text-emerald-400">
                              Clean
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="px-2 py-3">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                            <div
                              className={`h-full ${scoreBar(r.score)} rounded-full`}
                              style={{ width: `${r.score}%` }}
                            />
                          </div>
                          <span
                            className={`text-xs font-semibold ${scoreColor(r.score)}`}
                          >
                            {r.score}
                          </span>
                        </div>
                      </td>
                      <td className="px-2 py-3">
                        <span className="text-xs text-slate-600 flex items-center gap-1">
                          <Clock size={10} /> {timeAgo(r.started_at)}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>

        {/* RIGHT ────────────────────────────────────────────────────── */}
        <div className="flex flex-col gap-5">
          {/* Security gauge */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-base font-semibold">Threat Level</h3>
              <span className="text-xs text-slate-500">
                Based on critical findings
              </span>
            </div>
            <div className="flex items-center justify-center py-2">
              {loading ? (
                <Sk className="h-28 w-36 rounded-full" />
              ) : (
                <SecurityGauge score={threatScore} />
              )}
            </div>
          </div>

          {/* Vuln breakdown */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6">
            <h3 className="text-base font-semibold mb-5">
              Vulnerabilities by Category
            </h3>
            {loading ? (
              <div className="space-y-3">
                {Array(6)
                  .fill(0)
                  .map((_, i) => (
                    <Sk key={i} className="h-4 w-full" />
                  ))}
              </div>
            ) : breakdown.length === 0 ? (
              <p className="text-slate-600 text-sm text-center py-4">
                No data yet.
              </p>
            ) : (
              <div className="space-y-3">
                {breakdown.map((b, i) => {
                  const pct = Math.max((b.count / maxBreakdown) * 100, 2);
                  return (
                    <div key={i} className="flex items-center gap-3">
                      <span className="text-xs text-slate-400 w-28 truncate capitalize">
                        {b.category?.replace(/_/g, " ")}
                      </span>
                      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full transition-all duration-500"
                          style={{
                            width: `${pct}%`,
                            backgroundColor:
                              CATEGORY_COLORS[i % CATEGORY_COLORS.length],
                          }}
                        />
                      </div>
                      <span className="text-xs text-slate-500 w-5 text-right">
                        {b.count}
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Quick actions */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
            <h3 className="text-sm font-semibold text-slate-400 mb-4 uppercase tracking-wider">
              Quick Actions
            </h3>
            <div className="space-y-2">
              {[
                {
                  label: "Start New Scan",
                  icon: <Shield size={14} />,
                  path: "/dashboard/scanner",
                },
                {
                  label: "Continuous Monitor",
                  icon: <Activity size={14} />,
                  path: "/dashboard/scanner",
                },
              ].map((a) => (
                <button
                  key={a.label}
                  onClick={() => navigate(a.path)}
                  className="w-full flex items-center gap-3 px-3 py-2.5 rounded-xl
                    bg-slate-800/50 hover:bg-slate-800 text-slate-300 hover:text-white
                    text-sm transition cursor-pointer border border-transparent hover:border-slate-700"
                >
                  <span className="text-emerald-400">{a.icon}</span>
                  {a.label}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// Missing Globe import fix — add it inline
function Globe({ size, className }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      className={className}
    >
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}

// import { useEffect, useState } from "react";
// import {
//   getDashboardStats,
//   getRecentScans,
//   getWeeklyActivity,
//   getVulnBreakdown,
// } from "../../services/scanner_api";

// import StatCard from "../../components/admin/dashboard/StatCard";
// import WeeklyChart from "../../components/admin/dashboard/WeeklyChart";
// import RecentScans from "../../components/admin/dashboard/RecentScans";
// import VulnerabilityBreakdown from "../../components/admin/dashboard/VulnerabilityBreakdown";
// import SecurityGauge from "../../components/admin/dashboard/SecurityGauge";
// import QuickActions from "../../components/admin/dashboard/QuickActions";

// import { Shield, AlertTriangle, Activity, Eye } from "lucide-react";

// export default function Dashboard() {
//   const [stats, setStats] = useState({});
//   const [recents, setRecents] = useState([]);
//   const [weekly, setWeekly] = useState([]);
//   const [breakdown, setBreakdown] = useState([]);
//   const [loading, setLoading] = useState(true);

//   const load = async () => {
//     setLoading(true);
//     const [s, r, w, b] = await Promise.all([
//       getDashboardStats(),
//       getRecentScans(),
//       getWeeklyActivity(),
//       getVulnBreakdown(),
//     ]);
//     setStats(s);
//     setRecents(r);
//     setWeekly(w);
//     setBreakdown(b);
//     setLoading(false);
//   };

//   useEffect(() => {
//     load();
//   }, []);

//   const threatScore = stats?.critical_vulns
//     ? (stats.critical_vulns / stats.total_vulns) * 100
//     : 0;

//   return (
//     <div className="space-y-6">
//       {/* Stats */}
//       <div className="grid grid-cols-4 gap-4">
//         <StatCard icon={Shield} label="Scans" value={stats.total_scans} loading={loading} />
//         <StatCard icon={AlertTriangle} label="Vulns" value={stats.total_vulns} loading={loading} />
//         <StatCard icon={Activity} label="Critical" value={stats.critical_vulns} loading={loading} />
//         <StatCard icon={Eye} label="Monitored" value={stats.monitored_sites} loading={loading} />
//       </div>

//       {/* Chart */}
//       <WeeklyChart data={weekly} loading={loading} />

//       {/* Recent */}
//       <RecentScans data={recents} />

//       {/* Right side */}
//       <div className="grid grid-cols-2 gap-4">
//         <SecurityGauge score={threatScore} />
//         <VulnerabilityBreakdown data={breakdown} />
//       </div>

//       <QuickActions />
//     </div>
//   );
// }
