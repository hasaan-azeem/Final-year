/* eslint-disable no-unused-vars */
// src/pages/admin/ScanDetail.jsx
// ─────────────────────────────────────────────────────────────────────────────
// Single-scan deep-dive page with:
//   • 3 charts at the top (severity donut, CVSS bar, category bar)
//   • Vulnerability list with AI fix suggestions (expandable per vuln)
//   • Compliance section with progress rings (5 standards)
//   • Predictive section with mini forecast chart
//
// Calls:
//   getScanResults(id)             → vuln list (legacy compatibility)
//   getRemediationsForSession(id)  → vulns merged with AI fix payload
//   getCompliance(id)              → compliance scores + violations
//   getPredictive(id)              → posture forecast + at-risk pages
// ─────────────────────────────────────────────────────────────────────────────

import { useEffect, useMemo, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  Loader2,
  FileText,
  Shield,
  ShieldCheck,
  ShieldX,
  Brain,
  TrendingUp,
  TrendingDown,
  AlertTriangle,
  Globe,
  ArrowLeft,
  BarChart3,
  Activity,
  Sparkles,
} from "lucide-react";

import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
  AreaChart,
  Area,
} from "recharts";

import {
  getScanDetails,
  downloadReport,
  getScanResults,
} from "../../services/scanner_api";
import {
  getCompliance,
  getPredictive,
  getRemediationsForSession,
} from "../../services/extras_api";

import VulnTable from "../../components/admin/scanner/VulnTable";
import SeveritySummary from "../../components/admin/scanner/SeveritySummary";

// ─── Helpers ────────────────────────────────────────────────────────────────
function scoreColor(score) {
  if (score >= 80) return "text-emerald-400";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}
function statusStyle(s) {
  return s === "PASS"
    ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
    : "text-red-400 bg-red-500/10 border-red-500/20";
}
const safeHost = (u) => {
  try {
    return new URL(u).hostname;
  } catch {
    return u || "—";
  }
};

const SEVERITY_COLORS = {
  Critical: "#ef4444",
  High: "#f97316",
  Medium: "#f59e0b",
  Low: "#3b82f6",
  Info: "#64748b",
};

// ═════════════════════════════════════════════════════════════════════════════
// Sub-component: Severity Donut Chart
// ═════════════════════════════════════════════════════════════════════════════
function SeverityDonut({ vulns }) {
  const data = useMemo(() => {
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0 };
    for (const v of vulns) {
      const k = v.priority_category || "Low";
      if (counts[k] != null) counts[k]++;
    }
    return Object.entries(counts)
      .filter(([_, c]) => c > 0)
      .map(([name, value]) => ({ name, value }));
  }, [vulns]);

  const total = data.reduce((s, d) => s + d.value, 0);

  if (total === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-600 text-sm">
        No findings
      </div>
    );
  }

  return (
    <div className="relative">
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie
            data={data}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={80}
            paddingAngle={2}
            dataKey="value"
          >
            {data.map((entry, i) => (
              <Cell
                key={i}
                fill={SEVERITY_COLORS[entry.name] || "#64748b"}
                stroke="#0f172a"
                strokeWidth={2}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: "#0d1117",
              border: "1px solid #1e293b",
              borderRadius: 8,
              fontSize: 12,
            }}
          />
        </PieChart>
      </ResponsiveContainer>

      {/* Center label */}
      <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
        <p className="text-2xl font-bold text-white">{total}</p>
        <p className="text-[10px] text-slate-500 uppercase tracking-wider">
          Findings
        </p>
      </div>

      {/* Mini legend below */}
      <div className="flex flex-wrap justify-center gap-3 mt-2">
        {data.map((d) => (
          <div key={d.name} className="flex items-center gap-1.5">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: SEVERITY_COLORS[d.name] }}
            />
            <span className="text-[11px] text-slate-400">
              {d.name} ({d.value})
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Sub-component: CVSS Score Distribution
// ═════════════════════════════════════════════════════════════════════════════
function CvssDistribution({ vulns }) {
  const data = useMemo(() => {
    const buckets = [
      { range: "0-2", count: 0, color: "#3b82f6" },
      { range: "2-4", count: 0, color: "#3b82f6" },
      { range: "4-6", count: 0, color: "#f59e0b" },
      { range: "6-8", count: 0, color: "#f97316" },
      { range: "8-10", count: 0, color: "#ef4444" },
    ];
    for (const v of vulns) {
      const s = Number(v.cvss_score || 0);
      const idx = Math.min(Math.floor(s / 2), 4);
      buckets[idx].count++;
    }
    return buckets;
  }, [vulns]);

  const max = Math.max(...data.map((d) => d.count), 1);

  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart
        data={data}
        margin={{ top: 5, right: 10, left: -25, bottom: 5 }}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="#1e293b"
          vertical={false}
        />
        <XAxis
          dataKey="range"
          tick={{ fill: "#64748b", fontSize: 11 }}
          axisLine={{ stroke: "#334155" }}
        />
        <YAxis
          tick={{ fill: "#64748b", fontSize: 11 }}
          allowDecimals={false}
          axisLine={{ stroke: "#334155" }}
          domain={[0, max + 1]}
        />
        <Tooltip
          contentStyle={{
            backgroundColor: "#0d1117",
            border: "1px solid #1e293b",
            borderRadius: 8,
            fontSize: 12,
          }}
          cursor={{ fill: "#1e293b" }}
        />
        <Bar dataKey="count" radius={[4, 4, 0, 0]}>
          {data.map((d, i) => (
            <Cell key={i} fill={d.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Sub-component: Top categories horizontal bar
// ═════════════════════════════════════════════════════════════════════════════
function CategoryBars({ vulns }) {
  const data = useMemo(() => {
    const counts = {};
    for (const v of vulns) {
      const c = v.category || "Other";
      counts[c] = (counts[c] || 0) + 1;
    }
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 6);
  }, [vulns]);

  if (data.length === 0) {
    return (
      <div className="flex items-center justify-center h-48 text-slate-600 text-sm">
        No data
      </div>
    );
  }

  const max = Math.max(...data.map((d) => d.value), 1);
  const PALETTE = [
    "#10b981",
    "#3b82f6",
    "#f59e0b",
    "#ef4444",
    "#8b5cf6",
    "#06b6d4",
  ];

  return (
    <div className="space-y-2.5 py-2">
      {data.map((d, i) => {
        const pct = (d.value / max) * 100;
        return (
          <div key={d.name} className="flex items-center gap-3">
            <span
              className="text-[11px] text-slate-400 w-28 truncate text-right"
              title={d.name}
            >
              {d.name}
            </span>
            <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full rounded-full transition-all duration-500"
                style={{
                  width: `${pct}%`,
                  backgroundColor: PALETTE[i % PALETTE.length],
                }}
              />
            </div>
            <span className="text-[11px] font-bold text-slate-300 w-6 text-right">
              {d.value}
            </span>
          </div>
        );
      })}
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Sub-component: Compliance ring (small)
// ═════════════════════════════════════════════════════════════════════════════
function ComplianceRing({ score, size = 56, stroke = 5 }) {
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const offset = c - (Math.max(0, Math.min(100, score)) / 100) * c;
  const color = score >= 80 ? "#10b981" : score >= 50 ? "#f59e0b" : "#ef4444";

  return (
    <div className="relative" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke="#1e293b"
          strokeWidth={stroke}
          fill="none"
        />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          stroke={color}
          strokeWidth={stroke}
          fill="none"
          strokeDasharray={c}
          strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-xs font-bold text-white">
          {Math.round(score)}%
        </span>
      </div>
    </div>
  );
}

// ═════════════════════════════════════════════════════════════════════════════
// Main page
// ═════════════════════════════════════════════════════════════════════════════
export default function ScanDetail() {
  const { id } = useParams();
  const navigate = useNavigate();

  // Vulnerabilities — start with raw rows, replace with remediation-enriched
  // version once that arrives (so the page is interactive immediately and the
  // AI fixes pop in as they're ready).
  const [vulns, setVulns] = useState([]);
  const [meta, setMeta] = useState(null);
  const [compliance, setCompliance] = useState(null);
  const [predictive, setPredictive] = useState(null);
  const [loading, setLoading] = useState(true);
  const [remediating, setRemediating] = useState(false);

  useEffect(() => {
    let cancelled = false;

    (async () => {
      // ── Phase 1: fast — show vulns + meta + compliance + predictive ─────
      try {
        const [v, m, c, p] = await Promise.all([
          getScanResults(id),
          getScanDetails(id).catch(() => null),
          getCompliance(id),
          getPredictive(id),
        ]);
        if (cancelled) return;
        setVulns(Array.isArray(v) ? v : []);
        setMeta(m || { url: v?.[0]?.page_url || "", domain: "" });
        setCompliance(c);
        setPredictive(p);
      } catch (e) {
        console.error("[ScanDetail] phase 1 error:", e);
      } finally {
        if (!cancelled) setLoading(false);
      }

      // ── Phase 2: slow — fetch AI remediations (1-3 sec) ─────────────────
      if (cancelled) return;
      setRemediating(true);
      try {
        const enriched = await getRemediationsForSession(id);
        if (cancelled) return;
        if (Array.isArray(enriched) && enriched.length > 0) {
          setVulns(enriched);
        }
      } catch (e) {
        console.warn("[ScanDetail] remediation fetch failed:", e);
      } finally {
        if (!cancelled) setRemediating(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [id]);

  if (loading) {
    return (
      <div className="flex justify-center items-center py-20 text-slate-400">
        <Loader2 className="animate-spin mr-2" size={20} />
        Loading scan details...
      </div>
    );
  }

  return (
    <section className="max-w-6xl mx-auto text-white space-y-8">
      {/* ── Top header ─────────────────────────────────────────────── */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div className="flex items-center gap-3 min-w-0">
          <button
            onClick={() => navigate(-1)}
            className="p-2 rounded-lg border border-slate-700 text-slate-400
              hover:text-white hover:border-slate-500 transition cursor-pointer"
            title="Back"
          >
            <ArrowLeft size={14} />
          </button>
          <div className="min-w-0">
            <h1 className="text-2xl sm:text-3xl font-bold truncate">
              {meta?.domain || safeHost(meta?.url || "")}
            </h1>
            <p className="text-slate-400 text-sm font-mono truncate">
              {meta?.url || ""}
            </p>
          </div>
        </div>
        <button
          onClick={() => downloadReport(id)}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-500
            text-slate-900 font-semibold text-sm hover:bg-emerald-400 transition cursor-pointer"
        >
          <FileText size={14} /> Download CSV
        </button>
      </div>

      {/* ── Severity summary cards ────────────────────────────────── */}
      <SeveritySummary vulns={vulns} />

      {/* ── 3 charts grid ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <BarChart3 size={14} className="text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">
              Severity Distribution
            </h3>
          </div>
          <SeverityDonut vulns={vulns} />
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <Activity size={14} className="text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">CVSS Scores</h3>
          </div>
          <CvssDistribution vulns={vulns} />
          <p className="text-[10px] text-slate-600 mt-2 text-center">
            Common Vulnerability Scoring System
          </p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
          <div className="flex items-center gap-2 mb-3">
            <BarChart3 size={14} className="text-emerald-400" />
            <h3 className="text-sm font-semibold text-white">Top Categories</h3>
          </div>
          <CategoryBars vulns={vulns} />
        </div>
      </div>

      {/* ── Vulnerability list ─────────────────────────────────────── */}
      <div>
        <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <AlertTriangle size={18} className="text-amber-400" />
            Vulnerabilities ({vulns.length})
          </h2>
          {remediating && (
            <span className="inline-flex items-center gap-2 text-xs text-purple-400 bg-purple-500/10 border border-purple-500/20 px-3 py-1 rounded-full">
              <Sparkles size={11} className="animate-pulse" />
              AI is generating fix suggestions in the background...
            </span>
          )}
        </div>
        <div className="bg-[#111827] p-5 rounded-2xl border border-slate-800">
          <VulnTable vulns={vulns} />
        </div>
        {vulns.length > 0 && !remediating && (
          <p className="text-[11px] text-slate-600 mt-2 ml-2">
            <Sparkles size={10} className="inline text-emerald-400" /> Click any
            finding to see the recommended fix.
          </p>
        )}
      </div>

      {/* ── Compliance Section ─────────────────────────────────────── */}
      {compliance && (
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Shield size={18} className="text-emerald-400" />
            Compliance Report
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <p className="text-xs text-slate-500 mb-1">Overall Score</p>
              <p
                className={`text-2xl font-bold ${scoreColor(
                  compliance.overall_score,
                )}`}
              >
                {compliance.overall_score?.toFixed(1)}%
              </p>
            </div>
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <p className="text-xs text-slate-500 mb-1">Standards Passed</p>
              <p className="text-2xl font-bold text-emerald-400">
                {compliance.standards.filter((s) => s.status === "PASS").length}
                /{compliance.standards.length}
              </p>
            </div>
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <p className="text-xs text-slate-500 mb-1">Total Violations</p>
              <p className="text-2xl font-bold text-red-400">
                {compliance.standards.reduce((s, x) => s + x.violated, 0)}
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {compliance.standards.map((std) => (
              <div
                key={std.name}
                className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center gap-4"
              >
                <ComplianceRing score={std.score} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    <p className="text-sm font-semibold truncate">{std.name}</p>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full border ${statusStyle(
                        std.status,
                      )}`}
                    >
                      {std.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500">
                    {std.compliant}/{std.total_rules} compliant • {std.violated}{" "}
                    violations
                  </p>
                </div>
                {std.status === "PASS" ? (
                  <ShieldCheck
                    size={18}
                    className="text-emerald-400 shrink-0"
                  />
                ) : (
                  <ShieldX size={18} className="text-red-400 shrink-0" />
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Predictive Section ─────────────────────────────────────── */}
      {predictive && (
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Brain size={18} className="text-emerald-400" />
            Predictive Analysis
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
                {predictive.summary?.direction === "increasing" ? (
                  <TrendingUp size={12} className="text-red-400" />
                ) : (
                  <TrendingDown size={12} className="text-emerald-400" />
                )}
                Risk Trajectory
              </div>
              <p
                className={`text-2xl font-bold ${
                  predictive.summary?.direction === "increasing"
                    ? "text-red-400"
                    : "text-emerald-400"
                }`}
              >
                {predictive.summary?.direction === "increasing" ? "+" : "-"}
                {predictive.summary?.delta_pct ?? 0}%
              </p>
            </div>
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <p className="text-xs text-slate-500 mb-1">Model Confidence</p>
              <p className="text-2xl font-bold text-white">
                {Math.round((predictive.summary?.confidence ?? 0) * 100)}%
              </p>
            </div>
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <p className="text-xs text-slate-500 mb-1">
                Next Recommended Scan
              </p>
              <p className="text-2xl font-bold text-white">
                {predictive.summary?.next_review_in_days ?? "—"}{" "}
                <span className="text-base text-slate-500">days</span>
              </p>
            </div>
          </div>

          {/* Mini forecast chart */}
          {predictive.forecast?.length > 0 && (
            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5 mb-4">
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <TrendingUp size={13} className="text-emerald-400" /> 7-Day
                Score Forecast
              </h3>
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={predictive.forecast}>
                  <defs>
                    <linearGradient
                      id="sd_forecast"
                      x1="0"
                      y1="0"
                      x2="0"
                      y2="1"
                    >
                      <stop offset="0%" stopColor="#10b981" stopOpacity={0.3} />
                      <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis
                    dataKey="day"
                    tick={{ fill: "#64748b", fontSize: 11 }}
                  />
                  <YAxis
                    domain={[0, 100]}
                    tick={{ fill: "#64748b", fontSize: 11 }}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#0d1117",
                      border: "1px solid #1e293b",
                      borderRadius: 8,
                    }}
                  />
                  <Area
                    type="monotone"
                    dataKey="expected"
                    stroke="#10b981"
                    strokeWidth={2}
                    fill="url(#sd_forecast)"
                    name="Predicted score"
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* High-risk pages */}
          {predictive.at_risk?.length > 0 && (
            <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
              <p className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <AlertTriangle size={14} className="text-amber-400" />
                High-Risk Pages
              </p>
              <div className="space-y-2">
                {predictive.at_risk.map((p, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-3 bg-slate-900/40 border border-slate-800 rounded-lg p-3"
                  >
                    <Globe size={11} className="text-slate-500 shrink-0 mt-1" />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono text-slate-300 truncate">
                        {p.url}
                      </p>
                      <p className="text-[11px] text-slate-500 mt-0.5">
                        {p.reason}
                      </p>
                    </div>
                    <span
                      className={`text-xs font-bold shrink-0 ${
                        p.risk >= 8
                          ? "text-red-400"
                          : p.risk >= 6
                            ? "text-orange-400"
                            : "text-amber-400"
                      }`}
                    >
                      {Number(p.risk || 0).toFixed(1)}/10
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  );
}
