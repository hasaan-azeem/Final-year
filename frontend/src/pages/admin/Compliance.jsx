// src/pages/dashboard/Compliance.jsx
// 5 standards (OWASP, PCI-DSS, GDPR, HIPAA, ISO 27001) — real DB data.
// Latest report for the logged-in user is loaded by default.

import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import {
  Shield,
  ShieldCheck,
  ShieldX,
  Loader2,
  RefreshCw,
  ChevronRight,
  CheckCircle,
  XCircle,
  AlertTriangle,
  FileText,
  Activity,
} from "lucide-react";
import { getCompliance } from "../../services/extras_api";

function statusStyle(status) {
  switch (status) {
    case "PASS":
      return "text-emerald-400 bg-emerald-500/10 border-emerald-500/20";
    case "FAIL":
      return "text-red-400 bg-red-500/10 border-red-500/20";
    default:
      return "text-amber-400 bg-amber-500/10 border-amber-500/20";
  }
}

function severityChip(sev) {
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

function scoreColor(score) {
  if (score >= 80) return "text-emerald-400";
  if (score >= 50) return "text-amber-400";
  return "text-red-400";
}

export default function Compliance() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(() => new Set());
  const navigate = useNavigate();

  const load = async () => {
    setLoading(true);
    try {
      // No sessionId → backend returns the most recent compliance for this user
      const d = await getCompliance();
      setData(d);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  const toggle = (name) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  // ── Loading state ──────────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="min-h-screen flex justify-center items-center text-slate-400">
        <Loader2 className="animate-spin mr-2" size={20} />
        Loading compliance report...
      </div>
    );
  }

  // ── Empty state — no compliance data exists yet ───────────────────────────
  if (!data) {
    return (
      <section className="min-h-screen text-white">
        <div className="max-w-6xl mx-auto mb-8">
          <div className="flex items-center gap-3 mb-1">
            <div className="w-9 h-9 rounded-xl bg-emerald-500/10 flex items-center justify-center">
              <Shield size={18} className="text-emerald-400" />
            </div>
            <h1 className="text-3xl font-bold text-white">Compliance Report</h1>
          </div>
          <p className="text-slate-400 text-sm ml-12">
            OWASP, PCI-DSS, GDPR, HIPAA, ISO 27001
          </p>
        </div>

        <div className="max-w-6xl mx-auto">
          <div className="bg-[#111827] border border-slate-800 border-dashed rounded-2xl p-12 text-center">
            <Shield size={40} className="text-slate-700 mx-auto mb-3" />
            <p className="text-slate-400 font-medium">No compliance data yet</p>
            <p className="text-slate-600 text-sm mt-1 mb-5">
              Run a scan first. Compliance is generated automatically when a
              scan finishes.
            </p>
            <div className="flex items-center justify-center gap-3">
              <button
                onClick={() => navigate("/dashboard/scanner")}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 text-slate-900 font-semibold text-sm hover:bg-emerald-400 transition cursor-pointer"
              >
                <Shield size={16} /> Run a Scan
              </button>
              <button
                onClick={load}
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl border border-slate-700 text-slate-400 text-sm hover:text-white hover:border-slate-500 transition cursor-pointer"
              >
                <RefreshCw size={14} /> Refresh
              </button>
            </div>
          </div>
        </div>
      </section>
    );
  }

  // ── Normal render ─────────────────────────────────────────────────────────
  const passed = data.standards.filter((s) => s.status === "PASS").length;

  return (
    <section className="min-h-screen text-white">
      {/* Header */}
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                <Shield size={18} className="text-emerald-400" />
              </div>
              <h1 className="text-3xl font-bold text-white">
                Compliance Report
              </h1>
            </div>
            <p className="text-slate-400 text-sm ml-12">
              {data.domain || "—"}
              {data.session_id && (
                <span> • Session {data.session_id.slice(0, 8)}</span>
              )}
            </p>
          </div>

          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700
              text-slate-400 text-sm hover:text-white hover:border-slate-500 transition cursor-pointer"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {/* Overall summary */}
      <div className="max-w-6xl mx-auto grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <p className="text-xs text-slate-500 mb-1">Overall Score</p>
          <p className={`text-3xl font-bold ${scoreColor(data.overall_score)}`}>
            {Number(data.overall_score || 0).toFixed(1)}%
          </p>
          <p className="text-xs text-slate-600 mt-1">
            Across {data.standards.length} standards
          </p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <p className="text-xs text-slate-500 mb-1">Standards Passed</p>
          <p className="text-3xl font-bold text-emerald-400">
            {passed}/{data.standards.length}
          </p>
          <p className="text-xs text-slate-600 mt-1">Compliant standards</p>
        </div>

        <div className="bg-[#111827] border border-slate-800 rounded-xl p-5">
          <p className="text-xs text-slate-500 mb-1">Total Violations</p>
          <p className="text-3xl font-bold text-red-400">
            {data.standards.reduce((sum, s) => sum + (s.violated || 0), 0)}
          </p>
          <p className="text-xs text-slate-600 mt-1">Rules to address</p>
        </div>
      </div>

      {/* Standards list */}
      <div className="max-w-6xl mx-auto space-y-3">
        {data.standards.map((std) => {
          const isOpen = expanded.has(std.name);

          return (
            <div
              key={std.name}
              className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden"
            >
              <button
                onClick={() => toggle(std.name)}
                className="w-full flex items-center gap-4 p-5 hover:bg-slate-800/30 transition cursor-pointer text-left"
              >
                <ChevronRight
                  size={16}
                  className={`text-slate-500 shrink-0 transition-transform ${
                    isOpen ? "rotate-90" : ""
                  }`}
                />

                <div className="w-10 h-10 rounded-xl bg-slate-800 flex items-center justify-center shrink-0">
                  {std.status === "PASS" ? (
                    <ShieldCheck size={18} className="text-emerald-400" />
                  ) : (
                    <ShieldX size={18} className="text-red-400" />
                  )}
                </div>

                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <h3 className="text-base font-semibold text-white">
                      {std.name}
                    </h3>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full border font-medium ${statusStyle(
                        std.status,
                      )}`}
                    >
                      {std.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500">
                    {std.compliant} of {std.total_rules} rules compliant •{" "}
                    {std.violated} violations
                  </p>
                </div>

                <div className="flex flex-col items-end shrink-0">
                  <p className={`text-2xl font-bold ${scoreColor(std.score)}`}>
                    {Number(std.score || 0).toFixed(1)}%
                  </p>
                  <div className="w-24 h-1.5 bg-slate-800 rounded-full overflow-hidden mt-1">
                    <div
                      className={`h-full rounded-full transition-all ${
                        std.score >= 80
                          ? "bg-emerald-500"
                          : std.score >= 50
                            ? "bg-amber-500"
                            : "bg-red-500"
                      }`}
                      style={{ width: `${std.score}%` }}
                    />
                  </div>
                </div>
              </button>

              {isOpen && (
                <div className="border-t border-slate-800 px-5 py-4">
                  {!std.violations || std.violations.length === 0 ? (
                    <div className="py-6 text-center text-slate-500 text-sm flex items-center justify-center gap-2">
                      <CheckCircle size={14} className="text-emerald-400" />
                      All rules compliant
                    </div>
                  ) : (
                    <>
                      <p className="text-xs text-slate-500 mb-3 flex items-center gap-2">
                        <AlertTriangle size={12} className="text-amber-400" />
                        Violated Rules ({std.violations.length})
                      </p>
                      <div className="space-y-2">
                        {std.violations.map((v, idx) => (
                          <div
                            key={`${v.rule_id}-${idx}`}
                            className="flex items-start gap-3 bg-slate-900/40 border border-slate-800 rounded-lg p-3"
                          >
                            <XCircle
                              size={14}
                              className="text-red-400 shrink-0 mt-0.5"
                            />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 mb-1 flex-wrap">
                                <code className="text-xs font-mono text-emerald-400 bg-slate-800/60 px-1.5 py-0.5 rounded">
                                  {v.rule_id}
                                </code>
                                <span
                                  className={`text-[10px] px-2 py-0.5 rounded-full border ${severityChip(
                                    v.severity,
                                  )}`}
                                >
                                  {v.severity}
                                </span>
                              </div>
                              <p className="text-sm text-white">
                                {v.rule_name}
                              </p>
                              {v.page_url && (
                                <p className="text-[11px] text-slate-500 font-mono mt-1 truncate">
                                  {v.page_url}
                                </p>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <div className="max-w-6xl mx-auto mt-6">
        <div className="flex items-start gap-2 px-4 py-3 rounded-xl bg-slate-800/30 border border-slate-700/50">
          <FileText size={13} className="text-slate-500 shrink-0 mt-0.5" />
          <p className="text-xs text-slate-500">
            Compliance scores are calculated per scan session. A standard passes
            when 80% or more rules are compliant.
          </p>
        </div>
      </div>
    </section>
  );
}
