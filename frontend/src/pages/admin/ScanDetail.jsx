import React, { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
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
} from "lucide-react";

import {
  getScanDetails,
  downloadReport,
  getScanResults,
} from "../../services/scanner_api";
import { getCompliance, getPredictive } from "../../services/extras_api";

import VulnTable from "../../components/admin/scanner/VulnTable";
import SeveritySummary from "../../components/admin/scanner/SeveritySummary";

// ── Helpers ────────────────────────────────────────────────────────────────
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

const ScanDetail = () => {
  const { id } = useParams();

  const [vulns, setVulns] = useState([]);
  const [meta, setMeta] = useState(null);
  const [compliance, setCompliance] = useState(null);
  const [predictive, setPredictive] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    (async () => {
      try {
        // Vulnerabilities
        const v = await getScanResults(id);
        setVulns(v || []);

        // Meta (status, url etc.) — best-effort
        try {
          const m = await getScanDetails(id);
          setMeta(m);
        } catch {
          setMeta({ url: v?.[0]?.page_url || "Unknown", domain: "" });
        }

        // Compliance (mock or real)
        const c = await getCompliance(id);
        setCompliance(c);

        // Predictive (mock or real)
        const p = await getPredictive(id);
        setPredictive(p);
      } catch (e) {
        console.error(e);
      } finally {
        setLoading(false);
      }
    })();
  }, [id]);

  if (loading) {
    return (
      <div className="flex justify-center py-20 text-slate-400">
        <Loader2 className="animate-spin mr-2" /> Loading details...
      </div>
    );
  }

  const safeHost = (u) => {
    try {
      return new URL(u).hostname;
    } catch {
      return u || "—";
    }
  };

  return (
    <section className="max-w-6xl mx-auto text-white space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-3xl font-bold mb-1">
            {meta?.domain || safeHost(meta?.url || "")}
          </h1>
          <p className="text-slate-400 text-sm font-mono">{meta?.url || ""}</p>
        </div>
        <button
          onClick={() => downloadReport(id)}
          className="flex items-center gap-2 px-4 py-2 rounded-xl bg-emerald-500 text-slate-900 font-semibold text-sm hover:bg-emerald-400 transition cursor-pointer"
        >
          <FileText size={14} /> Download Report
        </button>
      </div>

      {/* Severity summary */}
      <SeveritySummary vulns={vulns} />

      {/* Vulnerabilities */}
      <div>
        <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
          <AlertTriangle size={18} className="text-amber-400" />
          Vulnerabilities ({vulns.length})
        </h2>
        <div className="bg-[#111827] p-6 rounded-2xl border border-slate-800">
          <VulnTable vulns={vulns} />
        </div>
      </div>

      {/* Compliance Section */}
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
                className={`text-2xl font-bold ${scoreColor(compliance.overall_score)}`}
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

          <div className="space-y-2">
            {compliance.standards.map((std) => (
              <div
                key={std.name}
                className="bg-[#111827] border border-slate-800 rounded-xl p-4 flex items-center gap-4"
              >
                {std.status === "PASS" ? (
                  <ShieldCheck
                    size={18}
                    className="text-emerald-400 shrink-0"
                  />
                ) : (
                  <ShieldX size={18} className="text-red-400 shrink-0" />
                )}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <p className="text-sm font-semibold">{std.name}</p>
                    <span
                      className={`text-[10px] px-2 py-0.5 rounded-full border ${statusStyle(std.status)}`}
                    >
                      {std.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-500">
                    {std.compliant}/{std.total_rules} rules compliant •{" "}
                    {std.violated} violations
                  </p>
                </div>
                <div className="shrink-0 text-right">
                  <p className={`text-xl font-bold ${scoreColor(std.score)}`}>
                    {std.score.toFixed(1)}%
                  </p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Predictive Section */}
      {predictive && (
        <div>
          <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
            <Brain size={18} className="text-emerald-400" />
            Predictive Analysis
          </h2>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-4">
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <div className="flex items-center gap-2 text-slate-500 text-xs mb-1">
                {predictive.summary.direction === "increasing" ? (
                  <TrendingUp size={12} className="text-red-400" />
                ) : (
                  <TrendingDown size={12} className="text-emerald-400" />
                )}
                Risk Trajectory
              </div>
              <p
                className={`text-2xl font-bold ${
                  predictive.summary.direction === "increasing"
                    ? "text-red-400"
                    : "text-emerald-400"
                }`}
              >
                {predictive.summary.direction === "increasing" ? "+" : "-"}
                {predictive.summary.delta_pct}%
              </p>
            </div>
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <p className="text-xs text-slate-500 mb-1">Model Confidence</p>
              <p className="text-2xl font-bold text-white">
                {Math.round(predictive.summary.confidence * 100)}%
              </p>
            </div>
            <div className="bg-[#111827] border border-slate-800 rounded-xl p-4">
              <p className="text-xs text-slate-500 mb-1">
                Next Recommended Scan
              </p>
              <p className="text-2xl font-bold text-white">
                {predictive.summary.next_review_in_days}{" "}
                <span className="text-base text-slate-500">days</span>
              </p>
            </div>
          </div>

          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
            <p className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
              <AlertTriangle size={14} className="text-amber-400" /> High-Risk
              Pages
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
                    {p.risk.toFixed(1)}/10
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </section>
  );
};

export default ScanDetail;
