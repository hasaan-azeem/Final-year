// src/pages/dashboard/Vulnerability.jsx
// All scans for the logged-in user

import React, { useEffect, useState } from "react";
import {
  Shield,
  Loader2,
  ExternalLink,
  FileText,
  AlertTriangle,
  CheckCircle,
  RefreshCw,
  Globe,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

import { getScanHistory, downloadReport } from "../../services/scanner_api";
import ScoreCircle from "../../components/admin/vulnerability/ScoreCircle";

// ── Risk label helper (score is 0-100, higher = better) ─────────────────────
function riskLabel(score) {
  if (score >= 80)
    return {
      label: "Low Risk",
      color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    };
  if (score >= 60)
    return {
      label: "Medium Risk",
      color: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    };
  if (score >= 40)
    return {
      label: "High Risk",
      color: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    };
  return {
    label: "Critical Risk",
    color: "text-red-400 bg-red-500/10 border-red-500/20",
  };
}

// Status normalize: backend "complete" / "completed" dono bhej sakta hai
const isDone = (status) => ["complete", "completed"].includes(status);
const isFailed = (status) => status === "failed";

// ─────────────────────────────────────────────────────────────────────────────
const Vulnerability = () => {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const navigate = useNavigate();

  const fetchHistory = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await getScanHistory();
      setScans(Array.isArray(data) ? data : []);
    } catch (e) {
      setError(
        e.message ||
          "Failed to load scan history. Make sure the API is running.",
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, []);

  // Helper for safe URL hostname extraction
  const safeHost = (u) => {
    try {
      return u ? new URL(u).hostname : "—";
    } catch {
      return u || "—";
    }
  };

  return (
    <section className="min-h-screen text-white">
      {/* Page header */}
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                <Shield size={18} className="text-emerald-400" />
              </div>
              <h1 className="text-3xl font-bold text-white">Vulnerabilities</h1>
            </div>
            <p className="text-slate-400 text-sm ml-12">
              All scanned websites and their security posture
            </p>
          </div>

          <button
            onClick={fetchHistory}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700
              text-slate-400 text-sm hover:text-white hover:border-slate-500 transition
              disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
            Refresh
          </button>
        </div>
      </div>

      {/* Loading */}
      {loading && (
        <div className="max-w-6xl mx-auto flex justify-center py-20 text-slate-400">
          <Loader2 className="animate-spin mr-2" size={20} />
          <span>Loading scans...</span>
        </div>
      )}

      {/* Error */}
      {!loading && error && (
        <div className="max-w-6xl mx-auto">
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3">
            <AlertTriangle size={14} className="shrink-0" />
            {error}
          </div>
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && scans.length === 0 && (
        <div className="max-w-6xl mx-auto">
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-12 text-center">
            <Globe size={40} className="text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 font-medium">No scans yet</p>
            <p className="text-slate-600 text-sm mt-1">
              Run your first scan from the Scanner page.
            </p>
          </div>
        </div>
      )}

      {/* Table */}
      {!loading && scans.length > 0 && (
        <div className="max-w-6xl mx-auto">
          {/* Summary stat strip */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
            {[
              {
                label: "Total Scans",
                value: scans.length,
                color: "text-white",
              },
              {
                label: "Critical Risk",
                value: scans.filter((s) => (s.score ?? 0) < 40).length,
                color: "text-red-400",
              },
              {
                label: "High Risk",
                value: scans.filter(
                  (s) => (s.score ?? 0) >= 40 && (s.score ?? 0) < 60,
                ).length,
                color: "text-orange-400",
              },
              {
                label: "Low / Safe",
                value: scans.filter((s) => (s.score ?? 0) >= 80).length,
                color: "text-emerald-400",
              },
            ].map((stat) => (
              <div
                key={stat.label}
                className="bg-[#111827] border border-slate-800 rounded-xl p-4"
              >
                <p className="text-xs text-slate-500 mb-1">{stat.label}</p>
                <p className={`text-2xl font-bold ${stat.color}`}>
                  {stat.value}
                </p>
              </div>
            ))}
          </div>

          {/* Table container */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-slate-800">
                  <th className="text-left px-6 py-4 text-xs font-medium text-slate-500 uppercase tracking-wider">
                    Website
                  </th>
                  <th className="text-left px-6 py-4 text-xs font-medium text-slate-500 uppercase tracking-wider">
                    Risk Score
                  </th>
                  <th className="text-left px-6 py-4 text-xs font-medium text-slate-500 uppercase tracking-wider">
                    Issues
                  </th>
                  <th className="text-left px-6 py-4 text-xs font-medium text-slate-500 uppercase tracking-wider">
                    Scanned
                  </th>
                  <th className="text-left px-6 py-4 text-xs font-medium text-slate-500 uppercase tracking-wider">
                    Status
                  </th>
                  <th className="text-right px-6 py-4 text-xs font-medium text-slate-500 uppercase tracking-wider">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60">
                {scans.map((scan) => {
                  const score = scan.score ?? 0;
                  const risk = riskLabel(score);
                  const totalVulns = scan.total_vulns ?? 0;

                  return (
                    <tr
                      key={scan.session_id}
                      className="hover:bg-slate-800/30 transition-colors group"
                    >
                      {/* Website */}
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <div className="w-8 h-8 rounded-lg bg-slate-800 flex items-center justify-center shrink-0">
                            <Globe size={14} className="text-slate-400" />
                          </div>
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-white truncate max-w-60">
                              {scan.domain || safeHost(scan.url)}
                            </p>
                            <p className="text-xs text-slate-500 truncate max-w-60">
                              {scan.url}
                            </p>
                          </div>
                        </div>
                      </td>

                      {/* Risk score */}
                      <td className="px-6 py-4">
                        <div className="flex items-center gap-3">
                          <ScoreCircle score={score} size="sm" />
                          <span
                            className={`text-xs px-2 py-1 rounded-full border ${risk.color}`}
                          >
                            {risk.label}
                          </span>
                        </div>
                      </td>

                      {/* Issues count */}
                      <td className="px-6 py-4">
                        <span
                          className={`text-sm font-semibold ${
                            totalVulns === 0
                              ? "text-emerald-400"
                              : "text-amber-400"
                          }`}
                        >
                          {totalVulns}
                        </span>
                        <span className="text-slate-500 text-xs ml-1">
                          {totalVulns === 1 ? "issue" : "issues"}
                        </span>
                      </td>

                      {/* Date */}
                      <td className="px-6 py-4 text-sm text-slate-400">
                        {scan.created_at
                          ? new Date(scan.created_at).toLocaleDateString(
                              undefined,
                              {
                                month: "short",
                                day: "numeric",
                                year: "numeric",
                              },
                            )
                          : "—"}
                      </td>

                      {/* Status badge */}
                      <td className="px-6 py-4">
                        {isDone(scan.status) ? (
                          <div className="flex items-center gap-1.5 text-emerald-400 text-xs">
                            <CheckCircle size={13} />
                            <span>Completed</span>
                          </div>
                        ) : isFailed(scan.status) ? (
                          <div className="flex items-center gap-1.5 text-red-400 text-xs">
                            <AlertTriangle size={13} />
                            <span>Failed</span>
                          </div>
                        ) : (
                          <div className="flex items-center gap-1.5 text-slate-400 text-xs">
                            <Loader2 size={13} className="animate-spin" />
                            <span className="capitalize">
                              {scan.status || "Unknown"}
                            </span>
                          </div>
                        )}
                      </td>

                      {/* Actions */}
                      <td className="px-6 py-4">
                        <div className="flex items-center justify-end gap-2">
                          <button
                            onClick={() =>
                              navigate(
                                `/dashboard/vulnerability/${scan.session_id}`,
                              )
                            }
                            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500
                              text-slate-900 text-xs font-semibold hover:bg-emerald-400 transition cursor-pointer"
                          >
                            <ExternalLink size={12} />
                            View Details
                          </button>

                          <button
                            onClick={() => downloadReport(scan.session_id)}
                            title="Download CSV report"
                            className="p-1.5 rounded-lg border border-slate-700 text-slate-400
                              hover:text-white hover:border-slate-500 transition cursor-pointer"
                          >
                            <FileText size={14} />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <p className="text-xs text-slate-600 mt-3 text-right">
            Showing {scans.length} scan{scans.length !== 1 ? "s" : ""}
          </p>
        </div>
      )}
    </section>
  );
};

export default Vulnerability;
