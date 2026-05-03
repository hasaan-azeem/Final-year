// All scan reports in one place: vulns + compliance + predictive per scan.

import { useEffect, useState } from "react";
import {
  FileText,
  Shield,
  ShieldCheck,
  ShieldX,
  Brain,
  Globe,
  Loader2,
  RefreshCw,
  ExternalLink,
  AlertTriangle,
  TrendingUp,
  TrendingDown,
  ChevronRight,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import { getScanHistory, downloadReport } from "../../services/scanner_api";
import { getCompliance, getPredictive } from "../../services/extras_api";

function scoreColor(s) {
  if (s >= 80) return "text-emerald-400";
  if (s >= 50) return "text-amber-400";
  return "text-red-400";
}

export default function Reports() {
  const [scans, setScans] = useState([]);
  const [enrichments, setEnrichments] = useState({});
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState(() => new Set());
  const navigate = useNavigate();

  const fetchData = async () => {
    setLoading(true);
    try {
      const data = await getScanHistory();
      const list = Array.isArray(data) ? data : [];
      setScans(list);

      const enr = {};
      await Promise.all(
        list.slice(0, 10).map(async (s) => {
          const [c, p] = await Promise.all([
            getCompliance(s.session_id),
            getPredictive(s.session_id),
          ]);
          enr[s.session_id] = { compliance: c, predictive: p };
        }),
      );
      setEnrichments(enr);
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const toggle = (id) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <section className="min-h-screen text-white">
      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                <FileText size={18} className="text-emerald-400" />
              </div>
              <h1 className="text-3xl font-bold text-white">Reports</h1>
            </div>
            <p className="text-slate-400 text-sm ml-12">
              Detailed reports for every scan including compliance and risk
              analysis
            </p>
          </div>

          <button
            onClick={fetchData}
            disabled={loading}
            className="flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700
              text-slate-400 text-sm hover:text-white hover:border-slate-500 transition cursor-pointer"
          >
            <RefreshCw size={14} className={loading ? "animate-spin" : ""} />{" "}
            Refresh
          </button>
        </div>
      </div>

      {loading && (
        <div className="max-w-6xl mx-auto flex justify-center py-20 text-slate-400">
          <Loader2 className="animate-spin mr-2" size={20} /> Loading reports...
        </div>
      )}

      {!loading && scans.length === 0 && (
        <div className="max-w-6xl mx-auto">
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-12 text-center">
            <FileText size={40} className="text-slate-600 mx-auto mb-3" />
            <p className="text-slate-400 font-medium">No reports yet</p>
            <p className="text-slate-600 text-sm mt-1">
              Run a scan to generate your first report.
            </p>
          </div>
        </div>
      )}

      {!loading && scans.length > 0 && (
        <div className="max-w-6xl mx-auto space-y-3">
          {scans.map((scan) => {
            const isOpen = expanded.has(scan.session_id);
            const enr = enrichments[scan.session_id];
            const compliance = enr?.compliance;
            const predictive = enr?.predictive;

            return (
              <div
                key={scan.session_id}
                className="bg-[#111827] border border-slate-800 rounded-2xl overflow-hidden"
              >
                {/* Header row */}
                <button
                  onClick={() => toggle(scan.session_id)}
                  className="w-full flex items-center gap-4 p-5 hover:bg-slate-800/30 transition cursor-pointer text-left"
                >
                  <ChevronRight
                    size={16}
                    className={`text-slate-500 shrink-0 transition-transform ${isOpen ? "rotate-90" : ""}`}
                  />
                  <div className="w-10 h-10 rounded-xl bg-slate-800 flex items-center justify-center shrink-0">
                    <Globe size={16} className="text-slate-400" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white truncate">
                      {scan.domain || scan.url}
                    </p>
                    <p className="text-xs text-slate-500 mt-0.5">
                      {scan.created_at
                        ? new Date(scan.created_at).toLocaleString(undefined, {
                            month: "short",
                            day: "numeric",
                            hour: "2-digit",
                            minute: "2-digit",
                          })
                        : "—"}
                      {" • "}
                      {scan.total_vulns || 0} issues
                    </p>
                  </div>

                  <div className="hidden sm:flex items-center gap-4 shrink-0">
                    <div className="text-right">
                      <p className="text-[10px] text-slate-500 uppercase">
                        Security
                      </p>
                      <p
                        className={`text-lg font-bold ${scoreColor(scan.score || 0)}`}
                      >
                        {scan.score || 0}
                      </p>
                    </div>
                    {compliance && (
                      <div className="text-right">
                        <p className="text-[10px] text-slate-500 uppercase">
                          Compliance
                        </p>
                        <p
                          className={`text-lg font-bold ${scoreColor(compliance.overall_score)}`}
                        >
                          {compliance.overall_score.toFixed(0)}%
                        </p>
                      </div>
                    )}
                    {predictive && (
                      <div className="text-right">
                        <p className="text-[10px] text-slate-500 uppercase">
                          Trend
                        </p>
                        <div className="flex items-center gap-1 justify-end">
                          {predictive.summary.direction === "increasing" ? (
                            <TrendingUp size={14} className="text-red-400" />
                          ) : (
                            <TrendingDown
                              size={14}
                              className="text-emerald-400"
                            />
                          )}
                          <span
                            className={`text-sm font-bold ${predictive.summary.direction === "increasing" ? "text-red-400" : "text-emerald-400"}`}
                          >
                            {predictive.summary.delta_pct}%
                          </span>
                        </div>
                      </div>
                    )}
                  </div>
                </button>

                {/* Expanded */}
                {isOpen && (
                  <div className="border-t border-slate-800 p-5 space-y-5">
                    {/* Compliance summary */}
                    {compliance && (
                      <div>
                        <p className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                          <Shield size={14} className="text-emerald-400" />{" "}
                          Compliance
                        </p>
                        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2">
                          {compliance.standards.map((std) => (
                            <div
                              key={std.name}
                              className="bg-slate-900/40 border border-slate-800 rounded-lg p-3"
                            >
                              <p className="text-[10px] text-slate-500 mb-1">
                                {std.name}
                              </p>
                              <div className="flex items-center gap-1.5">
                                {std.status === "PASS" ? (
                                  <ShieldCheck
                                    size={12}
                                    className="text-emerald-400"
                                  />
                                ) : (
                                  <ShieldX size={12} className="text-red-400" />
                                )}
                                <span
                                  className={`text-sm font-bold ${scoreColor(std.score)}`}
                                >
                                  {std.score.toFixed(0)}%
                                </span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Predictive summary */}
                    {predictive && (
                      <div>
                        <p className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                          <Brain size={14} className="text-emerald-400" />{" "}
                          Predictive Analysis
                        </p>
                        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                          <div className="bg-slate-900/40 border border-slate-800 rounded-lg p-3">
                            <p className="text-[10px] text-slate-500 mb-1">
                              Risk Trajectory
                            </p>
                            <p
                              className={`text-base font-bold ${predictive.summary.direction === "increasing" ? "text-red-400" : "text-emerald-400"}`}
                            >
                              {predictive.summary.direction === "increasing"
                                ? "+"
                                : "-"}
                              {predictive.summary.delta_pct}%
                            </p>
                          </div>
                          <div className="bg-slate-900/40 border border-slate-800 rounded-lg p-3">
                            <p className="text-[10px] text-slate-500 mb-1">
                              Confidence
                            </p>
                            <p className="text-base font-bold text-white">
                              {Math.round(predictive.summary.confidence * 100)}%
                            </p>
                          </div>
                          <div className="bg-slate-900/40 border border-slate-800 rounded-lg p-3">
                            <p className="text-[10px] text-slate-500 mb-1">
                              Next Review
                            </p>
                            <p className="text-base font-bold text-white">
                              {predictive.summary.next_review_in_days} days
                            </p>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Action buttons */}
                    <div className="flex items-center gap-2 pt-3 border-t border-slate-800/60">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(
                            `/dashboard/vulnerability/${scan.session_id}`,
                          );
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 text-slate-900 text-xs font-semibold hover:bg-emerald-400 transition cursor-pointer"
                      >
                        <ExternalLink size={12} /> Full Details
                      </button>
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          downloadReport(scan.session_id);
                        }}
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-slate-700 text-slate-400 text-xs hover:text-white hover:border-slate-500 transition cursor-pointer"
                      >
                        <FileText size={12} /> Download CSV
                      </button>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </section>
  );
}
