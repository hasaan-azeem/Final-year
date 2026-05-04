/* eslint-disable no-unused-vars */
// src/pages/dashboard/ContinuousMonitoring.jsx
// Live monitored sites with compliance + predictive risk per row.

import React, { useEffect, useState, useRef } from "react";
import {
  CirclePlus,
  ShieldCheck,
  ShieldAlert,
  Shield,
  Loader2,
  RefreshCw,
  Globe,
  X,
  AlertTriangle,
  Clock,
  Activity,
  ExternalLink,
  FileText,
  Brain,
  TrendingUp,
  TrendingDown,
} from "lucide-react";
import { useNavigate } from "react-router-dom";

import { downloadReport } from "../../services/scanner_api";
import { getCompliance, getPredictive } from "../../services/extras_api";

import MonitorConfigModal from "../../components/admin/monitoring/MonitorConfigModal";

const BASE = "http://localhost:8000";

async function apiFetch(path, opts = {}) {
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${localStorage.getItem("token") || ""}`,
    },
    ...opts,
  });
  if (!res.ok) {
    const b = await res.json().catch(() => ({}));
    throw new Error(b.detail || b.message || `HTTP ${res.status}`);
  }
  return res.json();
}

const getMonitoredSites = () => apiFetch("/api/monitor/sites");
const addMonitoredSite = (url) =>
  apiFetch("/api/monitor/sites", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
const removeMonitoredSite = (id) =>
  apiFetch(`/api/monitor/sites/${id}`, { method: "DELETE" });

function scoreColor(score) {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-400";
  if (score >= 40) return "text-orange-400";
  return "text-red-400";
}
function riskLabel(score) {
  if (score >= 80)
    return {
      label: "Secure",
      icon: <ShieldCheck size={13} />,
      color: "text-emerald-400 bg-emerald-500/10 border-emerald-500/20",
    };
  if (score >= 60)
    return {
      label: "Moderate",
      icon: <ShieldAlert size={13} />,
      color: "text-amber-400 bg-amber-500/10 border-amber-500/20",
    };
  if (score >= 40)
    return {
      label: "At Risk",
      icon: <ShieldAlert size={13} />,
      color: "text-orange-400 bg-orange-500/10 border-orange-500/20",
    };
  return {
    label: "Critical",
    icon: <ShieldAlert size={13} />,
    color: "text-red-400 bg-red-500/10 border-red-500/20",
  };
}

function AddSiteModal({ onClose, onAdd }) {
  const [siteUrl, setSiteUrl] = useState("");
  const [adding, setAdding] = useState(false);
  const [err, setErr] = useState("");
  const inputRef = useRef(null);

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const handleAdd = async () => {
    const u = siteUrl.trim();
    if (!u) return setErr("Please enter a URL.");
    if (!u.startsWith("http"))
      return setErr("URL must start with http:// or https://");
    setAdding(true);
    setErr("");
    try {
      await onAdd(u);
      onClose();
    } catch (e) {
      setErr(e.message || "Failed to add website.");
    } finally {
      setAdding(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="w-full max-w-md mx-4 bg-[#0d1117] border border-slate-700 rounded-2xl p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-2">
            <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center">
              <Activity size={15} className="text-emerald-400" />
            </div>
            <h3 className="font-semibold text-white">Add Website to Monitor</h3>
          </div>
          <button
            onClick={onClose}
            className="text-slate-500 hover:text-white transition cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        <div className="relative mb-3">
          <Globe
            size={14}
            className="absolute left-3.5 top-1/2 -translate-y-1/2 text-slate-600 pointer-events-none"
          />
          <input
            ref={inputRef}
            type="text"
            placeholder="https://example.com"
            value={siteUrl}
            onChange={(e) => {
              setSiteUrl(e.target.value);
              setErr("");
            }}
            onKeyDown={(e) => e.key === "Enter" && handleAdd()}
            className="w-full pl-9 pr-4 py-2.5 rounded-xl bg-slate-900 border border-slate-700
              text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/50 text-sm transition"
          />
        </div>

        {err && (
          <div className="flex items-center gap-2 text-red-400 text-xs bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 mb-3">
            <AlertTriangle size={12} /> {err}
          </div>
        )}

        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2.5 rounded-xl border border-slate-700 text-slate-400 text-sm hover:text-white hover:border-slate-500 transition cursor-pointer"
          >
            Cancel
          </button>
          <button
            onClick={handleAdd}
            disabled={adding}
            className="flex-1 py-2.5 rounded-xl bg-emerald-500 text-slate-900 font-semibold text-sm
              flex items-center justify-center gap-2 hover:bg-emerald-400 transition
              disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {adding ? (
              <Loader2 size={14} className="animate-spin" />
            ) : (
              <CirclePlus size={14} />
            )}
            {adding ? "Adding..." : "Add Website"}
          </button>
        </div>
      </div>
    </div>
  );
}

const ContinuousMonitoring = () => {
  const [sites, setSites] = useState([]);
  const [enrichments, setEnrichments] = useState({}); // { session_id: { compliance, predictive } }
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showModal, setShowModal] = useState(false);
  const [removing, setRemoving] = useState(null);

  const navigate = useNavigate();
  const [monitorConfig, setMonitorConfig] = useState({});

  const fetchSites = async () => {
    setLoading(true);
    setError("");
    try {
      const data = await getMonitoredSites();
      const list = data || [];
      setSites(list);
      // Enrich each site with compliance + predictive (mock or real)
      const enr = {};
      await Promise.all(
        list.map(async (s) => {
          if (!s.session_id) return;
          const [c, p] = await Promise.all([
            getCompliance(s.session_id),
            getPredictive(s.session_id),
          ]);
          enr[s.session_id] = { compliance: c, predictive: p };
        }),
      );
      setEnrichments(enr);
    } catch (e) {
      setError(e.message || "Failed to load monitored sites.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchSites();
  }, []);

  const handleAdd = async (url) => {
    await addMonitoredSite(url);
    await fetchSites();
  };

  const handleRemove = async (id) => {
    setRemoving(id);
    try {
      await removeMonitoredSite(id);
      setSites((prev) => prev.filter((s) => s.id !== id));
    } catch (e) {
      setError(e.message || "Failed to remove site.");
    } finally {
      setRemoving(null);
    }
  };

  const totalSites = sites.length;
  const secureSites = sites.filter((s) => (s.score || 0) >= 80).length;
  const atRiskSites = sites.filter((s) => (s.score || 0) < 60).length;
  const avgScore = totalSites
    ? Math.round(sites.reduce((acc, s) => acc + (s.score || 0), 0) / totalSites)
    : 0;

  return (
    <section className="min-h-screen text-white">
      {showModal && (
        <AddSiteModal onClose={() => setShowModal(false)} onAdd={handleAdd} />
      )}

      <div className="max-w-6xl mx-auto mb-8">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-xl bg-emerald-500/10 flex items-center justify-center">
                <Activity size={18} className="text-emerald-400" />
              </div>
              <h1 className="text-3xl font-bold text-white">
                Continuous Monitoring
              </h1>
            </div>
            <p className="text-slate-400 text-sm ml-12">
              Websites under active monitoring with compliance and risk
              forecasting
            </p>
          </div>

          <div className="flex items-center gap-3">
            <MonitorConfigModal onChange={setMonitorConfig} />
            <button
              onClick={fetchSites}
              disabled={loading}
              className="flex items-center gap-2 px-4 py-2 rounded-xl border border-slate-700
                text-slate-400 text-sm hover:text-white hover:border-slate-500 transition
                disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
            >
              <RefreshCw size={14} className={loading ? "animate-spin" : ""} />{" "}
              Refresh
            </button>
            <button
              onClick={() => setShowModal(true)}
              className="flex items-center gap-2 px-5 py-2 rounded-xl bg-emerald-500
                text-slate-900 font-semibold text-sm hover:bg-emerald-400 transition cursor-pointer"
            >
              <CirclePlus size={16} /> Add Website
            </button>
          </div>
        </div>
      </div>

      <div className="max-w-6xl mx-auto grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
        {[
          { label: "Monitored", value: totalSites, color: "text-white" },
          { label: "Secure", value: secureSites, color: "text-emerald-400" },
          { label: "At Risk", value: atRiskSites, color: "text-red-400" },
          { label: "Avg Score", value: avgScore, color: scoreColor(avgScore) },
        ].map((stat) => (
          <div
            key={stat.label}
            className="bg-[#111827] border border-slate-800 rounded-xl p-4"
          >
            <p className="text-xs text-slate-500 mb-1">{stat.label}</p>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {error && (
        <div className="max-w-6xl mx-auto mb-4">
          <div className="flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/20 rounded-xl px-4 py-3">
            <AlertTriangle size={14} className="shrink-0" /> {error}
          </div>
        </div>
      )}

      {loading && (
        <div className="max-w-6xl mx-auto flex justify-center py-20 text-slate-400">
          <Loader2 className="animate-spin mr-2" size={20} />{" "}
          <span>Loading monitored sites...</span>
        </div>
      )}

      {!loading && !error && sites.length === 0 && (
        <div className="max-w-6xl mx-auto">
          <div className="bg-[#111827] border border-slate-800 border-dashed rounded-2xl p-12 text-center">
            <Activity size={40} className="text-slate-700 mx-auto mb-3" />
            <p className="text-slate-400 font-medium">
              No websites monitored yet
            </p>
            <p className="text-slate-600 text-sm mt-1 mb-5">
              Add a website to start tracking its security posture over time.
            </p>
            <button
              onClick={() => setShowModal(true)}
              className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl bg-emerald-500 text-slate-900 font-semibold text-sm hover:bg-emerald-400 transition cursor-pointer"
            >
              <CirclePlus size={16} /> Add Your First Website
            </button>
          </div>
        </div>
      )}

      {!loading && sites.length > 0 && (
        <div className="max-w-6xl mx-auto space-y-3">
          {sites.map((site) => {
            const score = site.score || 0;
            const risk = riskLabel(score);
            const enr = enrichments[site.session_id];
            const compliance = enr?.compliance;
            const predictive = enr?.predictive;

            return (
              <div
                key={site.id || site.session_id}
                className="bg-[#111827] border border-slate-800 rounded-2xl p-5"
              >
                {/* Top row */}
                <div className="flex items-start gap-4 flex-wrap">
                  <div className="w-10 h-10 rounded-lg bg-slate-800 flex items-center justify-center shrink-0">
                    <Globe size={16} className="text-slate-400" />
                  </div>

                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-white truncate">
                      {site.domain ||
                        (() => {
                          try {
                            return new URL(site.url).hostname;
                          } catch {
                            return site.url;
                          }
                        })()}
                    </p>
                    <p className="text-xs text-slate-500 truncate font-mono">
                      {site.url}
                    </p>
                    <div className="flex items-center gap-1.5 text-slate-400 text-[11px] mt-1">
                      <Clock size={10} />
                      {site.last_checked
                        ? new Date(site.last_checked).toLocaleString(
                            undefined,
                            {
                              month: "short",
                              day: "numeric",
                              hour: "2-digit",
                              minute: "2-digit",
                            },
                          )
                        : "Just added"}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="flex items-center gap-2 shrink-0">
                    {site.session_id && (
                      <button
                        onClick={() =>
                          navigate(
                            `/dashboard/vulnerability/${site.session_id}`,
                          )
                        }
                        className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-emerald-500 text-slate-900 text-xs font-semibold hover:bg-emerald-400 transition cursor-pointer"
                      >
                        <ExternalLink size={12} /> Details
                      </button>
                    )}
                    {site.session_id && (
                      <button
                        onClick={() => downloadReport(site.session_id)}
                        title="Download report"
                        className="p-1.5 rounded-lg border border-slate-700 text-slate-400 hover:text-white hover:border-slate-500 transition cursor-pointer"
                      >
                        <FileText size={14} />
                      </button>
                    )}
                    <button
                      onClick={() => handleRemove(site.id)}
                      disabled={removing === site.id}
                      title="Remove from monitoring"
                      className="p-1.5 rounded-lg border border-slate-700 text-slate-500 hover:text-red-400 hover:border-red-500/40 transition disabled:opacity-40 disabled:cursor-not-allowed cursor-pointer"
                    >
                      {removing === site.id ? (
                        <Loader2 size={14} className="animate-spin" />
                      ) : (
                        <X size={14} />
                      )}
                    </button>
                  </div>
                </div>

                {/* Metrics row */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mt-4 pt-4 border-t border-slate-800/60">
                  {/* Security score */}
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                      Security
                    </p>
                    <div className="flex items-center gap-2">
                      <span
                        className={`text-lg font-bold ${scoreColor(score)}`}
                      >
                        {score}
                      </span>
                      <span
                        className={`text-[10px] px-1.5 py-0.5 rounded border ${risk.color}`}
                      >
                        {risk.label}
                      </span>
                    </div>
                  </div>

                  {/* Issues */}
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1">
                      Issues
                    </p>
                    <p
                      className={`text-lg font-bold ${(site.total_vulns || 0) === 0 ? "text-emerald-400" : "text-amber-400"}`}
                    >
                      {site.total_vulns || 0}
                    </p>
                  </div>

                  {/* Compliance */}
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1 flex items-center gap-1">
                      <Shield size={9} /> Compliance
                    </p>
                    {compliance ? (
                      <p
                        className={`text-lg font-bold ${scoreColor(compliance.overall_score)}`}
                      >
                        {compliance.overall_score.toFixed(0)}%
                      </p>
                    ) : (
                      <p className="text-sm text-slate-600">—</p>
                    )}
                  </div>

                  {/* Predictive risk */}
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-1 flex items-center gap-1">
                      <Brain size={9} /> Risk Trend
                    </p>
                    {predictive ? (
                      <div className="flex items-center gap-1.5">
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
                          {predictive.summary.direction === "increasing"
                            ? "+"
                            : "-"}
                          {predictive.summary.delta_pct}%
                        </span>
                      </div>
                    ) : (
                      <p className="text-sm text-slate-600">—</p>
                    )}
                  </div>
                </div>
              </div>
            );
          })}

          <p className="text-xs text-slate-600 mt-3 text-right">
            Monitoring {sites.length} website{sites.length !== 1 ? "s" : ""}
          </p>
        </div>
      )}
    </section>
  );
};

export default ContinuousMonitoring;
