/* eslint-disable no-empty */
// Live crawler view: pages discovered, endpoints, forms, queue.
// Refresh par session_id localStorage me persist.

import { useEffect, useState, useRef, useCallback } from "react";
import {
  Network,
  Globe,
  Loader2,
  RefreshCw,
  FileCode,
  FormInput,
  ChevronRight,
  CheckCircle,
  Clock,
  X,
  Activity,
} from "lucide-react";
import { getCrawlerData } from "../../services/extras_api";
import { startScan, getCrawlerQueue } from "../../services/scanner_api";

const STORAGE_KEY = "webxguard_crawler_session";

function statusColor(status) {
  if (status === "done") return "text-emerald-400";
  if (status === "failed") return "text-red-400";
  if (status === "in_progress") return "text-amber-400";
  return "text-slate-500";
}

export default function Crawler() {
  const [url, setUrl] = useState("");
  const [sessionId, setSessionId] = useState(() => {
    try {
      return localStorage.getItem(STORAGE_KEY) || null;
    } catch {
      return null;
    }
  });
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [activeTab, setActiveTab] = useState("pages");

  const pollRef = useRef(null);

  // Restore on mount
  useEffect(() => {
    if (sessionId) loadData(sessionId);
    // eslint-disable-next-line
  }, []);

  const loadData = useCallback(async (sid) => {
    if (!sid) return;
    try {
      const d = await getCrawlerData(sid);
      // Also fetch live queue from real backend if available
      try {
        const queue = await getCrawlerQueue(sid);
        if (queue && queue.length) {
          d.queue = queue;
        }
      } catch {}
      setData(d);
    } catch (e) {
      console.error(e);
    }
  }, []);

  const startCrawl = async () => {
    if (!url.trim()) return setError("Please enter a URL.");
    if (!url.startsWith("http"))
      return setError("URL must start with http:// or https://");

    setError("");
    setLoading(true);
    try {
      const res = await startScan({ url, login_enabled: false });
      const sid = res.session_id;
      setSessionId(sid);
      try {
        localStorage.setItem(STORAGE_KEY, sid);
      } catch {}
      await loadData(sid);

      // Poll for live updates
      if (pollRef.current) clearInterval(pollRef.current);
      pollRef.current = setInterval(() => loadData(sid), 4000);
    } catch (e) {
      setError(e.message || "Failed to start crawl. Backend running?");
    } finally {
      setLoading(false);
    }
  };

  const clearSession = () => {
    setSessionId(null);
    setData(null);
    setUrl("");
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch {}
    if (pollRef.current) clearInterval(pollRef.current);
  };

  // Cleanup
  useEffect(
    () => () => {
      if (pollRef.current) clearInterval(pollRef.current);
    },
    [],
  );

  const tabs = [
    { id: "pages", label: "Pages", icon: <Globe size={13} /> },
    { id: "endpoints", label: "Endpoints", icon: <FileCode size={13} /> },
    { id: "forms", label: "Forms", icon: <FormInput size={13} /> },
    { id: "queue", label: "Queue", icon: <Activity size={13} /> },
  ];

  return (
    <section className="min-h-screen text-white">
      {/* Header */}
      <div className="max-w-5xl mx-auto text-center mb-10">
        <div className="flex justify-center mb-4">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 flex items-center justify-center">
            <Network size={28} className="text-emerald-400" />
          </div>
        </div>
        <h1 className="text-4xl md:text-5xl font-bold text-white mb-3">
          Crawler
        </h1>
        <p className="text-slate-400 text-base max-w-xl mx-auto">
          Discover all pages, endpoints, and forms exposed by a target site.
        </p>
      </div>

      {/* URL input */}
      <div className="max-w-3xl mx-auto mb-6">
        <div className="flex flex-row gap-3 items-center">
          <div className="flex-1 relative">
            <Globe
              size={15}
              className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600"
            />
            <input
              value={url}
              onChange={(e) => {
                setUrl(e.target.value);
                setError("");
              }}
              onKeyDown={(e) => e.key === "Enter" && startCrawl()}
              type="text"
              placeholder="https://example.com"
              className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700
                text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/50
                transition text-sm"
            />
          </div>
          <button
            onClick={startCrawl}
            disabled={loading}
            className="px-6 py-3 rounded-xl bg-emerald-500 text-slate-900 font-semibold text-sm
              flex items-center justify-center gap-2 transition cursor-pointer
              hover:bg-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
          >
            {loading ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Network size={16} />
            )}
            Start Crawling
          </button>
        </div>

        {error && (
          <div className="mt-3 flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2.5">
            <X size={14} className="shrink-0" /> {error}
          </div>
        )}

        {sessionId && (
          <div className="mt-3 flex items-center justify-between text-xs text-slate-500 bg-slate-900/50 border border-slate-800 rounded-lg px-3 py-2">
            <span className="font-mono">
              Session: {sessionId.slice(0, 8)}...
            </span>
            <div className="flex items-center gap-3">
              <button
                onClick={() => loadData(sessionId)}
                className="text-emerald-400 hover:text-emerald-300 cursor-pointer flex items-center gap-1"
              >
                <RefreshCw size={11} /> Refresh
              </button>
              <button
                onClick={clearSession}
                className="text-slate-500 hover:text-red-400 cursor-pointer"
              >
                Clear session
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Data view */}
      {data && (
        <div className="max-w-5xl mx-auto">
          {/* Stat cards */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
            {[
              {
                label: "Pages",
                value: data.pages?.length || 0,
                color: "text-white",
              },
              {
                label: "Endpoints",
                value: data.endpoints?.length || 0,
                color: "text-emerald-400",
              },
              {
                label: "Forms",
                value: data.forms?.length || 0,
                color: "text-amber-400",
              },
              {
                label: "Status",
                value: data.status || "—",
                color: "text-blue-400",
              },
            ].map((s) => (
              <div
                key={s.label}
                className="bg-[#111827] border border-slate-800 rounded-xl p-4"
              >
                <p className="text-xs text-slate-500 mb-1">{s.label}</p>
                <p className={`text-2xl font-bold ${s.color} capitalize`}>
                  {s.value}
                </p>
              </div>
            ))}
          </div>

          {/* Tabs */}
          <div className="flex items-center gap-2 mb-4 overflow-x-auto">
            {tabs.map((t) => (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium border transition cursor-pointer whitespace-nowrap ${
                  activeTab === t.id
                    ? "bg-emerald-500/15 border-emerald-500/40 text-emerald-400"
                    : "bg-transparent border-slate-700 text-slate-400 hover:text-slate-200"
                }`}
              >
                {t.icon} {t.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
            {activeTab === "pages" && (
              <div className="space-y-1">
                {(data.pages || []).map((p, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-slate-800/40"
                  >
                    <Globe size={11} className="text-slate-500 shrink-0" />
                    <span className="text-xs font-mono text-slate-300 truncate flex-1">
                      {p.url}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      d{p.depth}
                    </span>
                    <span
                      className={`text-[10px] font-semibold ${
                        p.status === 200 ? "text-emerald-400" : "text-amber-400"
                      }`}
                    >
                      {p.status}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === "endpoints" && (
              <div className="space-y-1">
                {(data.endpoints || []).map((e, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-slate-800/40"
                  >
                    <FileCode size={11} className="text-emerald-400 shrink-0" />
                    <span className="text-xs font-mono text-slate-300 truncate flex-1">
                      {e.url}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400 uppercase">
                      {e.type}
                    </span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === "forms" && (
              <div className="space-y-1">
                {(data.forms || []).map((f, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-slate-800/40"
                  >
                    <FormInput size={11} className="text-amber-400 shrink-0" />
                    <span className="text-xs font-mono text-slate-300 truncate flex-1">
                      {f.action}
                    </span>
                    <span className="text-[10px] px-2 py-0.5 rounded bg-slate-800 text-slate-400">
                      {f.method}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      {f.inputs} inputs
                    </span>
                  </div>
                ))}
              </div>
            )}

            {activeTab === "queue" && (
              <div className="space-y-1">
                {(data.queue || []).map((q, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-3 py-2 px-3 rounded-lg hover:bg-slate-800/40"
                  >
                    {q.status === "done" ? (
                      <CheckCircle
                        size={11}
                        className="text-emerald-400 shrink-0"
                      />
                    ) : (
                      <Clock
                        size={11}
                        className="text-amber-400 shrink-0 animate-pulse"
                      />
                    )}
                    <span className="text-xs font-mono text-slate-300 truncate flex-1">
                      {q.url}
                    </span>
                    <span
                      className={`text-[10px] capitalize ${statusColor(q.status)}`}
                    >
                      {q.status?.replace("_", " ")}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
