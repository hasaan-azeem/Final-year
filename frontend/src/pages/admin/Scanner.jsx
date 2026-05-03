/* eslint-disable react-hooks/set-state-in-effect */
/* eslint-disable no-empty */

import { useState, useRef, useEffect, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import {
  Shield,
  Search,
  Loader2,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Globe,
  Lock,
} from "lucide-react";

import MultiStepLoader from "../../components/admin/scanner/MultiStepLoader";
import SeveritySummary from "../../components/admin/scanner/SeveritySummary";
import VulnTable from "../../components/admin/scanner/VulnTable";
import AuthForm from "../../components/admin/scanner/AuthForm";
import {
  SCAN_STEPS,
  msgToStep,
} from "../../components/admin/scanner/Scannerconstants";

import {
  startScan,
  getScanStatus,
  getScanResults,
  getCrawlerQueue,
} from "../../services/scanner_api";
import { pushAlert } from "../../services/extras_api";

// ─── Persistence keys ──────────────────────────────────────────────────────
const STORAGE_KEY = "webxguard_lastScan";

function saveLastScan(payload) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(payload));
  } catch {}
}
function loadLastScan() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}
function clearLastScan() {
  try {
    localStorage.removeItem(STORAGE_KEY);
  } catch {}
}

const SECURITY_TIPS = [
  {
    icon: <Lock size={18} />,
    title: "Keep Dependencies Updated",
    desc: "Always update libraries to avoid known exploits",
  },
  {
    icon: <Shield size={18} />,
    title: "Use HTTPS Everywhere",
    desc: "Encrypt all traffic between users and your server",
  },
  {
    icon: <CheckCircle size={18} />,
    title: "Validate All Inputs",
    desc: "Sanitize user data to prevent injection attacks",
  },
];

const DONE_STATUSES = ["complete", "completed"];
const TERMINAL_STATUSES = [...DONE_STATUSES, "failed"];

// ─────────────────────────────────────────────────────────────────────────────
export default function Scanner() {
  const [searchParams] = useSearchParams();

  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [job, setJob] = useState(null);
  const [error, setError] = useState("");
  const [authData, setAuthData] = useState(null);
  const [results, setResults] = useState([]);
  const [resultsLoading, setResultsLoading] = useState(false);
  const [crawlerUrls, setCrawlerUrls] = useState([]);
  const [liveVulns, setLiveVulns] = useState([]);

  const pollRef = useRef(null);
  const crawlerPollRef = useRef(null);
  const sessionIdRef = useRef(null);

  // ── Restore last scan from localStorage on mount ───────────────────────
  useEffect(() => {
    const last = loadLastScan();
    if (last && last.results?.length > 0) {
      setJob(last.job);
      setResults(last.results);
      setUrl(last.job?.url || "");
    }
  }, []);

  // ── Pre-fill URL from query param or sessionStorage ────────────────────
  useEffect(() => {
    const fromQuery = searchParams.get("url");
    const fromStorage = sessionStorage.getItem("pendingScanUrl");
    if (fromQuery) {
      setUrl(fromQuery);
      sessionStorage.removeItem("pendingScanUrl");
    } else if (fromStorage) {
      setUrl(fromStorage);
      sessionStorage.removeItem("pendingScanUrl");
    }
  }, [searchParams]);

  // ── Polling helpers ─────────────────────────────────────────────────────
  const stopAll = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    if (crawlerPollRef.current) {
      clearInterval(crawlerPollRef.current);
      crawlerPollRef.current = null;
    }
  }, []);

  const stopCrawlerPoll = useCallback(() => {
    if (crawlerPollRef.current) {
      clearInterval(crawlerPollRef.current);
      crawlerPollRef.current = null;
    }
    setCrawlerUrls([]);
  }, []);

  const startCrawlerPoll = useCallback((sessionId) => {
    if (crawlerPollRef.current) clearInterval(crawlerPollRef.current);
    crawlerPollRef.current = setInterval(async () => {
      try {
        const rows = await getCrawlerQueue(sessionId);
        setCrawlerUrls(rows.slice(-15));
      } catch {}
    }, 3000);
  }, []);

  // Push critical/high findings to alerts list
  const pushAlertsFromResults = useCallback((vulns, scanUrl, sessionId) => {
    const critical = (vulns || []).filter(
      (v) =>
        v.priority_category === "Critical" || v.priority_category === "High",
    );
    critical.slice(0, 5).forEach((v) => {
      pushAlert({
        severity: v.priority_category,
        title: v.title,
        url: v.page_url || scanUrl,
        scan_session: sessionId,
      });
    });
  }, []);

  const loadResults = useCallback(
    async (sessionId, jobSnapshot) => {
      if (!sessionId) return;
      setResultsLoading(true);
      try {
        const data = await getScanResults(sessionId);
        const list = data || [];
        setResults(list);
        // Persist for refresh
        saveLastScan({
          job: { ...jobSnapshot, status: "complete" },
          results: list,
          savedAt: new Date().toISOString(),
        });
        // Push alerts
        pushAlertsFromResults(list, jobSnapshot?.url, sessionId);
      } catch (e) {
        console.error("Results load error:", e);
      }
      setResultsLoading(false);
    },
    [pushAlertsFromResults],
  );

  // ── Main poll loop ─────────────────────────────────────────────────────
  const startPoll = useCallback(
    (sessionId) => {
      if (!sessionId) return;
      if (pollRef.current) clearInterval(pollRef.current);

      pollRef.current = setInterval(async () => {
        try {
          const d = await getScanStatus(sessionId);

          setJob((prev) => ({
            ...prev,
            ...d,
            session_id: d.session_id || sessionId,
          }));

          const step = msgToStep(d.message || "");

          if (step === 1 && !crawlerPollRef.current)
            startCrawlerPoll(d.session_id || sessionId);
          if (step !== 1 && crawlerPollRef.current) stopCrawlerPoll();

          if (step >= 2) {
            try {
              const vulns = await getScanResults(sessionId);
              setLiveVulns((vulns || []).slice(0, 10));
            } catch {}
          }

          if (TERMINAL_STATUSES.includes(d.status)) {
            stopAll();
            setLoading(false);
            if (DONE_STATUSES.includes(d.status)) {
              await loadResults(d.session_id || sessionId, {
                ...d,
                session_id: sessionId,
              });
            }
          }
        } catch (err) {
          console.error("Polling error:", err);
          stopAll();
          setLoading(false);
        }
      }, 2500);
    },
    [stopAll, stopCrawlerPoll, startCrawlerPoll, loadResults],
  );

  // ── Submit ──────────────────────────────────────────────────────────────
  const submit = async () => {
    if (!url.trim()) return setError("Please enter a URL.");
    if (!url.startsWith("http"))
      return setError("URL must start with http:// or https://");

    setError("");
    setLoading(true);
    setResults([]);
    setLiveVulns([]);
    setCrawlerUrls([]);
    sessionIdRef.current = null;
    clearLastScan(); // naye scan se purana wipe
    stopAll();

    try {
      const payload = {
        url,
        login_enabled: authData?.enabled ?? false,
        auth_type: authData?.enabled ? authData.auth_type || null : null,
        login_url: authData?.enabled ? authData.login_url || null : null,
        login_username: authData?.enabled ? authData.username || null : null,
        login_password: authData?.enabled ? authData.password || null : null,
        login_user_field: authData?.enabled
          ? authData.login_user_field || null
          : null,
        login_pass_field: authData?.enabled
          ? authData.login_pass_field || null
          : null,
      };

      const d = await startScan(payload);

      setJob({
        session_id: d.session_id,
        status: "pending",
        message: "Initializing Scanner",
        url,
      });
      sessionIdRef.current = d.session_id;
      startPoll(d.session_id);
    } catch (e) {
      setError(
        e.message ||
          "Cannot connect to scanner API. Is it running on port 8000?",
      );
      setLoading(false);
    }
  };

  // Cleanup on unmount
  useEffect(() => () => stopAll(), [stopAll]);

  // ── Derived ─────────────────────────────────────────────────────────────
  const currentStep = job ? msgToStep(job.message || "") : 0;
  const showLoader =
    loading && job?.status !== "failed" && !DONE_STATUSES.includes(job?.status);
  const isComplete = DONE_STATUSES.includes(job?.status);

  return (
    <section className="min-h-screen text-white">
      {showLoader && (
        <MultiStepLoader
          steps={SCAN_STEPS}
          currentStep={currentStep}
          status={job?.status}
          message={job?.message || ""}
          crawlerUrls={crawlerUrls}
          liveVulns={liveVulns}
        />
      )}

      <div className="max-w-5xl mx-auto text-center mb-12">
        <div className="flex justify-center mb-4">
          <div className="w-14 h-14 rounded-2xl bg-emerald-500/10 flex items-center justify-center">
            <Shield size={28} className="text-emerald-400" />
          </div>
        </div>
        <h1 className="text-4xl md:text-5xl font-bold text-white mb-3">
          Security Scanner
        </h1>
        <p className="text-slate-400 text-base max-w-xl mx-auto">
          Detect vulnerabilities, misconfigurations, and security issues in any
          web application.
        </p>
      </div>

      <div className="max-w-3xl mx-auto mb-8">
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
              onKeyDown={(e) => e.key === "Enter" && submit()}
              type="text"
              placeholder="https://example.com"
              className="w-full pl-10 pr-4 py-3 rounded-xl bg-slate-900 border border-slate-700
                text-white placeholder-slate-600 focus:outline-none focus:border-emerald-500/50
                transition text-sm"
            />
          </div>
          <AuthForm onChange={setAuthData} mainUrl={url} />
          <button
            onClick={submit}
            disabled={loading}
            className="px-6 py-3 rounded-xl bg-emerald-500 text-slate-900 font-semibold text-sm
              flex items-center justify-center gap-2 transition cursor-pointer
              hover:bg-emerald-400 disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
          >
            {loading ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Search size={16} />
            )}
            {loading ? "Running..." : "Start Scan"}
          </button>
        </div>

        {error && (
          <div className="mt-3 flex items-center gap-2 text-red-400 text-sm bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-2.5">
            <XCircle size={14} className="shrink-0" />
            {error}
          </div>
        )}

        {job && !showLoader && (
          <div
            className={`mt-3 flex items-center gap-2 text-sm px-4 py-2.5 rounded-lg border ${
              isComplete
                ? "bg-emerald-500/10 border-emerald-500/20 text-emerald-400"
                : job.status === "failed"
                  ? "bg-red-500/10 border-red-500/20 text-red-400"
                  : "bg-slate-800 border-slate-700 text-slate-300"
            }`}
          >
            {isComplete ? (
              <CheckCircle size={14} />
            ) : job.status === "failed" ? (
              <XCircle size={14} />
            ) : (
              <Loader2 size={14} className="animate-spin" />
            )}
            <span>{job.message || (isComplete ? "Scan complete" : "")}</span>
          </div>
        )}
      </div>

      {(results.length > 0 || resultsLoading) && (
        <div className="max-w-5xl mx-auto">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <AlertTriangle size={18} className="text-amber-400" />
              Scan Results
            </h2>
            {!resultsLoading && (
              <span className="text-sm text-slate-500">
                {results.length} finding{results.length !== 1 ? "s" : ""} for{" "}
                <span className="text-slate-300">{job?.url}</span>
              </span>
            )}
          </div>

          {!resultsLoading && <SeveritySummary vulns={results} />}

          <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6">
            <VulnTable vulns={results} loading={resultsLoading} />
          </div>
        </div>
      )}

      {isComplete && !resultsLoading && results.length === 0 && (
        <div className="max-w-3xl mx-auto">
          <div className="bg-emerald-500/10 border border-emerald-500/20 rounded-2xl p-8 text-center">
            <CheckCircle size={36} className="text-emerald-400 mx-auto mb-3" />
            <p className="text-lg font-semibold text-emerald-400">
              No Vulnerabilities Found
            </p>
            <p className="text-slate-400 text-sm mt-1">
              The scanned website appears to be clean. Keep it that way!
            </p>
          </div>
        </div>
      )}

      {!job && (
        <div className="max-w-5xl mx-auto mt-8 grid md:grid-cols-3 gap-5">
          {SECURITY_TIPS.map((tip) => (
            <div
              key={tip.title}
              className="bg-[#111827] p-5 rounded-2xl border border-slate-800"
            >
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center text-emerald-400 mb-3">
                {tip.icon}
              </div>
              <h3 className="font-semibold mb-1 text-sm">{tip.title}</h3>
              <p className="text-slate-500 text-xs leading-relaxed">
                {tip.desc}
              </p>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
