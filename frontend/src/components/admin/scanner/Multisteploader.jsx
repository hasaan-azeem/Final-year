import { useEffect, useRef } from "react";
import {
  Shield,
  CheckCircle,
  Loader2,
  Globe,
  Check,
  X,
  Clock,
} from "lucide-react";

// ── Small icon shown next to each crawled URL based on its DB status ──────────
function CrawlStatusDot({ status }) {
  if (status === "done")
    return <Check size={10} className="text-emerald-400 shrink-0" />;
  if (status === "failed")
    return <X size={10} className="text-red-400    shrink-0" />;
  return <Clock size={10} className="text-slate-500 shrink-0 animate-pulse" />;
}

export default function MultiStepLoader({
  steps,
  currentStep,
  status,
  message,
  crawlerUrls = [], // live crawler_queue rows, passed from Scanner.jsx
}) {
  // Auto-scroll URL list to bottom so the latest URL stays visible
  const listRef = useRef(null);
  useEffect(() => {
    if (listRef.current) {
      listRef.current.scrollTop = listRef.current.scrollHeight;
    }
  }, [crawlerUrls]);

  // Only show the live feed during the "Crawling Website" step (index 1)
  const showCrawlerFeed = currentStep === 1 && crawlerUrls.length > 0;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm">
      <div className="w-full max-w-md mx-4">
        <div className="bg-[#0d1117] border border-slate-700 rounded-2xl overflow-hidden shadow-2xl">
          {/* ── Header ─────────────────────────────────────────────── */}
          <div className="px-8 pt-8 pb-6 border-b border-slate-800">
            <div className="flex items-center gap-3 mb-2">
              <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                <Shield size={16} className="text-emerald-400" />
              </div>
              <span className="text-sm font-semibold text-emerald-400 uppercase tracking-wider">
                WebXGuard Scanner
              </span>
            </div>
            <p className="text-xs text-slate-500 font-mono truncate">
              {message}
            </p>
          </div>

          {/* ── Steps list ─────────────────────────────────────────── */}
          <div className="px-8 py-6 space-y-5">
            {steps.map((step, i) => {
              const isDone = i < currentStep;
              const isActive = i === currentStep;

              return (
                <div key={i} className="flex items-start gap-4">
                  {/* Status icon */}
                  <div className="shrink-0 mt-0.5">
                    {isDone ? (
                      <div className="w-6 h-6 rounded-full bg-emerald-500/20 flex items-center justify-center">
                        <CheckCircle size={14} className="text-emerald-400" />
                      </div>
                    ) : isActive ? (
                      <div className="w-6 h-6 rounded-full bg-blue-500/20 flex items-center justify-center">
                        <Loader2
                          size={14}
                          className="text-blue-400 animate-spin"
                        />
                      </div>
                    ) : (
                      <div className="w-6 h-6 rounded-full bg-slate-800 flex items-center justify-center">
                        <div className="w-1.5 h-1.5 rounded-full bg-slate-600" />
                      </div>
                    )}
                  </div>

                  {/* Step label + desc + crawler feed */}
                  <div className="flex-1 min-w-0">
                    <p
                      className={`text-sm font-medium transition-colors ${
                        isDone
                          ? "text-emerald-400"
                          : isActive
                            ? "text-white"
                            : "text-slate-600"
                      }`}
                    >
                      {step.label}
                    </p>
                    <p
                      className={`text-xs mt-0.5 transition-colors ${
                        isActive ? "text-slate-400" : "text-slate-700"
                      }`}
                    >
                      {step.desc}
                    </p>

                    {/* ── Live crawler feed ── only on crawling step ── */}
                    {isActive && showCrawlerFeed && (
                      <div
                        ref={listRef}
                        className="mt-3 max-h-32 overflow-y-auto bg-slate-900/70 border border-slate-800 rounded-lg px-3 py-2 space-y-1.5"
                      >
                        {crawlerUrls.map((row, idx) => (
                          <div
                            key={row.id ?? idx}
                            className="flex items-center gap-2 min-w-0"
                          >
                            {/* DB status dot */}
                            <CrawlStatusDot status={row.status} />

                            {/* Globe icon */}
                            <Globe
                              size={10}
                              className="text-slate-600 shrink-0"
                            />

                            {/* URL text — truncated so layout stays clean */}
                            <span
                              className="text-xs font-mono text-slate-400 truncate flex-1"
                              title={row.url}
                            >
                              {row.url}
                            </span>

                            {/* Depth badge e.g. d0, d1, d2 */}
                            <span className="text-[10px] text-slate-700 shrink-0">
                              d{row.depth ?? 0}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* ── Progress bar ───────────────────────────────────────── */}
          <div className="px-8 pb-8">
            <div className="h-1 bg-slate-800 rounded-full overflow-hidden">
              <div
                className="h-full bg-linear-to-r from-emerald-600 to-emerald-400 rounded-full transition-all duration-700"
                style={{
                  width: `${((currentStep + 1) / steps.length) * 100}%`,
                }}
              />
            </div>
            <p className="text-xs text-slate-600 mt-2 text-right">
              Step {Math.min(currentStep + 1, steps.length)} of {steps.length}
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
