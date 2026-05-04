import { useState } from "react";
import { Settings, X, Plus, Trash2, Activity } from "lucide-react";

const DEFAULTS = {
  max_concurrent_requests: 5,
  max_pages: 200,
  max_depth: 0,
  monitor_interval_minutes: 1,
  max_js_browsers: 2,
  user_agent:
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
  target_urls: [],
  domain_js_wait: {},
};

export default function MonitorConfigModal({ onChange }) {
  const [open, setOpen] = useState(false);
  const [config, setConfig] = useState(DEFAULTS);
  const [newUrl, setNewUrl] = useState("");
  const [newDomain, setNewDomain] = useState("");
  const [newWait, setNewWait] = useState(4000);
  const [urlErr, setUrlErr] = useState("");

  const update = (key, val) => setConfig((prev) => ({ ...prev, [key]: val }));

  const addUrl = () => {
    const u = newUrl.trim();
    if (!u) return;
    if (!u.startsWith("http")) return setUrlErr("Must start with http:// or https://");
    if (config.target_urls.includes(u)) return setUrlErr("Already added");
    update("target_urls", [...config.target_urls, u]);
    setNewUrl("");
    setUrlErr("");
  };

  const removeUrl = (i) =>
    update("target_urls", config.target_urls.filter((_, idx) => idx !== i));

  const addDomainWait = () => {
    if (!newDomain.trim()) return;
    update("domain_js_wait", {
      ...config.domain_js_wait,
      [newDomain.trim()]: newWait,
    });
    setNewDomain("");
    setNewWait(4000);
  };

  const removeDomainWait = (d) => {
    const { [d]: _, ...rest } = config.domain_js_wait;
    update("domain_js_wait", rest);
  };

  const apply = () => { onChange?.(config); setOpen(false); };
  const reset = () => {
    setConfig(DEFAULTS);
    setNewUrl(""); setNewDomain(""); setNewWait(4000); setUrlErr("");
  };

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        title="Monitor configuration"
        className="p-2 rounded-xl border border-slate-700 text-slate-400
          hover:text-emerald-400 hover:border-emerald-500/40 transition cursor-pointer"
      >
        <Settings size={15} />
      </button>

      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="w-full max-w-lg mx-4 bg-[#111827] border border-slate-700
            rounded-2xl p-6 shadow-2xl max-h-[90vh] overflow-y-auto">

            {/* Header */}
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                  <Activity size={14} className="text-emerald-400" />
                </div>
                <span className="font-semibold text-white text-sm">
                  Monitor Configuration
                </span>
              </div>
              <button
                onClick={() => setOpen(false)}
                className="p-1.5 rounded-lg border border-slate-700 text-slate-500
                  hover:text-white hover:border-slate-500 transition cursor-pointer"
              >
                <X size={14} />
              </button>
            </div>

            {/* Crawler Limits */}
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
              Crawler Limits
            </p>
            <div className="grid grid-cols-2 gap-3 mb-5">
              {[
                { key: "max_pages", label: "Max Pages" },
                { key: "max_depth", label: "Max Depth" },
                { key: "max_concurrent_requests", label: "Concurrent Requests" },
                { key: "max_js_browsers", label: "JS Browsers" },
              ].map(({ key, label }) => (
                <div key={key}>
                  <label className="text-xs text-slate-400 block mb-1">{label}</label>
                  <input
                    type="number"
                    value={config[key]}
                    onChange={(e) => update(key, Number(e.target.value))}
                    className="w-full px-3 py-2 bg-slate-900 border border-slate-700
                      rounded-lg text-sm text-white focus:outline-none
                      focus:border-emerald-500/50 transition"
                  />
                </div>
              ))}
            </div>

            {/* Schedule */}
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
              Schedule
            </p>
            <div className="mb-5">
              <label className="text-xs text-slate-400 block mb-1">
                Interval (minutes)
              </label>
              <input
                type="number"
                value={config.monitor_interval_minutes}
                onChange={(e) =>
                  update("monitor_interval_minutes", Number(e.target.value))
                }
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700
                  rounded-lg text-sm text-white focus:outline-none
                  focus:border-emerald-500/50 transition"
              />
            </div>

            {/* Target URLs */}
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
              Target URLs
            </p>
            <div className="space-y-1.5 mb-2">
              {config.target_urls.map((u, i) => (
                <div
                  key={i}
                  className="flex items-center gap-2 bg-slate-900 border border-slate-700
                    rounded-lg px-3 py-2"
                >
                  <span className="flex-1 text-xs text-slate-300 truncate font-mono">
                    {u}
                  </span>
                  <button
                    onClick={() => removeUrl(i)}
                    className="text-slate-600 hover:text-red-400 transition cursor-pointer"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
            </div>
            <div className="flex gap-2 mb-1">
              <input
                value={newUrl}
                onChange={(e) => { setNewUrl(e.target.value); setUrlErr(""); }}
                onKeyDown={(e) => e.key === "Enter" && addUrl()}
                placeholder="https://example.com"
                className="flex-1 px-3 py-2 bg-slate-900 border border-slate-700
                  rounded-lg text-xs text-white placeholder-slate-600
                  focus:outline-none focus:border-emerald-500/50 transition"
              />
              <button
                onClick={addUrl}
                className="px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30
                  text-emerald-400 hover:bg-emerald-500/20 transition cursor-pointer"
              >
                <Plus size={14} />
              </button>
            </div>
            {urlErr && (
              <p className="text-[10px] text-red-400 mb-3">{urlErr}</p>
            )}

            {/* Domain JS Wait */}
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2 mt-5">
              JS Wait Per Domain (ms)
            </p>
            <div className="space-y-1.5 mb-2">
              {Object.entries(config.domain_js_wait).map(([d, w]) => (
                <div
                  key={d}
                  className="flex items-center gap-2 bg-slate-900 border border-slate-700
                    rounded-lg px-3 py-2"
                >
                  <span className="flex-1 text-xs text-slate-300 font-mono truncate">
                    {d}
                  </span>
                  <span className="text-xs text-emerald-400 shrink-0">{w}ms</span>
                  <button
                    onClick={() => removeDomainWait(d)}
                    className="text-slate-600 hover:text-red-400 transition cursor-pointer"
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              ))}
            </div>
            <div className="flex gap-2 mb-5">
              <input
                value={newDomain}
                onChange={(e) => setNewDomain(e.target.value)}
                placeholder="slow-spa.example.com"
                className="flex-1 px-3 py-2 bg-slate-900 border border-slate-700
                  rounded-lg text-xs text-white placeholder-slate-600
                  focus:outline-none focus:border-emerald-500/50 transition"
              />
              <input
                type="number"
                value={newWait}
                onChange={(e) => setNewWait(Number(e.target.value))}
                className="w-20 px-3 py-2 bg-slate-900 border border-slate-700
                  rounded-lg text-xs text-white focus:outline-none
                  focus:border-emerald-500/50 transition"
              />
              <button
                onClick={addDomainWait}
                className="px-3 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30
                  text-emerald-400 hover:bg-emerald-500/20 transition cursor-pointer"
              >
                <Plus size={14} />
              </button>
            </div>

            {/* User Agent */}
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
              User Agent
            </p>
            <div className="mb-5">
              <input
                type="text"
                value={config.user_agent}
                onChange={(e) => update("user_agent", e.target.value)}
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700
                  rounded-lg text-xs text-white focus:outline-none
                  focus:border-emerald-500/50 transition font-mono"
              />
            </div>

            {/* Footer */}
            <div className="flex gap-2">
              <button
                onClick={reset}
                className="flex-1 py-2.5 rounded-xl border border-slate-700 text-slate-400
                  text-sm hover:text-white hover:border-slate-500 transition cursor-pointer"
              >
                Reset Defaults
              </button>
              <button
                onClick={apply}
                className="flex-1 py-2.5 rounded-xl bg-emerald-500 text-slate-900
                  font-semibold text-sm hover:bg-emerald-400 transition cursor-pointer"
              >
                Apply
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}