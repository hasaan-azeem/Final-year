import { useState, useEffect } from "react";
import { Settings, X } from "lucide-react";

const DEFAULTS = {
  scan_type: "passive",
  max_pages: 1000,
  max_depth: 1,
  max_concurrent_requests: 5,
  request_timeout: 30,
  max_js_browsers: 2,
  obey_robots_txt: false,
};

const SCAN_TYPES = [
  { value: "passive", label: "Passive", desc: "No active probing", icon: "👁" },
  { value: "active", label: "Active", desc: "Full active tests", icon: "⚡" },
  { value: "full", label: "Full", desc: "Passive + active", icon: "🔬" },
];

export default function ScanConfigModal({ onChange }) {
  const [open, setOpen] = useState(false);
  const [config, setConfig] = useState(DEFAULTS);

  const update = (key, val) => setConfig((prev) => ({ ...prev, [key]: val }));

  const reset = () => setConfig(DEFAULTS);
  const apply = () => {
    onChange?.(config);
    setOpen(false);
  };

  useEffect(() => {
    onChange?.(config);
  }, []);

  return (
    <>
      {/* Trigger button */}
      <button
        onClick={() => setOpen(true)}
        title="Scan configuration"
        className="p-2.5 rounded-xl border border-slate-700 text-slate-400
          hover:text-emerald-400 hover:border-emerald-500/40 transition cursor-pointer"
      >
        <Settings size={16} />
      </button>

      {/* Modal */}
      {open && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div
            className="w-full max-w-md mx-4 bg-[#111827] border border-slate-700
            rounded-2xl p-6 shadow-2xl max-h-[90vh] overflow-y-auto"
          >
            {/* Header */}
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2.5">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 flex items-center justify-center">
                  <Settings size={14} className="text-emerald-400" />
                </div>
                <span className="font-semibold text-white text-sm">
                  Scan Configuration
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

            {/* Scan Type */}
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
              Scan Mode
            </p>
            <div className="grid grid-cols-3 gap-2 mb-5">
              {SCAN_TYPES.map((t) => (
                <button
                  key={t.value}
                  onClick={() => update("scan_type", t.value)}
                  className={`p-3 rounded-xl border text-center transition cursor-pointer
                    ${
                      config.scan_type === t.value
                        ? "border-emerald-500/60 bg-emerald-500/8 text-emerald-400"
                        : "border-slate-700 bg-slate-900 text-slate-400 hover:border-slate-500"
                    }`}
                >
                  <div className="text-base mb-1">{t.icon}</div>
                  <div className="text-xs font-semibold">{t.label}</div>
                  <div className="text-[10px] text-slate-500 mt-0.5">
                    {t.desc}
                  </div>
                </button>
              ))}
            </div>

            {/* Crawler limits */}
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
              Crawler Limits
            </p>
            <div className="grid grid-cols-2 gap-3 mb-4">
              {[
                { key: "max_pages", label: "Max Pages" },
                { key: "max_depth", label: "Max Depth" },
                {
                  key: "max_concurrent_requests",
                  label: "Concurrent Requests",
                },
                { key: "max_js_browsers", label: "JS Browsers" },
              ].map(({ key, label }) => (
                <div key={key}>
                  <label className="text-xs text-slate-400 block mb-1">
                    {label}
                  </label>
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

            {/* Network */}
            <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-2">
              Network
            </p>
            <div className="mb-4">
              <label className="text-xs text-slate-400 block mb-1">
                Request Timeout (sec)
              </label>
              <input
                type="number"
                value={config.request_timeout}
                onChange={(e) =>
                  update("request_timeout", Number(e.target.value))
                }
                className="w-full px-3 py-2 bg-slate-900 border border-slate-700
                  rounded-lg text-sm text-white focus:outline-none
                  focus:border-emerald-500/50 transition"
              />
            </div>

            {/* Toggle — FIXED */}
            <div
              className="flex items-center justify-between px-3 py-2.5 bg-slate-900
  border border-slate-700 rounded-lg mb-5"
            >
              <span className="text-xs text-slate-400">Respect robots.txt</span>
              <button
                onClick={() =>
                  update("obey_robots_txt", !config.obey_robots_txt)
                }
                style={{
                  position: "relative",
                  width: 34,
                  height: 18,
                  flexShrink: 0,
                }}
                className={`rounded-full transition-colors cursor-pointer
      ${config.obey_robots_txt ? "bg-emerald-500" : "bg-slate-700"}`}
              >
                <span
                  style={{
                    position: "absolute",
                    top: 2,
                    left: config.obey_robots_txt ? 16 : 2,
                    width: 14,
                    height: 14,
                    background: "#fff",
                    borderRadius: "50%",
                    transition: "left .2s",
                    boxShadow: "0 1px 3px rgba(0,0,0,.4)",
                  }}
                />
              </button>
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
