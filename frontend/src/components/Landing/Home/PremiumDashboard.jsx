import React, { useEffect, useState } from "react";

const logs = [
  "Initializing security scan...",
  "Checking SSL configuration...",
  "Scanning open ports...",
  "Analyzing OWASP vulnerabilities...",
  "Testing injection points...",
  "Checking authentication flow...",
  "Inspecting API endpoints...",
  "Finalizing report...",
];

const PremiumDashboard = () => {
  const [progress, setProgress] = useState(0);
  const [logIndex, setLogIndex] = useState(0);

  // Progress animation
  useEffect(() => {
    const interval = setInterval(() => {
      setProgress((prev) => (prev < 100 ? prev + 1 : 100));
    }, 80);

    return () => clearInterval(interval);
  }, []);

  // Fake logs animation
  useEffect(() => {
    const logInterval = setInterval(() => {
      setLogIndex((prev) => (prev < logs.length - 1 ? prev + 1 : prev));
    }, 1200);

    return () => clearInterval(logInterval);
  }, []);

  return (
    <div className="absolute left-1/2 bottom-[-120px] -translate-x-1/2 w-[92%] max-w-6xl z-30 top-160 hidden sm:block">
      {/* Glow */}
      <div className="absolute inset-0 bg-[#059669] opacity-20 blur-3xl rounded-3xl -z-10" />

      <div className="bg-black/40 backdrop-blur-2xl border border-white/10 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-white/10">
          <p className="text-sm text-gray-200">Security Scan Dashboard</p>
          <span className="text-xs px-3 py-1 rounded-full bg-[#059669]/20 text-[#059669] border border-[#059669]/30">
            Live Scan
          </span>
        </div>

        {/* Progress Bar */}
        <div className="px-5 pt-4">
          <div className="w-full h-2 bg-white/10 rounded-full overflow-hidden">
            <div
              className="h-full bg-[#059669] transition-all duration-300"
              style={{ width: `${progress}%` }}
            />
          </div>

          <p className="text-xs text-gray-400 mt-2">
            Scan Progress: {progress}%
          </p>
        </div>

        {/* Content */}
        <div className="p-5 md:p-6 grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Left stats */}
          <div className="space-y-4">
            <div className="bg-white/5 border border-white/10 rounded-xl p-4">
              <p className="text-xs text-gray-400">Status</p>
              <p className="text-lg font-semibold text-[#059669]">
                Scanning Active
              </p>
            </div>

            <div className="bg-white/5 border border-white/10 rounded-xl p-4">
              <p className="text-xs text-gray-400">Threats Found</p>
              <p className="text-lg font-semibold text-red-400">3 Critical</p>
            </div>
          </div>

          {/* Fake Live Logs */}
          <div className="bg-black/30 border border-white/10 rounded-xl p-4 h-48 overflow-hidden">
            <p className="text-xs text-gray-400 mb-3">Live Security Logs</p>

            <div className="space-y-2 text-xs font-mono text-gray-300">
              {logs.slice(0, logIndex + 1).map((log, i) => (
                <p key={i} className="opacity-80 animate-pulse">
                  <span className="text-[#059669]">●</span> {log}
                </p>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default PremiumDashboard;
