// Vulnerability table — array of vuln objects (from backend) ko handle karta hai
// Backend ka format: [{ id, page_url, title, category, confidence, cwe,
//                       severity, cvss_score, severity_level, target_priority,
//                       priority_category, ... }, ...]

import { ChevronRight, AlertTriangle, ShieldOff } from "lucide-react";
import { useState } from "react";

// Priority category badge colours
function badgeClass(category) {
  switch ((category || "").toLowerCase()) {
    case "critical":
      return "bg-red-500/10 text-red-400 border-red-500/20";
    case "high":
      return "bg-orange-500/10 text-orange-400 border-orange-500/20";
    case "medium":
      return "bg-amber-500/10 text-amber-400 border-amber-500/20";
    case "low":
      return "bg-blue-500/10 text-blue-400 border-blue-500/20";
    default:
      return "bg-slate-700/40 text-slate-300 border-slate-600/30";
  }
}

// Group vulns by page_url for cleaner display
function groupByUrl(vulns) {
  const groups = {};
  for (const v of vulns) {
    const key = v.page_url || v.url || "unknown";
    if (!groups[key]) groups[key] = [];
    groups[key].push(v);
  }
  return groups;
}

export default function VulnTable({ vulns, loading }) {
  const [expanded, setExpanded] = useState(() => new Set());

  if (loading) {
    return (
      <div className="text-slate-400 text-sm py-6 text-center">
        Loading vulnerabilities...
      </div>
    );
  }

  // ✅ Defensive: agar array nahi mila to empty list treat karein
  const list = Array.isArray(vulns) ? vulns : [];

  if (list.length === 0) {
    return (
      <div className="text-slate-400 text-sm py-6 text-center">
        No vulnerabilities found.
      </div>
    );
  }

  const grouped = groupByUrl(list);
  const urls = Object.keys(grouped);

  const toggle = (url) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(url)) next.delete(url);
      else next.add(url);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      {urls.map((url) => {
        const items = grouped[url];
        const isOpen = expanded.has(url);

        // Highest priority in this group (for the URL header chip)
        const highest = items.reduce((acc, v) => {
          const order = { critical: 4, high: 3, medium: 2, low: 1 };
          const a = order[(acc?.priority_category || "").toLowerCase()] || 0;
          const b = order[(v?.priority_category || "").toLowerCase()] || 0;
          return b > a ? v : acc;
        }, items[0]);

        return (
          <div
            key={url}
            className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden"
          >
            {/* URL header (clickable) */}
            <button
              onClick={() => toggle(url)}
              className="w-full flex items-center justify-between gap-3 px-4 py-3 hover:bg-slate-800/40 transition cursor-pointer text-left"
            >
              <div className="flex items-center gap-3 min-w-0 flex-1">
                <ChevronRight
                  size={14}
                  className={`text-slate-500 shrink-0 transition-transform ${
                    isOpen ? "rotate-90" : ""
                  }`}
                />
                <ShieldOff size={14} className="text-emerald-400 shrink-0" />
                <span className="text-sm text-slate-200 truncate font-mono">
                  {url}
                </span>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <span
                  className={`text-[10px] px-2 py-0.5 rounded-full border ${badgeClass(
                    highest?.priority_category,
                  )}`}
                >
                  {highest?.priority_category || "Issue"}
                </span>
                <span className="text-xs text-slate-500">
                  {items.length} {items.length === 1 ? "issue" : "issues"}
                </span>
              </div>
            </button>

            {/* Issue list (expanded) */}
            {isOpen && (
              <div className="border-t border-slate-800">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-slate-500 border-b border-slate-800/60 bg-slate-900/30">
                      <th className="text-left px-4 py-2 text-xs font-medium">
                        Title
                      </th>
                      <th className="text-left px-4 py-2 text-xs font-medium">
                        Category
                      </th>
                      <th className="text-left px-4 py-2 text-xs font-medium">
                        Risk
                      </th>
                      <th className="text-left px-4 py-2 text-xs font-medium">
                        CVSS
                      </th>
                      <th className="text-left px-4 py-2 text-xs font-medium">
                        CWE
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((v, idx) => (
                      <tr
                        key={v.id ?? idx}
                        className="border-b border-slate-800/40 last:border-0 hover:bg-slate-800/20"
                      >
                        <td className="px-4 py-3 text-slate-200">
                          <div className="flex items-start gap-2">
                            <AlertTriangle
                              size={12}
                              className="text-amber-400 mt-1 shrink-0"
                            />
                            <span>{v.title || "Untitled finding"}</span>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-slate-400 text-xs">
                          {v.category || "—"}
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`text-[10px] px-2 py-0.5 rounded-full border ${badgeClass(
                              v.priority_category,
                            )}`}
                          >
                            {v.priority_category || "—"}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-slate-400 text-xs">
                          {v.cvss_score != null
                            ? Number(v.cvss_score).toFixed(1)
                            : "—"}
                        </td>
                        <td className="px-4 py-3 text-slate-500 text-xs font-mono">
                          {v.cwe || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}