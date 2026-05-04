// src/components/admin/scanner/VulnTable.jsx
// ─────────────────────────────────────────────────────────────────────────────
// Vulnerability table — array of vuln objects (from backend) ko handle karta hai
// Backend ka format: [{ id, page_url, title, category, confidence, cwe,
//                       severity, cvss_score, severity_level, target_priority,
//                       priority_category, ..., remediation: {...} }, ...]
//
// ★ NEW: Click any vuln row → expand to show AI-generated fix suggestion
//        (RemediationPanel component renders inside each expanded row)
// ─────────────────────────────────────────────────────────────────────────────

import { useState } from "react";
import {
  ChevronRight,
  ChevronDown,
  AlertTriangle,
  ShieldOff,
  Sparkles,
} from "lucide-react";

import RemediationPanel from "../../../pages/admin/RemediationPanel";

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

// Highest priority finding inside a group (used for the URL header chip)
function highestPriority(items) {
  const order = { critical: 4, high: 3, medium: 2, low: 1 };
  return items.reduce((acc, v) => {
    const a = order[(acc?.priority_category || "").toLowerCase()] || 0;
    const b = order[(v?.priority_category || "").toLowerCase()] || 0;
    return b > a ? v : acc;
  }, items[0]);
}

export default function VulnTable({ vulns, loading }) {
  // Set of URL groups currently expanded
  const [expandedUrls, setExpandedUrls] = useState(() => new Set());
  // Set of vulnerability IDs currently expanded (showing remediation panel)
  const [expandedVulns, setExpandedVulns] = useState(() => new Set());

  if (loading) {
    return (
      <div className="text-slate-400 text-sm py-6 text-center">
        Loading vulnerabilities...
      </div>
    );
  }

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

  const toggleUrl = (url) => {
    setExpandedUrls((prev) => {
      const next = new Set(prev);
      next.has(url) ? next.delete(url) : next.add(url);
      return next;
    });
  };

  const toggleVuln = (id) => {
    setExpandedVulns((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      {urls.map((url) => {
        const items = grouped[url];
        const isOpen = expandedUrls.has(url);
        const highest = highestPriority(items);

        return (
          <div
            key={url}
            className="bg-slate-900/40 border border-slate-800 rounded-xl overflow-hidden"
          >
            {/* URL header (clickable) */}
            <button
              onClick={() => toggleUrl(url)}
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
                {items.map((v, idx) => {
                  const vid = v.id ?? `${url}-${idx}`;
                  const isVulnOpen = expandedVulns.has(vid);
                  const hasRemediation = Boolean(v.remediation);

                  return (
                    <div
                      key={vid}
                      className="border-b border-slate-800/40 last:border-0"
                    >
                      {/* Vulnerability summary row — clickable */}
                      <button
                        onClick={() => toggleVuln(vid)}
                        className="w-full flex items-start gap-3 px-4 py-3 hover:bg-slate-800/30 transition cursor-pointer text-left"
                      >
                        <ChevronDown
                          size={14}
                          className={`text-slate-500 shrink-0 mt-1 transition-transform ${
                            isVulnOpen ? "rotate-180" : ""
                          }`}
                        />
                        <AlertTriangle
                          size={13}
                          className="text-amber-400 shrink-0 mt-1"
                        />

                        <div className="flex-1 min-w-0">
                          <div className="flex items-start justify-between gap-3 flex-wrap">
                            <p className="text-sm text-slate-100 font-medium leading-tight">
                              {v.title || "Untitled finding"}
                            </p>
                            <div className="flex items-center gap-2 shrink-0">
                              <span
                                className={`text-[10px] px-2 py-0.5 rounded-full border ${badgeClass(
                                  v.priority_category,
                                )}`}
                              >
                                {v.priority_category || "—"}
                              </span>
                              {v.cvss_score != null && (
                                <span className="text-[10px] text-slate-500 font-mono">
                                  CVSS {Number(v.cvss_score).toFixed(1)}
                                </span>
                              )}
                            </div>
                          </div>

                          <div className="flex items-center gap-3 mt-1 text-[11px] text-slate-500 flex-wrap">
                            {v.category && <span>{v.category}</span>}
                            {v.cwe && (
                              <span className="font-mono">{v.cwe}</span>
                            )}
                            {v.confidence && (
                              <span className="capitalize">
                                Confidence: {v.confidence}
                              </span>
                            )}
                            {hasRemediation && !isVulnOpen && (
                              <span className="inline-flex items-center gap-1 text-emerald-400">
                                <Sparkles size={10} />
                                View Fix
                              </span>
                            )}
                          </div>
                        </div>
                      </button>

                      {/* Remediation panel (expanded) */}
                      {isVulnOpen && (
                        <RemediationPanel
                          remediation={v.remediation}
                          loading={!hasRemediation}
                        />
                      )}
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}
