// src/components/admin/scanner/RemediationPanel.jsx
// ─────────────────────────────────────────────────────────────────────────────
// AI-generated fix for one vulnerability. Displays:
//   • Summary (1-2 sentences explaining the vulnerability)
//   • Numbered fix steps
//   • Secure code example (syntax-highlighted)
//   • References (clickable links to OWASP, MITRE, etc.)
//   • Provenance badge (static KB / AI / fallback)
//
// Renders inline inside an expanded VulnTable row.
// ─────────────────────────────────────────────────────────────────────────────

import { useState } from "react";
import {
  Sparkles,
  ShieldCheck,
  Copy,
  Check,
  ExternalLink,
  Code2,
  ListChecks,
  BookOpen,
  Loader2,
  Database,
  Zap,
} from "lucide-react";

// ─────────────────────────────────────────────────────────────────────────────
// Source badge — shows whether fix came from cache, KB, or AI
// ─────────────────────────────────────────────────────────────────────────────
function SourceBadge({ source, cached, model }) {
  const label = cached
    ? "Cached"
    : source === "static"
      ? "Knowledge Base"
      : source === "ai"
        ? "AI Generated"
        : "Generic";

  const icon = cached ? (
    <Database size={10} />
  ) : source === "ai" ? (
    <Sparkles size={10} />
  ) : source === "static" ? (
    <ShieldCheck size={10} />
  ) : (
    <Zap size={10} />
  );

  const cls = cached
    ? "text-blue-400 bg-blue-500/10 border-blue-500/20"
    : source === "ai"
      ? "text-purple-400 bg-purple-500/10 border-purple-500/20"
      : source === "static"
        ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
        : "text-slate-400 bg-slate-500/10 border-slate-500/20";

  return (
    <span
      className={`inline-flex items-center gap-1 text-[10px] px-2 py-0.5 rounded-full border font-medium ${cls}`}
      title={model || ""}
    >
      {icon}
      {label}
    </span>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Code block with copy button
// ─────────────────────────────────────────────────────────────────────────────
function CodeBlock({ code }) {
  const [copied, setCopied] = useState(false);
  if (!code) return null;

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* clipboard unavailable */
    }
  };

  return (
    <div className="relative group">
      <pre className="text-xs font-mono text-slate-300 bg-[#0a0e14] border border-slate-800 rounded-lg p-4 overflow-x-auto leading-relaxed">
        {code}
      </pre>
      <button
        onClick={handleCopy}
        className="absolute top-2 right-2 p-1.5 rounded-md bg-slate-800/80 border border-slate-700
          text-slate-400 hover:text-emerald-400 hover:border-emerald-500/40
          opacity-0 group-hover:opacity-100 transition cursor-pointer"
        title="Copy code"
      >
        {copied ? <Check size={11} /> : <Copy size={11} />}
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Loading skeleton — shown while AI generates
// ─────────────────────────────────────────────────────────────────────────────
function LoadingSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="h-3 bg-slate-800 rounded w-3/4" />
      <div className="h-3 bg-slate-800 rounded w-2/3" />
      <div className="space-y-2 mt-5">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="flex items-start gap-3">
            <div className="w-5 h-5 rounded-full bg-slate-800 shrink-0 mt-0.5" />
            <div className="flex-1 space-y-1.5">
              <div className="h-2.5 bg-slate-800 rounded w-full" />
              <div className="h-2.5 bg-slate-800 rounded w-4/5" />
            </div>
          </div>
        ))}
      </div>
      <div className="flex items-center gap-2 text-xs text-slate-500 mt-4">
        <Loader2 size={12} className="animate-spin text-purple-400" />
        AI is generating fix suggestions...
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main panel
// ─────────────────────────────────────────────────────────────────────────────
export default function RemediationPanel({ remediation, loading }) {
  if (loading) {
    return (
      <div className="border-t border-slate-800 px-5 py-5 bg-[#0d1117]">
        <LoadingSkeleton />
      </div>
    );
  }

  if (!remediation) {
    return (
      <div className="border-t border-slate-800 px-5 py-5 bg-[#0d1117]">
        <p className="text-sm text-slate-500 italic">
          No remediation available for this finding.
        </p>
      </div>
    );
  }

  const {
    summary,
    fix_steps = [],
    code_example,
    references = [],
    source,
    model,
    cached,
  } = remediation;

  return (
    <div className="border-t border-slate-800 px-5 py-5 bg-[#0d1117] space-y-5">
      {/* Header with source badge */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <div className="w-7 h-7 rounded-lg bg-emerald-500/10 flex items-center justify-center">
            <ShieldCheck size={14} className="text-emerald-400" />
          </div>
          <h4 className="text-sm font-semibold text-white">
            Recommended Fix
          </h4>
        </div>
        <SourceBadge source={source} cached={cached} model={model} />
      </div>

      {/* Summary */}
      {summary && (
        <p className="text-sm text-slate-300 leading-relaxed pl-1">
          {summary}
        </p>
      )}

      {/* Fix steps */}
      {fix_steps.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-3">
            <ListChecks size={13} className="text-emerald-400" />
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Mitigation Steps
            </span>
          </div>
          <ol className="space-y-2.5">
            {fix_steps.map((step, i) => (
              <li
                key={i}
                className="flex items-start gap-3 text-sm text-slate-300 leading-relaxed"
              >
                <span className="shrink-0 w-5 h-5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-[10px] font-bold flex items-center justify-center mt-0.5">
                  {i + 1}
                </span>
                <span>{step}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Code example */}
      {code_example && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <Code2 size={13} className="text-emerald-400" />
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              Secure Code Example
            </span>
          </div>
          <CodeBlock code={code_example} />
        </div>
      )}

      {/* References */}
      {references.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <BookOpen size={13} className="text-emerald-400" />
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">
              References
            </span>
          </div>
          <div className="flex flex-wrap gap-2">
            {references.map((ref, i) => (
              <a
                key={i}
                href={ref.url}
                target="_blank"
                rel="noreferrer"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg
                  bg-slate-800/60 border border-slate-700 text-xs text-slate-300
                  hover:text-emerald-400 hover:border-emerald-500/40 transition cursor-pointer"
              >
                <span className="truncate max-w-[280px]">{ref.title}</span>
                <ExternalLink size={10} className="shrink-0" />
              </a>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}