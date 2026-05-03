// src/components/scanner/CvssBadge.jsx
// ─────────────────────────────────────────────────────────────────────────────
// Displays a CVSS score with color coding per CVSS v3.1 severity bands:
//   Critical >= 9.0  |  High >= 7.0  |  Medium >= 4.0  |  Low < 4.0
// ─────────────────────────────────────────────────────────────────────────────

export default function CvssBadge({ score }) {
  const s = parseFloat(score) || 0;

  if (!s) {
    return <span className="text-slate-600 text-xs">—</span>;
  }

  const cls =
    s >= 9 ? "text-red-400    bg-red-500/10"    :
    s >= 7 ? "text-orange-400 bg-orange-500/10" :
    s >= 4 ? "text-amber-400  bg-amber-500/10"  :
             "text-emerald-400 bg-emerald-500/10";

  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-bold ${cls}`}>
      {s.toFixed(1)}
    </span>
  );
}