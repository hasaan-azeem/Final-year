// src/components/scanner/SkeletonRow.jsx
// ─────────────────────────────────────────────────────────────────────────────
// Animated placeholder row rendered inside VulnTable while results are loading.
// ─────────────────────────────────────────────────────────────────────────────

export default function SkeletonRow() {
  return (
    <tr className="border-b border-slate-800/50 animate-pulse">
      {[1, 2, 3, 4, 5].map((i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-3 bg-slate-800 rounded w-3/4" />
        </td>
      ))}
    </tr>
  );
}