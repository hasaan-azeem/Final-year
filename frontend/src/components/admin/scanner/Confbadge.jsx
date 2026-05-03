// src/components/scanner/ConfBadge.jsx
// ─────────────────────────────────────────────────────────────────────────────
// Small inline badge that colors itself based on confidence level.
// Accepted values: "certain" | "firm" | "tentative"
// ─────────────────────────────────────────────────────────────────────────────

const CONF_STYLES = {
  certain:   "bg-red-500/10   text-red-400   border-red-500/20",
  firm:      "bg-amber-500/10 text-amber-400 border-amber-500/20",
  tentative: "bg-blue-500/10  text-blue-400  border-blue-500/20",
};

export default function ConfBadge({ confidence }) {
  const cls = CONF_STYLES[confidence] ?? CONF_STYLES.tentative;
  return (
    <span
      className={`inline-flex px-2 py-0.5 rounded-full text-xs font-medium border ${cls}`}
    >
      {confidence}
    </span>
  );
}