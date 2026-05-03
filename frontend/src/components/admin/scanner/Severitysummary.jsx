// 4 cards: Critical / High / Medium / Total
// Backend ka `priority_category` field use karta hai (ML model se aata hai).
// Agar woh missing ho to severity_level (numeric 0-10) se fallback.

function categorize(v) {
  // Pehle ML category dekho
  const cat = (v.priority_category || "").toLowerCase();
  if (cat) return cat;

  // Fallback: severity_level se determine karein
  const lvl = Number(v.severity_level || v.cvss_score || 0);
  if (lvl >= 8.5) return "critical";
  if (lvl >= 6.5) return "high";
  if (lvl >= 4.5) return "medium";
  if (lvl > 0) return "low";
  return "unknown";
}

export default function SeveritySummary({ vulns }) {
  const list = Array.isArray(vulns) ? vulns : [];

  const critical = list.filter((v) => categorize(v) === "critical").length;
  const high = list.filter((v) => categorize(v) === "high").length;
  const medium = list.filter((v) => categorize(v) === "medium").length;
  const total = list.length;

  const cards = [
    {
      label: "Critical",
      count: critical,
      color: "text-red-400",
      bg: "bg-red-500/10 border-red-500/20",
    },
    {
      label: "High",
      count: high,
      color: "text-orange-400",
      bg: "bg-orange-500/10 border-orange-500/20",
    },
    {
      label: "Medium",
      count: medium,
      color: "text-amber-400",
      bg: "bg-amber-500/10 border-amber-500/20",
    },
    {
      label: "Total",
      count: total,
      color: "text-white",
      bg: "bg-slate-800 border-slate-700",
    },
  ];

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
      {cards.map((c) => (
        <div key={c.label} className={`rounded-xl border p-4 ${c.bg}`}>
          <p className="text-xs text-slate-400 mb-1">{c.label}</p>
          <p className={`text-2xl font-bold ${c.color}`}>{c.count}</p>
        </div>
      ))}
    </div>
  );
}
