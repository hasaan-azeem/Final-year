export default function SecurityGauge({ score }) {
  const s = Math.max(0, Math.min(100, score));
  const color = s >= 70 ? "#ef4444" : s >= 40 ? "#f59e0b" : "#10b981";

  return (
    <div className="text-center">
      <div
        className="text-4xl font-bold"
        style={{ color }}
      >
        {s}
      </div>
      <p className="text-sm text-slate-400 mt-1">Threat Score</p>
    </div>
  );
}