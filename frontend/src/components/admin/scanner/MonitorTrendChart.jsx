import { TrendingUp } from "lucide-react";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";

/**
 * Props
 * ─────
 * data    {Array}   trend rows from getMonitorTrend()
 *                   each row: { started_at, vuln_count, critical, high, medium }
 * loading {boolean} show skeleton while trend is being fetched
 */
export default function MonitorTrendChart({ data, loading }) {
  if (loading) {
    return (
      <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 mb-6 animate-pulse">
        <div className="h-4 bg-slate-800 rounded w-1/3 mb-6" />
        <div className="h-48 bg-slate-800 rounded" />
      </div>
    );
  }

  if (!data || data.length === 0) return null;

  const chartData = data.map((d) => ({
    time:     d.started_at
                ? new Date(d.started_at).toLocaleTimeString([], {
                    hour:   "2-digit",
                    minute: "2-digit",
                  })
                : "",
    total:    d.vuln_count,
    critical: d.critical,
    high:     d.high,
    medium:   d.medium,
  }));

  return (
    <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 mb-6">
      <div className="flex items-center gap-2 mb-6">
        <TrendingUp size={16} className="text-emerald-400" />
        <h3 className="text-base font-semibold">Vulnerability Trend Over Time</h3>
      </div>

      <ResponsiveContainer width="100%" height={220}>
        <LineChart
          data={chartData}
          margin={{ top: 5, right: 20, left: 0, bottom: 5 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
          <XAxis dataKey="time" tick={{ fill: "#64748b", fontSize: 11 }} />
          <YAxis                tick={{ fill: "#64748b", fontSize: 11 }} />
          <Tooltip
            contentStyle={{
              backgroundColor: "#0d1117",
              border:          "1px solid #1e293b",
              borderRadius:    8,
            }}
            labelStyle={{ color: "#94a3b8" }}
          />
          <Legend />
          <Line type="monotone" dataKey="total"    stroke="#10b981" strokeWidth={2} dot={false} name="Total"    />
          <Line type="monotone" dataKey="critical" stroke="#ef4444" strokeWidth={2} dot={false} name="Critical" />
          <Line type="monotone" dataKey="high"     stroke="#f59e0b" strokeWidth={2} dot={false} name="High"     />
          <Line type="monotone" dataKey="medium"   stroke="#3b82f6" strokeWidth={2} dot={false} name="Medium"   />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}