import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import Skeleton from "./Skeleton";

export default function WeeklyChart({ data, loading }) {
  if (loading) return <Skeleton className="h-48 w-full" />;

  return (
    <ResponsiveContainer width="100%" height={180}>
      <BarChart data={data}>
        <CartesianGrid stroke="#1e293b" />
        <XAxis dataKey="day" stroke="#64748b" />
        <YAxis stroke="#64748b" />
        <Tooltip />
        <Bar dataKey="scans" fill="#10b981" />
      </BarChart>
    </ResponsiveContainer>
  );
}