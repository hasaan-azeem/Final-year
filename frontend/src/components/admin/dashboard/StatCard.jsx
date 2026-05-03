import Skeleton from "./Skeleton";

export default function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  color,
  loading,
}) {
  return (
    <div className="bg-[#111827] p-5 rounded-2xl border border-slate-800 flex gap-4">
      <div className={`p-3 rounded-xl ${color}`}>
        <Icon size={20} />
      </div>
      <div>
        <p className="text-xs text-slate-500">{label}</p>
        {loading ? (
          <Skeleton className="h-8 w-16 mt-1" />
        ) : (
          <p className="text-2xl font-bold">{value ?? "—"}</p>
        )}
        <p className="text-xs text-slate-600">{sub}</p>
      </div>
    </div>
  );
}
