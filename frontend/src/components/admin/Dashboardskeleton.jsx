import React from "react";

// ── Shimmer animation ─────────────────────────────────────────────────────────
const shimmerStyle = `
  @keyframes shimmer {
    0% { background-position: -600px 0; }
    100% { background-position: 600px 0; }
  }
  .shimmer {
    background: linear-gradient(
      90deg,
      #1a2332 25%,
      #243044 50%,
      #1a2332 75%
    );
    background-size: 600px 100%;
    animation: shimmer 1.6s infinite linear;
    border-radius: 8px;
  }
`;

const Shimmer = ({ className = "", style = {} }) => (
  <div className={`shimmer ${className}`} style={style} />
);

// ── Stat card skeleton ────────────────────────────────────────────────────────
const StatCardSkeleton = () => (
  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-5">
    <div className="flex items-start justify-between">
      <div className="flex-1">
        <Shimmer className="h-3 w-28 mb-3" />
        <Shimmer className="h-8 w-16" />
      </div>
      <Shimmer className="h-10 w-10 rounded-xl shrink-0" />
    </div>
    <div className="mt-4">
      <Shimmer className="h-1.5 w-full mb-2" style={{ borderRadius: 4 }} />
      <Shimmer className="h-3 w-24" />
    </div>
  </div>
);

// ── Bar chart skeleton ────────────────────────────────────────────────────────
const BarChartSkeleton = () => (
  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6">
    <div className="flex items-center justify-between mb-6">
      <Shimmer className="h-4 w-32" />
      <Shimmer className="h-6 w-24 rounded-full" />
    </div>
    {/* Bars */}
    <div className="flex items-end justify-between gap-2 h-48 px-2">
      {[65, 90, 75, 100, 80, 95, 70].map((h, i) => (
        <div key={i} className="flex-1 flex items-end gap-0.5">
          <Shimmer style={{ height: `${h * 0.55}%`, flex: 1 }} />
          <Shimmer style={{ height: `${h * 0.38}%`, flex: 1 }} />
          <Shimmer style={{ height: `${h * 0.22}%`, flex: 1 }} />
        </div>
      ))}
    </div>
    {/* X axis labels */}
    <div className="flex justify-between mt-3 px-2">
      {["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"].map((d) => (
        <Shimmer key={d} className="h-2.5" style={{ width: 24 }} />
      ))}
    </div>
    {/* Legend */}
    <div className="flex justify-center gap-6 mt-4">
      {[64, 72, 48].map((w, i) => (
        <div key={i} className="flex items-center gap-2">
          <Shimmer style={{ width: 12, height: 12, borderRadius: 3 }} />
          <Shimmer style={{ width: w, height: 10 }} />
        </div>
      ))}
    </div>
  </div>
);

// ── Table skeleton ────────────────────────────────────────────────────────────
const TableSkeleton = () => (
  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6">
    <div className="flex items-center justify-between mb-6">
      <Shimmer className="h-4 w-40" />
      <Shimmer className="h-6 w-20 rounded-full" />
    </div>
    {/* Header row */}
    <div className="flex gap-4 pb-3 border-b border-slate-800 mb-1">
      <Shimmer className="h-2.5 w-14" />
      <Shimmer className="h-2.5 w-20" />
      <Shimmer className="h-2.5 w-16 ml-auto" />
    </div>
    {/* Data rows */}
    {[1, 2, 3, 4, 5].map((i) => (
      <div
        key={i}
        className="flex items-center gap-4 py-3 border-b border-slate-800/50"
      >
        <Shimmer className="h-6 w-20 rounded-md" />
        <Shimmer className="h-3 w-28" />
        <div className="ml-auto flex items-center gap-3">
          <Shimmer className="h-1.5 w-24 rounded-full" />
          <Shimmer className="h-3 w-6" />
        </div>
      </div>
    ))}
  </div>
);

// ── Speedometer skeleton ──────────────────────────────────────────────────────
const SpeedometerSkeleton = () => (
  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6 flex flex-col items-center">
    <div className="flex items-center justify-between w-full mb-4">
      <Shimmer className="h-4 w-28" />
      <Shimmer className="h-6 w-20 rounded-full" />
    </div>
    {/* Gauge arc shape */}
    <div className="relative flex items-center justify-center mt-2 mb-2">
      <Shimmer
        style={{ width: 176, height: 88, borderRadius: "88px 88px 0 0" }}
      />
      <div className="absolute bottom-0 left-1/2 -translate-x-1/2">
        <Shimmer style={{ width: 60, height: 28, borderRadius: 6 }} />
      </div>
    </div>
    <Shimmer className="h-3 w-24 mt-4" />
  </div>
);

// ── Threats list skeleton ─────────────────────────────────────────────────────
const ThreatsSkeleton = () => (
  <div className="bg-[#111827] border border-slate-800 rounded-2xl p-6">
    <div className="flex items-center justify-between mb-5">
      <Shimmer className="h-4 w-28" />
      <Shimmer className="h-6 w-16 rounded-full" />
    </div>
    <div className="space-y-2.5">
      {[1, 2, 3, 4, 5].map((i) => (
        <div
          key={i}
          className="flex items-center justify-between bg-slate-800/30 border border-slate-800 rounded-xl p-3"
        >
          <div className="flex items-center gap-2.5">
            <Shimmer style={{ width: 4, height: 32, borderRadius: 2 }} />
            <Shimmer className="h-3 w-36" />
          </div>
          <Shimmer className="h-6 w-12 rounded-md" />
        </div>
      ))}
    </div>
  </div>
);

// ── Full dashboard skeleton ───────────────────────────────────────────────────
const DashboardSkeleton = () => (
  <>
    <style>{shimmerStyle}</style>
    <div className="w-full">
      {/* Stats row */}
      <div className="mb-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        {[1, 2, 3, 4].map((i) => (
          <StatCardSkeleton key={i} />
        ))}
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left col */}
        <div className="col-span-1 lg:col-span-2 flex flex-col gap-5">
          <BarChartSkeleton />
          <TableSkeleton />
        </div>

        {/* Right col */}
        <div className="flex flex-col gap-5">
          <SpeedometerSkeleton />
          <ThreatsSkeleton />
        </div>
      </div>
    </div>
  </>
);

export default DashboardSkeleton;
