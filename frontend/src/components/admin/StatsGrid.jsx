import { Globe, ShieldAlert, BellRing, CheckCircle } from "lucide-react";

const StatsGrid = () => {
  const stats = [
    {
      title: "Total Websites",
      value: "12",
      change: "+5 this month",
      changeColor: "text-emerald-400",
      icon: <Globe className="h-5 w-5" />,
      accent: "text-emerald-400",
      iconBg: "bg-emerald-500/10 border border-emerald-500/20",
      bar: "bg-emerald-500",
    },
    {
      title: "Active Vulnerabilities",
      value: "13",
      change: "+12% this month",
      changeColor: "text-red-400",
      icon: <ShieldAlert className="h-5 w-5" />,
      accent: "text-red-400",
      iconBg: "bg-red-500/10 border border-red-500/20",
      bar: "bg-red-500",
    },
    {
      title: "High-Risk Alerts",
      value: "6",
      change: "+2 this month",
      changeColor: "text-red-400",
      icon: <BellRing className="h-5 w-5" />,
      accent: "text-amber-400",
      iconBg: "bg-amber-500/10 border border-amber-500/20",
      bar: "bg-amber-500",
    },
    {
      title: "Responses Taken",
      value: "24",
      change: "-5% this month",
      changeColor: "text-emerald-400",
      icon: <CheckCircle className="h-5 w-5" />,
      accent: "text-emerald-400",
      iconBg: "bg-emerald-500/10 border border-emerald-500/20",
      bar: "bg-emerald-500",
    },
  ];

  return (
    <div className="mb-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
      {stats.map((item, index) => (
        <div
          key={index}
          className="bg-[#111827] border border-slate-800 rounded-2xl p-5 hover:border-slate-700 transition-colors duration-200"
        >
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs font-medium text-slate-500 uppercase tracking-widest mb-2">
                {item.title}
              </p>
              <p className={`text-3xl font-bold ${item.accent}`}>
                {item.value}
              </p>
            </div>
            <div className={`p-2.5 rounded-xl ${item.iconBg} ${item.accent}`}>
              {item.icon}
            </div>
          </div>

          <div className="mt-4">
            <div className="h-1 w-full bg-slate-800 rounded-full overflow-hidden mb-2">
              <div className={`h-full w-1/3 ${item.bar} rounded-full`} />
            </div>
            <p className={`text-xs font-medium ${item.changeColor}`}>
              {item.change}
            </p>
          </div>
        </div>
      ))}
    </div>
  );
};

export default StatsGrid;
