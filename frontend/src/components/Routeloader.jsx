import { useEffect, useState } from "react";
import { useLocation } from "react-router-dom";
import { Shield } from "lucide-react";

export default function RouteLoader() {
  const location = useLocation();
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setVisible(true);
    const timer = setTimeout(() => setVisible(false), 600);
    return () => clearTimeout(timer);
  }, [location.pathname]);

  if (!visible) return null;

  return (
    <div
      className="fixed inset-0 mt-15 z-50 flex flex-col items-center justify-center bg-[#0a0f1a] transition-opacity duration-300"
      style={{ opacity: visible ? 1 : 0 }}
    >
      {/* Spinning ring + icon */}
      <div className="relative flex items-center justify-center mb-8">
        <div className="absolute w-24 h-24 rounded-full border-4 border-transparent border-t-emerald-400 border-r-emerald-400/30 animate-spin" />
        {/* <div className="absolute w-16 h-16 rounded-full border border-slate-700 animate-pulse" />
        <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
          <Shield size={22} className="text-emerald-400" />
        </div> */}
      </div>
    </div>
  );
}
