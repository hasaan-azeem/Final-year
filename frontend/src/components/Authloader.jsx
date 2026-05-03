import React from "react";
import { Shield } from "lucide-react";

const AuthLoader = ({ message = "Signing you in..." }) => {
  return (
    <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-[#0a0f1a]">
      {/* Animated ring */}
      <div className="relative flex items-center justify-center mb-8">
        {/* Outer spinning ring */}
        <div className="absolute w-24 h-24 rounded-full border-2 border-transparent border-t-emerald-400 border-r-emerald-400/30 animate-spin" />

        {/* Middle pulsing ring */}
        <div className="absolute w-16 h-16 rounded-full border border-slate-700 animate-pulse" />

        {/* Center icon */}
        <div className="w-12 h-12 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
          <Shield size={22} className="text-emerald-400" />
        </div>
      </div>

      {/* Dots loader */}
      <div className="flex items-center gap-1.5 mb-5">
        {[0, 1, 2].map((i) => (
          <span
            key={i}
            className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-bounce"
            style={{ animationDelay: `${i * 0.15}s` }}
          />
        ))}
      </div>

      {/* Message */}
      <p className="text-slate-300 text-sm font-medium tracking-wide">
        {message}
      </p>
      <p className="text-slate-600 text-xs mt-1.5">Please wait</p>
    </div>
  );
};

export default AuthLoader;
