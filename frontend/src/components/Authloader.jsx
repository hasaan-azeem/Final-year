import React from "react";
import { Shield } from "lucide-react";

const AuthLoader = ({ message = "Signing you in..." }) => {
  return (
    <div className="fixed inset-0 z-50 flex flex-col items-center justify-center bg-[#0a0f1a]">
      {/* Animated ring */}
      <div className="relative flex items-center justify-center mb-8">
        {/* Outer spinning ring */}
        <div className="absolute w-24 h-24 rounded-full border-2 border-transparent border-t-emerald-400 border-r-emerald-400/30 animate-spin" />

        {/* Message */}
        <p className="text-slate-300 text-sm font-medium tracking-wide">
          {message}
        </p>
        <p className="text-slate-600 text-xs mt-1.5">Please wait</p>
      </div>
    </div>
  );
};

export default AuthLoader;
