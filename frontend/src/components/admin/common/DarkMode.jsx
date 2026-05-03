import React, { useEffect, useState } from "react";
import { Sun, Moon } from "lucide-react";

export const DarkMode = () => {
  const [isDark, setIsDark] = useState(() => {
    const saved = localStorage.getItem("theme");
    if (saved) return saved === "dark";
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    document.documentElement.classList.toggle("dark", isDark);
    localStorage.setItem("theme", isDark ? "dark" : "light");
  }, [isDark]);

  return (
    <button
      onClick={() => setIsDark(!isDark)}
      className="w-10 h-10 flex items-center justify-center rounded-full
                 bg-gray-200 dark:bg-gray-800 transition-colors"
    >
      <Sun
        className={`absolute w-5 h-5 text-yellow-500 transition-all ${
          isDark ? "scale-0" : "scale-100"
        }`}
      />
      <Moon
        className={`absolute w-5 h-5 text-yellow-400 transition-all ${
          isDark ? "scale-100" : "scale-0"
        }`}
      />
    </button>
  );
};
