import { useState } from "react";

export default function AuthInput({
  label,
  type = "text",
  placeholder,
  value,
  onChange,
  error,
}) {
  const [show, setShow] = useState(false);
  const isPassword = type === "password";

  return (
    <div>
      <label className="block text-sm text-gray-300 mb-1">{label}</label>

      <div className="relative">
        <input
          type={isPassword && show ? "text" : type}
          value={value}
          onChange={onChange}
          placeholder={placeholder}
          className={`w-full px-4 py-2.5 pr-12 rounded-lg bg-black/40 border 
          ${error ? "border-red-500" : "border-white/10"}
          text-white placeholder-gray-500 focus:outline-none focus:ring-1 
          ${error ? "focus:ring-red-500" : "focus:ring-emerald-500"}`}
        />

        {isPassword && (
          <button
            type="button"
            onClick={() => setShow(!show)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 text-sm"
          >
            {show ? "Hide" : "Show"}
          </button>
        )}
      </div>

      {error && <p className="text-xs text-red-400 mt-1">{error}</p>}
    </div>
  );
}
