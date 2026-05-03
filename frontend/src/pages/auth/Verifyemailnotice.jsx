import { useState, useContext } from "react";
import { Link } from "react-router-dom";
import API from "../../api/backend_api";
import { AuthContext } from "../../context/AuthContext";
import AuthLoader from "../../components/AuthLoader";

export default function VerifyEmailNotice() {
  const { user, logout } = useContext(AuthContext);
  const [resendState, setResendState] = useState("idle"); // "idle" | "sending" | "sent" | "error"

  const handleResend = async () => {
    setResendState("sending");
    try {
      await API.post("/api/auth/resend-verification");
      setResendState("sent");
    } catch {
      setResendState("error");
    }
  };

  if (resendState === "sending")
    return <AuthLoader message="Resending verification email..." />;

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0a0f1a] px-4">
      <div className="bg-[#111827] border border-slate-800 rounded-2xl p-8 max-w-md w-full text-center">
        {/* Icon */}
        <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 mx-auto mb-6">
          <svg
            className="w-8 h-8 text-emerald-400"
            fill="none"
            stroke="currentColor"
            strokeWidth={1.5}
            viewBox="0 0 24 24"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"
            />
          </svg>
        </div>

        <h2 className="text-xl font-semibold text-white mb-2">
          Check your email
        </h2>

        <p className="text-slate-400 text-sm mb-1">
          We sent a verification link to:
        </p>
        <p className="text-emerald-400 font-medium text-sm mb-6">
          {user?.email || "your email address"}
        </p>

        <p className="text-slate-500 text-xs mb-8 leading-relaxed">
          Click the link in the email to activate your account. The link expires
          in 24 hours. Check your spam folder if you don't see it.
        </p>

        {/* Resend */}
        <div className="mb-6">
          {resendState === "sent" ? (
            <p className="text-sm text-emerald-400">
              Verification email resent successfully.
            </p>
          ) : (
            <button
              onClick={handleResend}
              className="text-sm text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2 rounded-lg transition"
            >
              Resend verification email
              {resendState === "error" && (
                <span className="ml-1 text-red-400">(failed, try again)</span>
              )}
            </button>
          )}
        </div>

        {/* Divider */}
        <div className="border-t border-slate-800 pt-5">
          <button
            onClick={logout}
            className="text-xs text-slate-500 hover:text-slate-300 transition-colors"
          >
            Sign out and use a different account
          </button>
        </div>
      </div>
    </div>
  );
}
