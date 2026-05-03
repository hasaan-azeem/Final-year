import { useEffect, useState } from "react";
import { useSearchParams, useNavigate, Link } from "react-router-dom";
import API from "../../api/backend_api";
import AuthLoader from "../../components/AuthLoader";

export default function VerifyEmail() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const [status, setStatus] = useState("verifying");
  const [errorMessage, setErrorMessage] = useState("");

  useEffect(() => {
    const verifyToken = async () => {
      const token = searchParams.get("token");

      if (!token) {
        setErrorMessage("Verification link is invalid or incomplete.");
        setStatus("error");
        return;
      }

      try {
        await API.get(`/api/auth/verify-email/${token}`);
        setStatus("success");
        setTimeout(() => navigate("/dashboard", { replace: true }), 2500);
      } catch (err) {
        const code = err.response?.data?.error?.code;

        if (code === "ALREADY_VERIFIED") {
          setStatus("already_verified");
          setTimeout(() => navigate("/dashboard", { replace: true }), 2500);
        } else if (code === "TOKEN_EXPIRED") {
          setErrorMessage(
            "This verification link has expired. Please request a new one.",
          );
          setStatus("error");
        } else if (code === "INVALID_TOKEN") {
          setErrorMessage(
            "This verification link is invalid. It may have already been used.",
          );
          setStatus("error");
        } else {
          setErrorMessage("Something went wrong. Please try again.");
          setStatus("error");
        }
      }
    };

    verifyToken();
  }, [searchParams, navigate]);

  // Full page loader while verifying
  if (status === "verifying")
    return <AuthLoader message="Verifying your email..." />;

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#0a0f1a] px-4">
      <div className="bg-[#111827] border border-slate-800 rounded-2xl p-8 max-w-md w-full text-center">
        {status === "success" && (
          <>
            <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 mx-auto mb-6">
              <svg
                className="w-8 h-8 text-emerald-400"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M5 13l4 4L19 7"
                />
              </svg>
            </div>
            <h2 className="text-xl font-semibold text-white mb-2">
              Email verified!
            </h2>
            <p className="text-slate-400 text-sm mb-6">
              Your account is now active. Taking you to your dashboard...
            </p>
            <Link
              to="/dashboard"
              className="inline-block bg-emerald-600 hover:bg-emerald-700 text-white text-sm font-medium px-6 py-2.5 rounded-lg transition-colors"
            >
              Go to Dashboard
            </Link>
          </>
        )}

        {status === "already_verified" && (
          <>
            <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-slate-700/50 border border-slate-700 mx-auto mb-6">
              <svg
                className="w-8 h-8 text-slate-300"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M5 13l4 4L19 7"
                />
              </svg>
            </div>
            <h2 className="text-xl font-semibold text-white mb-2">
              Already verified!
            </h2>
            <p className="text-slate-400 text-sm mb-6">
              Your email is already verified. Taking you to your dashboard...
            </p>
            <Link
              to="/dashboard"
              className="inline-block bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium px-6 py-2.5 rounded-lg transition-colors"
            >
              Go to Dashboard
            </Link>
          </>
        )}

        {status === "error" && (
          <>
            <div className="flex items-center justify-center w-16 h-16 rounded-2xl bg-red-500/10 border border-red-500/20 mx-auto mb-6">
              <svg
                className="w-8 h-8 text-red-400"
                fill="none"
                stroke="currentColor"
                strokeWidth={2}
                viewBox="0 0 24 24"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  d="M6 18L18 6M6 6l12 12"
                />
              </svg>
            </div>
            <h2 className="text-xl font-semibold text-white mb-2">
              Verification failed
            </h2>
            <p className="text-slate-400 text-sm mb-6">{errorMessage}</p>
            <div className="flex flex-col gap-3">
              <Link
                to="/auth/dashboard/login"
                className="bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium px-6 py-2.5 rounded-lg transition-colors"
              >
                Go to Login
              </Link>
              <ResendVerificationButton />
            </div>
          </>
        )}
      </div>
    </div>
  );
}

function ResendVerificationButton() {
  const [state, setState] = useState("idle");

  const handleResend = async () => {
    setState("sending");
    try {
      await API.post("/api/auth/resend-verification");
      setState("sent");
    } catch {
      setState("error");
    }
  };

  if (state === "sending")
    return <AuthLoader message="Resending verification email..." />;

  if (state === "sent") {
    return (
      <p className="text-sm text-emerald-400">
        A new verification email has been sent. Check your inbox.
      </p>
    );
  }

  return (
    <button
      onClick={handleResend}
      disabled={state === "sending"}
      className="text-sm text-slate-300 bg-slate-800 hover:bg-slate-700 border border-slate-700 px-4 py-2.5 rounded-lg transition disabled:opacity-50"
    >
      Resend verification email
      {state === "error" && (
        <span className="ml-1 text-red-400">(failed, try again)</span>
      )}
    </button>
  );
}
