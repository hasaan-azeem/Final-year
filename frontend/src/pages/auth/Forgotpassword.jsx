import { useState } from "react";
import { Link } from "react-router-dom";
import AuthLayout from "../../components/auth/AuthLayout";
import AuthInput from "../../components/auth/AuthInput";
import AuthButton from "../../components/auth/AuthButton";
import { validateEmail } from "../../utils/validators";
import API from "../../api/backend_api";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState({ type: "", text: "" });
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ type: "", text: "" });

    const emailError = validateEmail(email);
    if (emailError) {
      setMessage({ type: "error", text: emailError });
      setLoading(false);
      return;
    }

    try {
      await API.post("/api/users/forgot-password", { email });
      setMessage({
        type: "success",
        text: "If an account exists with this email, you will receive password reset instructions.",
      });
      setEmail("");
    } catch (error) {
      setMessage({
        type: "error",
        text:
          error.response?.data?.error?.message ||
          "Failed to send reset email",
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      title="Forgot Password?"
      subtitle="No worries, we'll send you reset instructions"
      footer={
        <Link
          to="/auth/dashboard/login"
          className="text-emerald-400 hover:underline flex items-center justify-center"
        >
          <svg
            className="w-4 h-4 mr-1"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M10 19l-7-7m0 0l7-7m-7 7h18"
            />
          </svg>
          Back to login
        </Link>
      }
    >
      <div className="mb-6 flex justify-center">
        <div className="h-12 w-12 bg-emerald-900/30 rounded-full flex items-center justify-center">
          <svg
            className="h-6 w-6 text-emerald-400"
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth={2}
              d="M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z"
            />
          </svg>
        </div>
      </div>

      {message.text && (
        <div
          className={`mb-6 p-4 rounded-lg ${
            message.type === "success"
              ? "bg-emerald-900/30 text-emerald-400 border border-emerald-800"
              : "bg-red-900/30 text-red-400 border border-red-800"
          }`}
        >
          {message.text}
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        <AuthInput
          label="Email Address"
          type="email"
          placeholder="you@company.com"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
        />

        <AuthButton
          text="Send Reset Instructions"
          loading={loading}
          disabled={!email || loading}
        />
      </form>
    </AuthLayout>
  );
}