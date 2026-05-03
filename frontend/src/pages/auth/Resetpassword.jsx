import { useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import AuthLayout from "../../components/auth/AuthLayout";
import AuthInput from "../../components/auth/AuthInput";
import AuthButton from "../../components/auth/AuthButton";
import {
  validatePassword,
  validateConfirmPassword,
} from "../../utils/validators";
import { getPasswordStrength } from "../../utils/passwordStrength";
import API from "../../api/backend_api";

export default function ResetPassword() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");

  const [formData, setFormData] = useState({
    password: "",
    confirmPassword: "",
  });
  const [message, setMessage] = useState({ type: "", text: "" });
  const [loading, setLoading] = useState(false);

  const strength = getPasswordStrength(formData.password);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setMessage({ type: "", text: "" });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ type: "", text: "" });

    if (!token) {
      setMessage({
        type: "error",
        text: "Invalid reset link. Please request a new one.",
      });
      setLoading(false);
      return;
    }

    const passwordError = validatePassword(formData.password);
    const confirmError = validateConfirmPassword(
      formData.password,
      formData.confirmPassword,
    );

    if (passwordError || confirmError) {
      setMessage({ type: "error", text: passwordError || confirmError });
      setLoading(false);
      return;
    }

    try {
      // Correct endpoint: /api/users/reset-password (handled by user_bp)
      await API.post("/api/users/reset-password", {
        token,
        password: formData.password,
      });
      setMessage({
        type: "success",
        text: "Password reset successful! Redirecting to login...",
      });
      setTimeout(
        () => navigate("/auth/dashboard/login", { replace: true }),
        2000,
      );
    } catch (error) {
      const code = error.response?.data?.error?.code;
      if (code === "TOKEN_EXPIRED") {
        setMessage({
          type: "error",
          text: "This reset link has expired. Please request a new one.",
        });
      } else if (code === "TOKEN_USED") {
        setMessage({
          type: "error",
          text: "This reset link has already been used. Please request a new one.",
        });
      } else if (code === "INVALID_TOKEN") {
        setMessage({
          type: "error",
          text: "This reset link is invalid. Please request a new one.",
        });
      } else {
        setMessage({
          type: "error",
          text:
            error.response?.data?.error?.message ||
            "Password reset failed. Please try again.",
        });
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <AuthLayout
      title="Reset Password"
      subtitle="Enter your new password"
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
              d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"
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

      <form onSubmit={handleSubmit} className="space-y-5">
        <AuthInput
          label="New Password"
          type="password"
          name="password"
          placeholder="Minimum 8 characters"
          value={formData.password}
          onChange={handleChange}
        />

        {/* Password strength meter using percent from getPasswordStrength */}
        {formData.password && (
          <div className="text-xs text-gray-400">
            Strength:
            <span className="ml-2 font-semibold text-white">
              {strength.label}
            </span>
            <div className="h-1 w-full bg-gray-700 rounded mt-1">
              <div
                className={`h-1 rounded transition-all ${strength.color}`}
                style={{ width: `${strength.percent}%` }}
              />
            </div>
          </div>
        )}

        <AuthInput
          label="Confirm New Password"
          type="password"
          name="confirmPassword"
          placeholder="Re-enter password"
          value={formData.confirmPassword}
          onChange={handleChange}
        />

        <AuthButton
          text="Reset Password"
          loading={loading}
          disabled={!formData.password || !formData.confirmPassword || loading}
        />
      </form>
    </AuthLayout>
  );
}
