import { useEffect, useState, useContext } from "react";
import { Link, useNavigate } from "react-router-dom";
import AuthLayout from "../../components/auth/AuthLayout";
import AuthInput from "../../components/auth/AuthInput";
import AuthButton from "../../components/auth/AuthButton";
import { validateEmail, validatePassword } from "../../utils/validators";
import API from "../../api/backend_api";
import { AuthContext } from "../../context/AuthContext";
import AuthLoader from "../../components/AuthLoader";
import logo from "../../assets/logo.svg";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState({});
  const [loading, setLoading] = useState(false);
  const [oauthLoading, setOauthLoading] = useState(null); // "google" | "github" | null

  const { user, login } = useContext(AuthContext);
  const navigate = useNavigate();

  useEffect(() => {
    if (user) navigate("/dashboard");
  }, [user, navigate]);

  const handleSubmit = async (e) => {
    e.preventDefault();

    const emailError = validateEmail(email);
    const passwordError = validatePassword(password);

    if (emailError || passwordError) {
      setErrors({ email: emailError, password: passwordError });
      return;
    }

    setErrors({});
    setLoading(true);

    try {
      const res = await API.post("/api/auth/login", { email, password });
      await login(res.data.access_token, res.data.user);
      navigate("/dashboard");
    } catch (error) {
      const msg =
        error.response?.data?.error?.message ||
        "Login failed. Check credentials and try again.";
      setErrors({ backend: msg });
    } finally {
      setLoading(false);
    }
  };

  const handleOAuthLogin = async (provider) => {
    setOauthLoading(provider);
    setErrors({});
    try {
      const response = await API.get(`/api/auth/oauth/${provider}`);
      if (response.data.auth_url) {
        localStorage.setItem("oauth_state", response.data.state);
        window.location.href = response.data.auth_url;
        // keep loader showing while redirect happens
        return;
      }
    } catch (error) {
      const msg =
        error.response?.data?.error?.message ||
        `${provider} login failed. Please try again.`;
      setErrors({ backend: msg });
      setOauthLoading(null);
    }
  };

  if (loading) return <AuthLoader message="Signing you in..." />;
  if (oauthLoading)
    return (
      <AuthLoader
        message={`Connecting with ${
          oauthLoading.charAt(0).toUpperCase() + oauthLoading.slice(1)
        }...`}
      />
    );

  return (
    <div className="min-h-screen py-10 w-full flex bg-[#020617] overflow-hidden">
      {/* LEFT SIDE */}
      <div className="hidden md:flex w-1/2 relative items-center justify-center">
        {/* Glow */}
        <div className="absolute w-[600px] h-[600px] bg-emerald-500/10 blur-[140px] rounded-full" />
        <div className="absolute w-[400px] h-[400px] bg-blue-500/10 blur-[120px] rounded-full bottom-[-120px] -right-20" />

        <div className="relative z-10 text-center px-10 max-w-md">
          <div className="mb-6 flex justify-center">
            <img src={logo} className="w-20" />
          </div>
          <h1 className="text-4xl font-bold text-white">
            Welcome to <span className="text-[#059669]">WebXGuard</span>
          </h1>

          <p className="text-gray-400 text-sm mt-4">
            Secure your applications with real-time vulnerability scanning and
            AI powered protection.
          </p>

          {/* Socials on LEFT */}
          <div className="mt-10 space-y-3">
            {/* GOOGLE */}
            <button
              type="button"
              onClick={() => handleOAuthLogin("google")}
              className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-xl bg-white text-black font-medium hover:bg-gray-200 transition cursor-pointer"
            >
              <svg className="w-5 h-5" viewBox="0 0 24 24">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                />
              </svg>

              <span>Continue with Google</span>
            </button>

            {/* GITHUB */}
            <button
              type="button"
              onClick={() => handleOAuthLogin("github")}
              className="w-full flex items-center justify-center gap-3 px-4 py-3 rounded-xl bg-white/5 border border-white/10 text-gray-200 hover:bg-white/10 transition cursor-pointer"
            >
              <svg
                className="w-5 h-5 text-gray-300"
                fill="currentColor"
                viewBox="0 0 24 24"
              >
                <path
                  fillRule="evenodd"
                  d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                  clipRule="evenodd"
                />
              </svg>

              <span>Continue with GitHub</span>
            </button>
          </div>
        </div>
      </div>

      {/* RIGHT SIDE */}
      <div className="w-full md:w-1/2 flex items-center justify-center px-6">
        <form onSubmit={handleSubmit} className="w-full max-w-md flex flex-col">
          {/* Header */}
          <div className="mb-6">
            <h2 className="text-2xl font-semibold text-white">Sign in</h2>
            <p className="text-gray-400 text-sm mt-1">
              Access your WebXGuard dashboard
            </p>
          </div>

          {/* Error */}
          {errors.backend && (
            <div className="p-3 mb-4 rounded-lg bg-red-500/10 border border-red-500/20 text-red-400 text-sm">
              {errors.backend}
            </div>
          )}

          {/* Inputs */}
          <div className="space-y-4">
            <AuthInput
              label="Email address"
              type="email"
              placeholder="you@company.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              error={errors.email}
            />

            <AuthInput
              label="Password"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              error={errors.password}
            />
          </div>

          {/* Options */}
          <div className="flex items-center justify-between mt-4 text-sm">
            <label className="flex items-center text-gray-400 cursor-pointer">
              <input type="checkbox" className="accent-emerald-500 mr-2" />
              Remember me
            </label>

            <Link
              to="/auth/dashboard/forgot-password"
              className="text-emerald-400 hover:underline"
            >
              Forgot password?
            </Link>
          </div>

          {/* SIGN IN BUTTON (mobile first order) */}
          <div className="mt-6">
            <AuthButton
              text="Sign In"
              loading={loading}
              disabled={!email || !password || loading}
            />
          </div>

          {/* SOCIALS (mobile after button) */}
          <div className="mt-6 sm:hidden">
            <div className="relative my-6">
              <div className="absolute inset-0 flex items-center">
                <div className="w-full border-t border-white/10" />
              </div>
              <div className="relative flex justify-center text-xs">
                <span className="bg-[#020617] px-2 text-gray-500">
                  or continue with
                </span>
              </div>
            </div>

            <div className="mt-6 grid grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => handleOAuthLogin("google")}
                disabled={!!oauthLoading}
                className="flex items-center justify-center px-4 py-3 border border-gray-700 rounded-lg hover:bg-gray-800 transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg className="w-5 h-5" viewBox="0 0 24 24">
                  <path
                    fill="#4285F4"
                    d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                  />
                  <path
                    fill="#34A853"
                    d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                  />
                  <path
                    fill="#FBBC05"
                    d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"
                  />
                  <path
                    fill="#EA4335"
                    d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"
                  />
                </svg>
                <span className="ml-2 text-sm font-medium text-gray-300">
                  Google
                </span>
              </button>

              <button
                type="button"
                onClick={() => handleOAuthLogin("github")}
                disabled={!!oauthLoading}
                className="flex items-center justify-center px-4 py-3 border border-gray-700 rounded-lg hover:bg-gray-800 transition cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <svg
                  className="w-5 h-5 text-gray-300"
                  fill="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    fillRule="evenodd"
                    d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"
                    clipRule="evenodd"
                  />
                </svg>
                <span className="ml-2 text-sm font-medium text-gray-300">
                  GitHub
                </span>
              </button>
            </div>
          </div>

          {/* SIGNUP LAST */}
          <div className="mt-8 text-center text-sm text-gray-400">
            Don’t have an account?{" "}
            <Link
              to="/auth/dashboard/signup"
              className="text-emerald-400 hover:underline"
            >
              Create a new account
            </Link>
          </div>
        </form>
      </div>
    </div>
  );
}
