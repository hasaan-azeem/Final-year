import { useEffect, useContext } from "react";
import { useNavigate } from "react-router-dom";
import { AuthContext } from "../../context/AuthContext";
import API from "../../api/backend_api";

export default function OAuthCallback() {
  const navigate = useNavigate();
  const { login } = useContext(AuthContext);

  useEffect(() => {
    const handleOAuthCallback = async () => {
      try {
        // Tokens are in the URL fragment (#access_token=...&refresh_token=...)
        // The browser never sends fragments to the server, so we read them client-side.
        const hash = window.location.hash.substring(1); // strip the leading '#'
        const params = new URLSearchParams(hash);

        const accessToken = params.get("access_token");
        const refreshToken = params.get("refresh_token");

        if (!accessToken) {
          throw new Error("No access token received");
        }

        // Save tokens
        localStorage.setItem("token", accessToken);
        if (refreshToken) {
          localStorage.setItem("refresh_token", refreshToken);
        }

        // Clean the fragment from the URL so tokens don't linger in browser history
        window.history.replaceState(null, "", window.location.pathname);

        // Fetch user data with the new token in place
        const userRes = await API.get("/api/auth/me");

        // Login with user data
        await login(accessToken, userRes.data);

        navigate("/dashboard", { replace: true });
      } catch (error) {
        console.error("OAuth callback error:", error);
        navigate("/auth/dashboard/login", {
          replace: true,
          state: { error: "OAuth authentication failed. Please try again." },
        });
      }
    };

    handleOAuthCallback();
  }, [navigate, login]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950">
      <div className="text-center">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
        <p className="mt-4 text-gray-600 dark:text-gray-400">
          Completing authentication...
        </p>
      </div>
    </div>
  );
}