import { useContext } from "react";
import { Navigate } from "react-router-dom";
import { AuthContext } from "../context/AuthContext";

const LoadingSpinner = () => (
  <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-950">
    <div className="text-center">
      <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mx-auto"></div>
      <p className="mt-4 text-gray-600 dark:text-gray-400">Loading...</p>
    </div>
  </div>
);

export default function ProtectedRoute({ children }) {
  const { user, loading } = useContext(AuthContext);

  // Wait until auth state is resolved
  if (loading) {
    return <LoadingSpinner />;
  }

  // Not logged in at all, go to login
  if (!user) {
    return <Navigate to="/auth/dashboard/login" replace />;
  }

  // Logged in but email not verified, go to notice page
  if (!user.is_verified) {
    return <Navigate to="/auth/dashboard/verify-email-notice" replace />;
  }

  // Logged in and verified, allow access
  return children;
}