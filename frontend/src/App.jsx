/* eslint-disable react-hooks/set-state-in-effect */
import React, { useContext, useEffect, useState } from "react";
import { BrowserRouter, Routes, Route, useLocation } from "react-router-dom";
import { ReactLenis } from "lenis/react";

// Context
import ProtectedRoute from "./components/ProtectedRoute";
import { AuthContext } from "./context/AuthContext";

// Layouts
import ClientLayout from "./layouts/ClientLayout";
import AdminLayout from "./layouts/AdminLayout";

// Client Pages
import Home from "./pages/landing/Home";
import Features from "./pages/landing/Features";
import Aboutus from "./pages/landing/AboutUs";
import Contact from "./pages/landing/Contact";
import PrivacyPolicy from "./components/Landing/Common/PrivacyPolicy";

// Admin Pages ✅ UPDATED IMPORTS
import Dashboard from "./pages/admin/Dashboard";
import Vulnerability from "./pages/admin/Vulnerabilities"; // ✅ NEW
import ScanDetail from "./pages/admin/ScanDetail"; // ✅ NEW
import Reports from "./pages/admin/Reports";
import Settings from "./pages/admin/Settings";
import HelpSupport from "./pages/admin/HelpSupport";
import ContinousMonitoring from "./pages/admin/ContinousMonitoring";
import Scanner from "./pages/admin/Scanner";
import Alerts from "./pages/admin/Alerts";
import PredictiveAnalysis from "./pages/admin/PredictiveAnalysis";
import Compliance from "./pages/admin/Compliance";
import Crawler from "./pages/admin/Crawler";

// Auth Pages
import Login from "./pages/auth/Login";
import Signup from "./pages/auth/Signup";
import VerifyEmail from "./pages/auth/VerifyEmail";
import VerifyEmailNotice from "./pages/auth/Verifyemailnotice";
import ForgotPassword from "./pages/auth/Forgotpassword";
import ResetPassword from "./pages/auth/ResetPassword";
import OAuthCallback from "./pages/auth/OAuthCallback";

// Utils
import ScrollToTop from "./components/ScrollToTop";
import RouteLoader from "./components/Routeloader";

function AppContent() {
  const location = useLocation();
  const { authLoading } = useContext(AuthContext);

  const [loading, setLoading] = useState(false);

  // Route loader
  useEffect(() => {
    setLoading(true);
    const timeout = setTimeout(() => setLoading(false), 500);
    return () => clearTimeout(timeout);
  }, [location.pathname]);

  const isDashboard = location.pathname.startsWith("/dashboard");

  if (authLoading) return null;

  const content = (
    <>
      <ScrollToTop />
      <RouteLoader loading={loading} />

      <Routes>
        {/* CLIENT */}
        <Route element={<ClientLayout />}>
          <Route path="/" element={<Home />} />
          <Route path="/features" element={<Features />} />
          <Route path="/aboutus" element={<Aboutus />} />
          <Route path="/contact" element={<Contact />} />
          <Route path="/privacy-policy" element={<PrivacyPolicy />} />

          {/* AUTH */}
          <Route path="/auth/dashboard/login" element={<Login />} />
          <Route path="/auth/dashboard/signup" element={<Signup />} />
          <Route
            path="/auth/dashboard/verify-email-notice"
            element={<VerifyEmailNotice />}
          />
          <Route path="/verify-email" element={<VerifyEmail />} />
          <Route
            path="/auth/dashboard/forgot-password"
            element={<ForgotPassword />}
          />
          <Route
            path="/auth/dashboard/reset-password"
            element={<ResetPassword />}
          />
          <Route path="/auth/callback" element={<OAuthCallback />} />
        </Route>

        {/* ADMIN */}
        <Route element={<AdminLayout />}>
          <Route
            path="/dashboard"
            element={
              <ProtectedRoute>
                <Dashboard />
              </ProtectedRoute>
            }
          />

          <Route
            path="/dashboard/ContinuousMonitoring"
            element={
              <ProtectedRoute>
                <ContinousMonitoring />
              </ProtectedRoute>
            }
          />

          {/* ✅ UPDATED VULNERABILITY ROUTES */}
          <Route
            path="/dashboard/vulnerability"
            element={
              <ProtectedRoute>
                <Vulnerability />
              </ProtectedRoute>
            }
          />
          <Route
  path="/dashboard/crawler"
  element={
    <ProtectedRoute>
      <Crawler />
    </ProtectedRoute>
  }
/>
          <Route
            path="/dashboard/alerts"
            element={
              <ProtectedRoute>
                <Alerts />
              </ProtectedRoute>
            }
          />

          <Route
            path="/dashboard/predictive"
            element={
              <ProtectedRoute>
                <PredictiveAnalysis />
              </ProtectedRoute>
            }
          />
          <Route
            path="/dashboard/compliance"
            element={
              <ProtectedRoute>
                <Compliance />
              </ProtectedRoute>
            }
          />

          {/* 🔥 NEW DETAIL PAGE ROUTE */}
          <Route
            path="/dashboard/vulnerability/:id"
            element={
              <ProtectedRoute>
                <ScanDetail />
              </ProtectedRoute>
            }
          />

          <Route
            path="/dashboard/scanner"
            element={
              <ProtectedRoute>
                <Scanner />
              </ProtectedRoute>
            }
          />

          <Route
            path="/dashboard/reports"
            element={
              <ProtectedRoute>
                <Reports />
              </ProtectedRoute>
            }
          />

          <Route
            path="/dashboard/Settings"
            element={
              <ProtectedRoute>
                <Settings />
              </ProtectedRoute>
            }
          />

          <Route
            path="/dashboard/HelpSupport"
            element={
              <ProtectedRoute>
                <HelpSupport />
              </ProtectedRoute>
            }
          />
        </Route>
      </Routes>
    </>
  );

  // Disable Lenis on dashboard
  if (isDashboard) return content;

  return (
    <ReactLenis
      root
      options={{
        lerp: 0.1,
        duration: 1.2,
        smoothWheel: true,
      }}
    >
      {content}
    </ReactLenis>
  );
}

function App() {
  return (
    <BrowserRouter>
      <AppContent />
    </BrowserRouter>
  );
}

export default App;
