/* eslint-disable react-hooks/set-state-in-effect */
import React, { useState, useEffect, useContext, useRef } from "react";
import { Link, useLocation, useNavigate, Outlet } from "react-router-dom";
import {
  ChartNoAxesColumn,
  Shield,
  Activity,
  FileText,
  Settings,
  HelpCircle,
  Menu,
  X,
  User,
  LogOut,
  Search,
  Bell,
  Brain,
  ShieldCheck,
  Network,
} from "lucide-react";
import { AuthContext } from "../context/AuthContext";
import AlertsBell from "../components/admin/AlertsBell";

// ─────────────────────────────────────────────
// Sidebar nav item
// ─────────────────────────────────────────────
const SidebarItem = ({ icon, label, to, active, onClick }) => (
  <Link
    to={to}
    onClick={onClick}
    className={`flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium transition-colors
      ${
        active
          ? "bg-emerald-500/15 text-emerald-400 border border-emerald-500/25"
          : "text-gray-400 hover:bg-white/5 hover:text-white"
      }`}
  >
    <span className={active ? "text-emerald-400" : ""}>{icon}</span>
    {label}
  </Link>
);

// ─────────────────────────────────────────────
// Menu items (3 naye items add huye: Alerts, Predictive, Compliance)
// ─────────────────────────────────────────────
const MENU_ITEMS = [
  {
    label: "Dashboard",
    to: "/dashboard",
    icon: <ChartNoAxesColumn size={18} />,
  },
  {
    label: "Scanner",
    to: "/dashboard/scanner",
    icon: <Search size={18} />,
  },
  {
    label: "Monitoring",
    to: "/dashboard/continuousmonitoring",
    icon: <Activity size={18} />,
  },
  {
    label: "Crawler",
    to: "/dashboard/crawler",
    icon: <Network size={18} />,
  },
  {
    label: "Vulnerabilities",
    to: "/dashboard/vulnerability",
    icon: <Shield size={18} />,
  },
  {
    label: "Predictive",
    to: "/dashboard/predictive",
    icon: <Brain size={18} />,
  },
  {
    label: "Compliance",
    to: "/dashboard/compliance",
    icon: <ShieldCheck size={18} />,
  },
  {
    label: "Alerts",
    to: "/dashboard/alerts",
    icon: <Bell size={18} />,
  },

  {
    label: "Reports",
    to: "/dashboard/reports",
    icon: <FileText size={18} />,
  },
  {
    label: "Support",
    to: "/dashboard/HelpSupport",
    icon: <HelpCircle size={18} />,
  },
  {
    label: "Settings",
    to: "/dashboard/settings",
    icon: <Settings size={18} />,
  },
];

// ─────────────────────────────────────────────
// Main layout
// ─────────────────────────────────────────────
const AdminLayout = () => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);

  const location = useLocation();
  const navigate = useNavigate();
  const profileRef = useRef(null);

  const { logout, user, loading } = useContext(AuthContext);

  const closeSidebar = () => setSidebarOpen(false);

  // Close sidebar when route changes
  useEffect(() => {
    closeSidebar();
  }, [location.pathname]);

  // Close profile dropdown on outside click
  useEffect(() => {
    const handler = (e) => {
      if (profileRef.current && !profileRef.current.contains(e.target)) {
        setProfileOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, []);

  const handleLogout = async () => {
    setProfileOpen(false);
    await logout();
    navigate("/auth/dashboard/login");
  };

  const displayName =
    user?.username || user?.full_name || user?.email || "User";

  return (
    <div className="flex h-screen overflow-hidden bg-gray-950 text-gray-100">
      {/* ═══════════════════════════════════════
          SIDEBAR
      ═══════════════════════════════════════ */}
      <aside
        className={`
          fixed z-40 w-64 h-full flex flex-col
          bg-black
          border-r border-white/5
          transform transition-transform duration-300
          ${sidebarOpen ? "translate-x-0" : "-translate-x-full"}
        `}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-5 shrink-0">
          <div className="flex items-center gap-2">
            <Shield size={20} className="text-emerald-400" />
            <h2 className="text-base font-bold text-white">WebXGuard</h2>
          </div>
          <button
            onClick={closeSidebar}
            className="p-1 rounded-lg hover:bg-white/10 text-gray-400 hover:text-white transition-colors cursor-pointer"
          >
            <X size={18} />
          </button>
        </div>

        {/* Divider */}
        <div className="h-px bg-white/10 mx-4 mb-3" />

        {/* Nav */}
        <nav className="flex-1 overflow-y-auto px-3 py-2">
          <div className="flex flex-col gap-1">
            {MENU_ITEMS.map((item) => (
              <SidebarItem
                key={item.to}
                {...item}
                active={location.pathname === item.to}
                onClick={closeSidebar}
              />
            ))}
          </div>
        </nav>

        {/* Divider */}
        <div className="h-px bg-white/10 mx-4" />

        {/* Logout */}
        <div className="p-3 shrink-0">
          <button
            onClick={handleLogout}
            className="flex items-center gap-3 px-4 py-3 rounded-xl text-sm font-medium w-full
              text-red-400 hover:bg-red-500/10 hover:text-red-300
              transition-colors cursor-pointer"
          >
            <LogOut size={18} />
            Logout
          </button>
        </div>
      </aside>

      {/* Overlay */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/40 z-30 cursor-pointer"
          onClick={closeSidebar}
        />
      )}

      {/* ═══════════════════════════════════════
          MAIN AREA
      ═══════════════════════════════════════ */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {/* Topbar */}
        <header
          className="
          flex items-center justify-between px-4 py-3 shrink-0
          bg-[#07090f]
          border-b border-white/5
        "
        >
          {/* Hamburger */}
          <button
            onClick={() => setSidebarOpen(true)}
            className="p-2 rounded-lg text-gray-300 hover:bg-white/10 hover:text-white transition-colors cursor-pointer"
          >
            <Menu size={20} />
          </button>

          <h2 className="text-md ml-2 font-semibold text-white">
            {MENU_ITEMS.find((item) => item.to === location.pathname)?.label ||
              "Dashboard"}
          </h2>

          {/* Right controls */}
          <div className="flex items-center gap-2 ml-auto">
            {/* 🔔 Alerts bell dropdown */}
            <AlertsBell />

            {/* Profile dropdown */}
            <div className="relative" ref={profileRef}>
              <button
                onClick={() => setProfileOpen((prev) => !prev)}
                className="flex items-center gap-2 px-3 py-2 rounded-xl text-sm font-medium
                  bg-white/10 hover:bg-white/15
                  text-gray-200 hover:text-white
                  transition-colors cursor-pointer"
              >
                <User size={16} />
                <span>{loading ? "Loading..." : displayName}</span>
              </button>

              {/* Dropdown */}
              {profileOpen && (
                <div
                  className="
                  absolute right-0 mt-2 w-48 z-50
                  bg-gray-900
                  border border-gray-700
                  rounded-xl shadow-lg overflow-hidden
                "
                >
                  {/* User info */}
                  <div className="px-4 py-3 border-b border-gray-100">
                    <p className="text-xs text-gray-400">Signed in as</p>
                    <p className="text-sm font-semibold text-gray-100 truncate">
                      {loading ? "Loading..." : displayName}
                    </p>
                  </div>

                  <Link
                    to="/dashboard/settings"
                    onClick={() => setProfileOpen(false)}
                    className="flex items-center gap-3 px-4 py-3 text-sm
                      text-gray-300 hover:bg-gray-500
                      transition-colors"
                  >
                    <Settings size={15} />
                    Settings
                  </Link>

                  <button
                    onClick={handleLogout}
                    className="flex items-center gap-3 px-4 py-3 text-sm w-full
                      text-red-400
                      hover:bg-red-500/10
                      transition-colors cursor-pointer"
                  >
                    <LogOut size={15} />
                    Logout
                  </button>
                </div>
              )}
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto bg-gray-950">
          <div className="p-3">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
};

export default AdminLayout;
