import React, { useState, useEffect, useContext } from "react";
import { AuthContext } from "../../context/AuthContext";
import API from "../../api/backend_api";

const Setting = () => {
  // Get user AND updateUser from context
  // updateUser() — ek function jo context ka user state update kare
  // (neeche bataya hai AuthContext mein kaise add karein)
  const { user, updateUser } = useContext(AuthContext);

  const [formData, setFormData] = useState({
    full_name: "",
    email: "",
    username: "",
  });

  const [passwordData, setPasswordData] = useState({
    current_password: "",
    new_password: "",
    confirm_password: "",
  });

  const [loading, setLoading] = useState(false);
  const [passwordLoading, setPasswordLoading] = useState(false);
  const [message, setMessage] = useState({ type: "", text: "" });
  const [passwordMessage, setPasswordMessage] = useState({
    type: "",
    text: "",
  });

  // Fill form with current user data on load
  useEffect(() => {
    if (user) {
      setFormData({
        full_name: user.full_name || "",
        email: user.email || "",
        username: user.username || "",
      });
    }
  }, [user]);

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
    setMessage({ type: "", text: "" });
  };

  const handlePasswordChange = (e) => {
    setPasswordData({ ...passwordData, [e.target.name]: e.target.value });
    setPasswordMessage({ type: "", text: "" });
  };

  // ─── Profile update ───────────────────────────────────
  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setMessage({ type: "", text: "" });

    try {
      await API.put("/api/users/me", {
        full_name: formData.full_name,
        username: formData.username,
      });

      // Immediately update the context so navbar/topbar reflects new name
      // without needing a page refresh
      updateUser({
        ...user,
        full_name: formData.full_name,
        username: formData.username,
      });

      setMessage({ type: "success", text: "Profile updated successfully!" });
    } catch (error) {
      setMessage({
        type: "error",
        text:
          error.response?.data?.error?.message || "Failed to update profile",
      });
    } finally {
      setLoading(false);
    }
  };

  // ─── Password change ──────────────────────────────────
  const handlePasswordSubmit = async (e) => {
    e.preventDefault();
    setPasswordLoading(true);
    setPasswordMessage({ type: "", text: "" });

    if (passwordData.new_password !== passwordData.confirm_password) {
      setPasswordMessage({ type: "error", text: "Passwords do not match" });
      setPasswordLoading(false);
      return;
    }

    if (passwordData.new_password.length < 8) {
      setPasswordMessage({
        type: "error",
        text: "Password must be at least 8 characters",
      });
      setPasswordLoading(false);
      return;
    }

    try {
      await API.put("/api/users/me/password", {
        current_password: passwordData.current_password,
        new_password: passwordData.new_password,
      });

      setPasswordMessage({
        type: "success",
        text: "Password changed successfully!",
      });
      setPasswordData({
        current_password: "",
        new_password: "",
        confirm_password: "",
      });
    } catch (error) {
      setPasswordMessage({
        type: "error",
        text:
          error.response?.data?.error?.message || "Failed to change password",
      });
    } finally {
      setPasswordLoading(false);
    }
  };

  // ─── Reusable input class ─────────────────────────────
  const inputClass =
    "w-full px-3 py-2 border border-gray-600 rounded-md focus:outline-none focus:ring-1 focus:ring-emerald-500 bg-gray-700 text-gray-100 placeholder-gray-400";

  // ─── Alert banner ─────────────────────────────────────
  const Alert = ({ msg }) =>
    msg.text ? (
      <div
        className={`mb-4 p-4 rounded-lg text-sm border ${
          msg.type === "success"
            ? "bg-green-50 dark:bg-green-900/30 text-green-800 dark:text-green-400 border-green-200 dark:border-green-800 cursor-pointer"
            : "bg-red-50 dark:bg-red-900/30 text-red-800 dark:text-red-400 border-red-200 dark:border-red-800 cursor-pointer"
        }`}
      >
        {msg.text}
      </div>
    ) : null;

  return (
    <div className="max-w-2xl mx-auto space-y-6">
      {/* ── Personal Information ── */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-100 mb-6">
          Personal Information
        </h2>

        <Alert msg={message} />

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label
              className="block text-sm font-medium text-gray-300  mb-1"
              htmlFor="full_name"
            >
              Full Name
            </label>
            <input
              type="text"
              id="full_name"
              name="full_name"
              value={formData.full_name}
              onChange={handleChange}
              className={inputClass}
              placeholder="Enter your full name"
            />
          </div>

          <div>
            <label
              className="block text-sm font-medium text-gray-300 mb-1"
              htmlFor="username"
            >
              Username
            </label>
            <input
              type="text"
              id="username"
              name="username"
              value={formData.username}
              onChange={handleChange}
              className={inputClass}
              placeholder="Enter your username"
            />
          </div>

          <div>
            <label
              className="block text-sm font-medium text-gray-300 mb-1"
              htmlFor="email"
            >
              Email
            </label>
            <input
              type="email"
              id="email"
              name="email"
              value={formData.email}
              disabled
              className={`${inputClass} bg-gray-800 cursor-not-allowed opacity-60`}
            />
            <p className="text-xs text-gray-500 mt-1">
              Email cannot be changed
            </p>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-md font-medium text-sm transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {loading ? "Saving..." : "Save Changes"}
          </button>
        </form>
      </div>

      {/* ── Change Password ── */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 shadow-sm">
        <h2 className="text-lg font-semibold text-gray-100 mb-6">
          Change Password
        </h2>

        <Alert msg={passwordMessage} />

        <form onSubmit={handlePasswordSubmit} className="space-y-4">
          <div>
            <label
              className="block text-sm font-medium text-gray-300 mb-1"
              htmlFor="current_password"
            >
              Current Password
            </label>
            <input
              type="password"
              id="current_password"
              name="current_password"
              value={passwordData.current_password}
              onChange={handlePasswordChange}
              className={inputClass}
              placeholder="Enter current password"
            />
          </div>

          <div>
            <label
              className="block text-sm font-medium text-gray-300 mb-1"
              htmlFor="new_password"
            >
              New Password
            </label>
            <input
              type="password"
              id="new_password"
              name="new_password"
              value={passwordData.new_password}
              onChange={handlePasswordChange}
              className={inputClass}
              placeholder="Enter new password"
            />
            <p className="text-xs text-gray-500 mt-1">Minimum 8 characters</p>
          </div>

          <div>
            <label
              className="block text-sm font-medium text-gray-300 mb-1"
              htmlFor="confirm_password"
            >
              Confirm New Password
            </label>
            <input
              type="password"
              id="confirm_password"
              name="confirm_password"
              value={passwordData.confirm_password}
              onChange={handlePasswordChange}
              className={inputClass}
              placeholder="Confirm new password"
            />
          </div>

          <button
            type="submit"
            disabled={
              passwordLoading ||
              !passwordData.current_password ||
              !passwordData.new_password ||
              !passwordData.confirm_password
            }
            className="w-full py-2.5 bg-emerald-600 hover:bg-emerald-700 text-white rounded-md font-medium text-sm transition disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            {passwordLoading ? "Changing..." : "Change Password"}
          </button>
        </form>
      </div>
    </div>
  );
};

export default Setting;
