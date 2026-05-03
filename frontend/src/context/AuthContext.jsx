/* eslint-disable react-refresh/only-export-components */
import { createContext, useState, useEffect } from "react";
import API from "../api/backend_api";

export const AuthContext = createContext();

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      fetchUser();
    } else {
      setLoading(false);
    }
  }, []);

  const fetchUser = async () => {
    try {
      const res = await API.get("/api/auth/me");
      setUser(res.data);
    } catch (error) {
      console.error("Failed to fetch user:", error);
      localStorage.removeItem("token");
      setUser(null);
    } finally {
      setLoading(false);
    }
  };
  // Yeh function add karo
  const updateUser = (newUserData) => {
    setUser(newUserData);
  };
  const login = async (access_token, userData = null) => {
    try {
      localStorage.setItem("token", access_token);
      if (userData) {
        setUser(userData);
        setLoading(false);
      } else {
        await fetchUser();
      }
    } catch (error) {
      console.error("Login error:", error);
      localStorage.removeItem("token");
      setLoading(false);
      throw error;
    }
  };

  const logout = async () => {
    try {
      await API.post("/api/auth/logout");
    } catch (error) {
      console.error("Logout error:", error);
    } finally {
      localStorage.removeItem("token");
      localStorage.removeItem("refresh_token");
      setUser(null);
    }
  };

  // Whether the currently logged-in user has verified their email
  const isVerified = user?.is_verified === true;

  return (
    <AuthContext.Provider
      value={{
        user,
        login,
        logout,
        loading,
        fetchUser,
        updateUser,
        isVerified,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}
