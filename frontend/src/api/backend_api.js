// import axios from "axios";

// // Create a single axios instance
// const API = axios.create({
//   baseURL: "http://localhost:5000", // Flask backend
//   headers: {
//     "Content-Type": "application/json",
//   },
//   withCredentials: true, // for cookies if needed
// });

// // Request interceptor to automatically add Authorization header
// API.interceptors.request.use(
//   (config) => {
//     const token = localStorage.getItem("token");
//     if (token) {
//       config.headers.Authorization = `Bearer ${token}`;
//     }
//     return config;
//   },
//   (error) => Promise.reject(error)
// );

// export default API;

import axios from "axios";

const API = axios.create({
  baseURL: "http://localhost:5000",
  withCredentials: true,
  headers: {
    "Content-Type": "application/json",
  },
});

// Add request interceptor to attach token to all requests
API.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Add response interceptor for better error handling
API.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // Token expired or invalid
      localStorage.removeItem("token");
      window.location.href = "/auth/dashboard/login";
    }
    return Promise.reject(error);
  }
);

export default API;