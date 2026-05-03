import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App.jsx";
import { AuthProvider } from "./context/AuthContext";
import Skeleton, { SkeletonTheme } from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";

createRoot(document.getElementById("root")).render(
  <StrictMode>
    <AuthProvider>
      <SkeletonTheme
        baseColor="#1e293b"   // dark base
        highlightColor="#334155" // shimmer
      >
        <App />
      </SkeletonTheme>
    </AuthProvider>
  </StrictMode>,
);
