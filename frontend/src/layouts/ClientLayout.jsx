// ClientLayout.jsx
import React from "react";
import { Outlet } from "react-router-dom";
import Header from "../components/Landing/Common/Header";
import Footer from "../components/Landing/Common/Footer";

const ClientLayout = () => {
  // const location = useLocation();

  const hideAuthButtons =
    location.pathname === "/login" || location.pathname === "/signup";

  return (
    <div className="min-h-screen flex flex-col w-full overflow-x-hidden">
      {/* Header */}
      <Header hideAuthButtons={hideAuthButtons} />

      {/* Main Content */}
      <main className="grow w-full">
        <Outlet /> {/* <-- Child routes render here */}
      </main>

      {/* Footer */}
      <Footer />
    </div>
  );
};

export default ClientLayout;
