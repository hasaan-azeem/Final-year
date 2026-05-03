import React, { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Highlighter } from "@/components/ui/highlighter";

const Header = () => {
  const [isOpen, setIsOpen] = useState(false);
  const navigate = useNavigate();

  const isLoggedIn = !!localStorage.getItem("token"); // simple auth check

  const handleDashboardClick = () => {
    if (isLoggedIn) {
      navigate("/dashboard");
    } else {
      navigate("/auth/dashboard/login");
    }
  };

  const menuItems = [
    { name: "Home", link: "/" },
    { name: "Features", link: "/features" },
    { name: "About Us", link: "/aboutus" },
    { name: "Contact", link: "/contact" },
  ];

  return (
    <header className="fixed top-4 left-1/2 -translate-x-1/2 w-[90%] max-w-7xl z-50 backdrop-blur-2xl bg-black/40 border border-white/10 rounded-xl shadow-[0_10px_40px_rgba(0,0,0,0.6)]">
      <div className="px-6 md:px-10 py-3 flex items-center justify-between">
        {/* Logo */}
        <Link
          to="/"
          className="text-lg sm:text-xl font-semibold text-white tracking-wide"
        >
          <span className="text-[#059669]">Web</span>XGuard
        </Link>

        {/* Desktop Nav */}
        <nav className="hidden lg:flex">
          <ul className="flex items-center gap-8">
            {menuItems.map((item) => (
              <li key={item.name} className="relative group">
                <Link
                  to={item.link}
                  className="text-white text-sm tracking-wide"
                >
                  {item.name}
                </Link>
                <span className="absolute left-0 -bottom-1 h-0.5 w-0 bg-[#059669] transition-all group-hover:w-full" />
              </li>
            ))}
          </ul>
        </nav>

        {/* Buttons */}
        <div className="hidden lg:flex items-center gap-3">
          {/* Dashboard instead of Login */}
          <button
            onClick={handleDashboardClick}
            className="text-sm text-gray-300 hover:text-white transition px-3 py-1.5 cursor-pointer"
          >
            <Highlighter action="circle" color="#FF9800">
              <span className="px-4">Dashboard</span>
            </Highlighter>
          </button>

          {/* CTA */}
          <Link
            to="/auth/dashboard/signup"
            className="text-sm font-medium px-5 py-2 rounded-lg bg-[#059669] hover:bg-[#047857] text-white transition shadow-lg shadow-emerald-900/30"
          >
            Get Started
          </Link>
        </div>

        {/* Mobile */}
        <div className="lg:hidden">
          <button onClick={() => setIsOpen(!isOpen)} className="text-white p-2">
            {isOpen ? "✕" : "☰"}
          </button>
        </div>
      </div>

      {/* Mobile Menu */}
      {isOpen && (
        <div className="lg:hidden border-t border-white/10 bg-black/60 backdrop-blur-xl">
          <ul className="flex flex-col px-6 py-4 space-y-3">
            {menuItems.map((item) => (
              <li key={item.name}>
                <Link
                  to={item.link}
                  className="text-gray-300 hover:text-white text-sm"
                  onClick={() => setIsOpen(false)}
                >
                  {item.name}
                </Link>
              </li>
            ))}

            {/* Dashboard Mobile */}
            <li>
              <button
                onClick={() => {
                  handleDashboardClick();
                  setIsOpen(false);
                }}
                className="block w-full text-center text-sm text-gray-300 py-2"
              >
                Dashboard
              </button>
            </li>

            <li>
              <Link
                to="/auth/dashboard/signup"
                className="block text-center bg-[#059669] py-2 rounded-lg text-sm text-white"
                onClick={() => setIsOpen(false)}
              >
                Get Started
              </Link>
            </li>
          </ul>
        </div>
      )}
    </header>
  );
};

export default Header;
