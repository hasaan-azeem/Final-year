import React from "react";
import { useNavigate } from "react-router-dom";
import heroVideo from "../../../assets/hero.mp4";
import { AnimatedTooltip } from "@/components/ui/animated-tooltip";
import { Highlighter } from "@/components/ui/highlighter";
import PremiumDashboard from "./PremiumDashboard";

const Hero = () => {
  const navigate = useNavigate();

  const handleStartScan = () => {
    const token =
      localStorage.getItem("token") || sessionStorage.getItem("token");

    if (token) {
      navigate("/dashboard/scanner");
    } else {
      sessionStorage.setItem("redirectAfterLogin", "/dashboard/scanner");
      navigate("/auth/dashboard/login");
    }
  };

  return (
    <section className="w-screen min-h-[120vh] relative overflow-visible flex flex-col pb-40">
      {/* Background Video */}
      <video
        autoPlay
        muted
        loop
        playsInline
        preload="auto"
        className="absolute top-0 left-0 w-full h-full object-cover"
      >
        <source src={heroVideo} type="video/mp4" />
      </video>

      {/* Overlay */}
      <div className="absolute inset-0 bg-linear-to-b from-black/80 via-black/70 to-black/90 z-10" />

      {/* Content */}
      <div className="relative z-10 flex flex-col h-full py-20 sm:py-8 ">
        <div className="flex-1 flex items-center justify-center px-6 md:px-20 pt-24 md:pt-32 pb-10">
          <div className="max-w-4xl text-center">
            {/* Tagline */}
            <p className="text-sm tracking-widest uppercase text-[#059669] mb-4">
              <Highlighter action="underline" color="#FF9800">
                Welcome to WebXGuard
              </Highlighter>
            </p>

            {/* Heading */}
            <h1 className="text-2xl sm:text-3xl md:text-5xl font-extrabold text-gray-100 leading-tight">
              Detect Vulnerabilities, <br />
              <span className="text-[#059669]">Ensure Compliance</span>
            </h1>

            {/* Description */}
            <p className="mt-5 text-sm sm:text-base text-gray-300 max-w-2xl mx-auto">
              Scan your website instantly and uncover critical security risks,
              hidden vulnerabilities, and potential weak points before attackers
              can discover and exploit them. Get clear, actionable insights to
              improve your security posture in real time.
            </p>

            {/* Buttons */}
            <div className="mt-8 flex flex-col sm:flex-row gap-4 justify-center items-center">
              <button
                onClick={handleStartScan}
                className="bg-[#059669] hover:bg-[#047857] text-white px-8 py-3 rounded-lg font-semibold transition shadow-lg shadow-emerald-900/30 cursor-pointer"
              >
                Start Scan
              </button>

              <button
                onClick={() => navigate("/features")}
                className="px-7 py-3 rounded-lg border border-white/20 text-gray-200 hover:bg-white/10 transition backdrop-blur-md cursor-pointer"
              >
                Explore Features
              </button>
            </div>
          </div>
        </div>
      </div>
      <PremiumDashboard />
    </section>
  );
};

export default Hero;
