import React, { useEffect, useState } from "react";
import {
  AnimatedSpan,
  Terminal,
  TypingAnimation,
} from "@/components/ui/terminal";

// Feature pill tags shown below the description
const FEATURE_PILLS = [
  "AI Risk Scoring",
  "OWASP Top 10",
  "CI/CD Ready",
  "Real-Time Alerts",
  "PDF Reports",
];

const FeatureHero = () => {
  // Controls whether elements are visible (for fade-up animations)
  const [visible, setVisible] = useState(false);

  // Trick: changing this key forces Terminal to fully remount
  // which restarts all Magic UI animations from the beginning
  const [terminalKey, setTerminalKey] = useState(0);

  // Trigger page entrance animations on load
  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), 100);
    return () => clearTimeout(timer);
  }, []);

  // Loop the terminal every 10 seconds
  // (~7s for all lines to finish + ~3s pause before restart)
  useEffect(() => {
    const loop = setInterval(() => {
      setTerminalKey((prev) => prev + 1);
    }, 16000);
    return () => clearInterval(loop);
  }, []);

  // Returns inline animation styles with a staggered delay
  function fadeUp(delay = 0) {
    return {
      opacity: visible ? 1 : 0,
      transform: visible ? "translateY(0)" : "translateY(16px)",
      transition: `opacity 0.55s ease ${delay}ms, transform 0.55s ease ${delay}ms`,
    };
  }

  return (
    <section className="relative w-full min-h-screen overflow-hidden flex flex-col">
      {/* Background image */}
      <img
        src="/images/Feature.jpeg"
        alt="Hero Background"
        className="absolute inset-0 w-full h-full object-cover"
      />

      {/* Dark overlay so text is readable */}
      <div className="absolute inset-0 bg-gray-950/85" />

      {/* linear: darker at top and bottom */}
      <div className="absolute inset-0 bg-linear-to-b from-gray-950/30 via-transparent to-gray-950/90" />

      {/* Subtle grid texture */}
      <div
        className="absolute inset-0 pointer-events-none opacity-10"
        style={{
          backgroundImage:
            "linear-linear(rgba(5,150,105,0.2) 1px, transparent 1px), linear-linear(90deg, rgba(5,150,105,0.2) 1px, transparent 1px)",
          backgroundSize: "48px 48px",
        }}
      />

      {/* Soft green glow in background */}
      <div className="absolute top-0 left-1/4 w-[500px] h-64 bg-emerald-500/10 blur-[100px] rounded-full pointer-events-none" />

      {/* Page content */}
      <div className="relative z-10 flex-1 flex items-center px-6 md:px-16 lg:px-20 py-28">
        <div className="w-full max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-2 gap-14 items-center">
          {/* ══ LEFT SIDE — Text content ══ */}
          <div>
          {/* Main heading */}
            <h1
              className="text-4xl md:text-5xl lg:text-6xl font-extrabold text-gray-100 leading-tight"
              style={fadeUp(100)}
            >
              WebXGuard
            </h1>

            {/* Sub-heading in green */}
            <h2
              className="text-2xl md:text-3xl font-semibold text-emerald-400 mt-2 leading-snug"
              style={fadeUp(160)}
            >
              Security Platform
            </h2>

            {/* Description paragraph */}
            <p
              className="mt-6 text-lg text-gray-300 leading-relaxed max-w-lg"
              style={fadeUp(220)}
            >
              A complete AI-driven security solution designed to protect,
              monitor, and strengthen modern web applications at every stage of
              your development lifecycle.
            </p>

            {/* Feature pill tags */}
            <div className="flex flex-wrap gap-2 mt-8" style={fadeUp(300)}>
              {FEATURE_PILLS.map((tag) => (
                <span
                  key={tag}
                  className="text-xs text-gray-400 bg-gray-800/60 border border-gray-700/50 rounded-full px-3 py-1 cursor-pointer"
                >
                  {tag}
                </span>
              ))}
            </div>

            {/* Call-to-action buttons */}
            <div className="flex flex-wrap gap-4 mt-10" style={fadeUp(360)}>
              <a
                href="auth/dashboard/login"
                className="bg-emerald-600 hover:bg-emerald-700 transition-colors text-white px-7 py-3 rounded-lg font-semibold text-sm"
              >
                Start Free Scan
              </a>
              <a
                href="#overview"
                className="border border-gray-600 hover:border-emerald-500 hover:text-emerald-400 transition-colors text-gray-300 px-7 py-3 rounded-lg font-semibold text-sm"
              >
                Explore Features
              </a>
            </div>
          </div>

          {/* ══ RIGHT SIDE — Magic UI Terminal (loops via key remount) ══ */}
          <div
            style={{
              opacity: visible ? 1 : 0,
              transform: visible ? "translateY(0)" : "translateY(24px)",
              transition: "opacity 0.6s ease 450ms, transform 0.6s ease 450ms",
            }}
          >
            {/*
              key={terminalKey} — every time terminalKey changes,
              React fully destroys and recreates the Terminal,
              which restarts all TypingAnimation and AnimatedSpan animations.
            */}
            <Terminal
              key={terminalKey}
              className="w-full max-h-[480px] overflow-y-auto bg-gray-950 border border-gray-700/60"
            >
              <TypingAnimation className="text-emerald-400">
                $ webxguard scan --target https://target-app.com
              </TypingAnimation>

              <AnimatedSpan className="text-gray-400">
                Initializing scan engine v3.4.1...
              </AnimatedSpan>
              <AnimatedSpan className="text-gray-400">
                Crawling application... 47 endpoints found
              </AnimatedSpan>

              <AnimatedSpan className="text-amber-400">
                [!] SQL Injection detected — /api/login
              </AnimatedSpan>
              <AnimatedSpan className="text-amber-400">
                [!] XSS (Stored) detected — /comments
              </AnimatedSpan>
              <AnimatedSpan className="text-amber-400">
                [!] Broken Access Control — /admin/users
              </AnimatedSpan>

              <AnimatedSpan className="text-gray-400">
                Checking OWASP Top 10 compliance...
              </AnimatedSpan>
              <AnimatedSpan className="text-emerald-300">
                [✓] HTTPS enforced
              </AnimatedSpan>
              <AnimatedSpan className="text-emerald-300">
                [✓] CSRF tokens present
              </AnimatedSpan>
              <AnimatedSpan className="text-red-400">
                [✗] Missing Content-Security-Policy header
              </AnimatedSpan>
              <AnimatedSpan className="text-red-400">
                [✗] Server version disclosed in headers
              </AnimatedSpan>

              <AnimatedSpan className="text-gray-400">
                Running AI risk scoring...
              </AnimatedSpan>
              <AnimatedSpan className="text-emerald-300">
                [✓] Scan complete — 14 vulnerabilities found
              </AnimatedSpan>
              <AnimatedSpan className="text-white font-semibold">
                Critical: 3 | High: 5 | Medium: 6
              </AnimatedSpan>

              <TypingAnimation className="text-emerald-400">
                $ webxguard report --format pdf
              </TypingAnimation>
              <AnimatedSpan className="text-emerald-300">
                [✓] Report saved — report.pdf
              </AnimatedSpan>
            </Terminal>
          </div>
        </div>
      </div>

      {/* Bottom fade into next section */}
      <div className="absolute bottom-0 left-0 right-0 h-20 bg-linear-to-t from-gray-950 to-transparent pointer-events-none" />
    </section>
  );
};

export default FeatureHero;
