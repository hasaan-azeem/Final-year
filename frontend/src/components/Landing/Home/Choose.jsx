import React, { useEffect, useState } from "react";
import Skeleton from "react-loading-skeleton";
import "react-loading-skeleton/dist/skeleton.css";

const features = [
  {
    title: "AI-Powered Risk Analysis",
    description: "Prioritizes high-risk vulnerabilities for faster mitigation.",
    icon: (
      <>
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z"
        />
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4" />
        <circle cx="12" cy="15" r="1" />
      </>
    ),
  },
  {
    title: "Continuous Monitoring",
    description: "Detects new threats and configuration changes in real-time.",
    icon: (
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M3 10h4l3 10 4-18 3 8h4"
      />
    ),
  },
  {
    title: "Predictive Analysis",
    description:
      "Forecast future trends and outcomes to support smarter decisions.",
    icon: (
      <>
        <path strokeLinecap="round" strokeLinejoin="round" d="M4 20h16" />
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M5 15l4-4 4 3 6-6"
        />
        <circle cx="5" cy="15" r="1" />
        <circle cx="9" cy="11" r="1" />
        <circle cx="13" cy="14" r="1" />
        <circle cx="19" cy="8" r="1" />
      </>
    ),
  },
  {
    title: "Compliance Tracking",
    description: "Checks against standards like OWASP Top 10 and PCI DSS.",
    icon: (
      <>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3" />
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M12 2a10 10 0 1010 10A10 10 0 0012 2z"
        />
      </>
    ),
  },
  {
    title: "Comprehensive Reporting",
    description: "Interactive dashboards, trends, and exportable reports.",
    icon: (
      <>
        <path
          strokeLinecap="round"
          strokeLinejoin="round"
          d="M7 4h8l3 3v13a2 2 0 01-2 2H7a2 2 0 01-2-2V6a2 2 0 012-2z"
        />
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 16h6" />
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 8h4" />
      </>
    ),
  },
  {
    title: "Real-Time Alerts",
    description:
      "Immediate notifications for critical vulnerabilities or changes.",
    icon: (
      <path
        strokeLinecap="round"
        strokeLinejoin="round"
        d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a1 1 0 0 0 .87 1.5h18.62a1 1 0 0 0 .87-1.5L13.71 3.86Q12 2.8 10.29 3.86z"
      />
    ),
  },
];

const SectionThird = () => {

  const [loading, setLoading] = useState(true);

useEffect(() => {
  const timer = setTimeout(() => setLoading(false), 1200); // simulate API
  return () => clearTimeout(timer);
}, []);

  return (
    <section className="w-full bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 py-20 text-white">
      <div className="max-w-7xl mx-auto px-4 md:px-12 flex flex-col lg:flex-row gap-12">
        
        {/* LEFT CONTENT */}
        <div className="lg:w-1/3">
          {loading ? (
            <>
              <Skeleton height={40} width="80%" />
              <Skeleton count={3} className="mt-4" />
              <Skeleton width={120} className="mt-6" />
            </>
          ) : (
            <>
              <h2 className="text-3xl md:text-4xl font-bold mb-6">
                Why Choose WebXGuard?
              </h2>
              <p className="text-gray-300 text-lg mb-8">
                WebXGuard provides a comprehensive AI-powered platform to detect,
                monitor, and prioritize web vulnerabilities while ensuring
                compliance with industry standards.
              </p>

              <div className="flex items-center space-x-2">
                <a href="/signup" className="relative text-gray-100 font-semibold group">
                  Explore More
                  <span className="absolute left-0 bottom-0 w-0 h-0.5 bg-[#059669] transition-all duration-300 group-hover:w-full" />
                </a>
              </div>
            </>
          )}
        </div>

        {/* RIGHT GRID */}
        <div className="lg:w-2/3 grid grid-cols-1 sm:grid-cols-2 gap-8">
          {(loading ? Array(6).fill(0) : features).map((feature, index) => (
            <div
              key={index}
              className="bg-linear-to-br from-[#059669]/30 to-[#059669]/10 p-6 border border-[#059669] rounded-xl shadow-lg"
            >
              {loading ? (
                <>
                  <Skeleton circle width={40} height={40} />
                  <Skeleton height={20} width="70%" className="mt-4" />
                  <Skeleton count={2} className="mt-2" />
                </>
              ) : (
                <>
                  <div className="mb-4">
                    <svg
                      className="w-10 h-10 text-[#059669]"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      viewBox="0 0 24 24"
                    >
                      {feature.icon}
                    </svg>
                  </div>
                  <h3 className="text-xl font-semibold mb-2">
                    {feature.title}
                  </h3>
                  <p className="text-gray-300 text-sm">
                    {feature.description}
                  </p>
                </>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default SectionThird;
