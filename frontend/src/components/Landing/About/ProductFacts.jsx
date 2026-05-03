import React from "react";

const ProductFacts = () => {
  return (
    <section className="relative w-full bg-linear-to-b from-gray-950 via-gray-900 to-gray-950">

      {/* Top image */}
      <img
        src="/hero-grid.svg"
        alt="Hero Grid"
        className="block w-full max-w-7xl mx-auto"
      />

      {/* SINGLE inner container */}
      <div className="mx-auto max-w-7xl px-4 md:px-12 -mt-12 pb-20">

        {/* Heading */}
        <h2 className="text-3xl md:text-4xl font-bold text-gray-100 mb-12 text-left">
          Product Facts
        </h2>

        {/* Responsive grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-8">

          {/* Card 1 */}
          <div className="bg-linear-to-br from-[#059669]/30 to-[#059669]/10 p-6 border border-[#059669] rounded-xl shadow-lg hover:scale-105 transition-transform duration-300 relative">
            <div className="mb-4">
              <svg className="w-10 h-10 text-[#059669]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7l8-4z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4" />
                <circle cx="12" cy="15" r="1" />
              </svg>
            </div>
            <h3 className="text-xl text-gray-100 font-semibold mb-2">
              AI-Powered Risk Analysis
            </h3>
            <p className="text-gray-300 text-sm">
              Prioritizes high-risk vulnerabilities for faster mitigation.
            </p>
          </div>

          {/* Card 2 */}
          <div className="bg-linear-to-br from-[#059669]/30 to-[#059669]/10 p-6 border border-[#059669] rounded-xl shadow-lg hover:scale-105 transition-transform duration-300 relative">
            <div className="mb-4">
              <svg className="w-10 h-10 text-[#059669]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M3 10h4l3 10 4-18 3 8h4" />
              </svg>
            </div>
            <h3 className="text-xl text-gray-100 font-semibold mb-2">
              Continuous Monitoring
            </h3>
            <p className="text-gray-300 text-sm">
              Detects new threats and configuration changes in real-time.
            </p>
          </div>

          {/* Card 3 */}
          <div className="bg-linear-to-br from-[#059669]/30 to-[#059669]/10 p-6 border border-[#059669] rounded-xl shadow-lg hover:scale-105 transition-transform duration-300 relative">
            <div className="mb-4">
              <svg className="w-10 h-10 text-[#059669]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 20h16" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M5 15l4-4 4 3 6-6" />
                <circle cx="5" cy="15" r="1" />
                <circle cx="9" cy="11" r="1" />
                <circle cx="13" cy="14" r="1" />
                <circle cx="19" cy="8" r="1" />
              </svg>
            </div>
            <h3 className="text-xl text-gray-100 font-semibold mb-2">
              Predictive Analysis
            </h3>
            <p className="text-gray-300 text-sm">
              Forecast future trends and outcomes, helping you make smarter decisions.
            </p>
          </div>

          {/* Card 4 */}
          <div className="bg-linear-to-br from-[#059669]/30 to-[#059669]/10 p-6 border border-[#059669] rounded-xl shadow-lg hover:scale-105 transition-transform duration-300 relative">
            <div className="mb-4">
              <svg className="w-10 h-10 text-[#059669]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 8v4l3 3" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 2a10 10 0 1010 10A10 10 0 0012 2z" />
              </svg>
            </div>
            <h3 className="text-xl text-gray-100 font-semibold mb-2">
              Compliance Tracking
            </h3>
            <p className="text-gray-300 text-sm">
              Checks against standards like OWASP Top 10 and PCI DSS.
            </p>
          </div>

          {/* Card 5 */}
          <div className="bg-linear-to-br from-[#059669]/30 to-[#059669]/10 p-6 border border-[#059669] rounded-xl shadow-lg hover:scale-105 transition-transform duration-300 relative">
            <div className="mb-4">
              <svg className="w-10 h-10 text-[#059669]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M7 4h8l3 3v13a2 2 0 01-2 2H7a2 2 0 01-2-2V6a2 2 0 012-2z" />
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6M9 16h6M9 8h4" />
              </svg>
            </div>
            <h3 className="text-xl text-gray-100 font-semibold mb-2">
              Comprehensive Reporting
            </h3>
            <p className="text-gray-300 text-sm">
              Interactive dashboards, trends, and exportable reports.
            </p>
          </div>

          {/* Card 6 */}
          <div className="bg-linear-to-br from-[#059669]/30 to-[#059669]/10 p-6 border border-[#059669] rounded-xl shadow-lg hover:scale-105 transition-transform duration-300 relative">
            <div className="mb-4">
              <svg className="w-10 h-10 text-[#059669]" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v4M12 17h.01M10.29 3.86L1.82 18a1 1 0 0 0 .87 1.5h18.62a1 1 0 0 0 .87-1.5L13.71 3.86 Q12 2.8 10.29 3.86z" />
              </svg>
            </div>
            <h3 className="text-xl text-gray-100 font-semibold mb-2">
              Real-Time Alerts
            </h3>
            <p className="text-gray-300 text-sm">
              Immediate notifications for critical vulnerabilities or changes.
            </p>
          </div>

        </div>
      </div>
    </section>
  );
};

export default ProductFacts;
