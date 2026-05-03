// CTA (Call To Action) Component
// This is a boxed section that encourages users to take action
import React from "react";
import { Link } from "react-router-dom";

const CTA = () => {
  return (
    // SECTION CONTAINER: Dark background with centered content
    <section className="bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 flex justify-center pb-30">
      <div className="max-w-7xl mx-auto px-4 md:px-12">
        {/* MAIN BOX: Gradient background with green border */}
        <div className="relative w-full p-10 bg-linear-to-br from-[#059669]/40 to-[#059669]/10 rounded-2xl border-2 border-[#059669]">
          {/* Decorative outer glow effect */}
          <div className="absolute inset-0 rounded-2xl"></div>

          {/* CONTENT SECTION */}
          <div className="relative z-10 text-center lg:text-left">
            {/* Main heading */}
            <h2 className="text-3xl text-white md:text-4xl font-bold mb-6">
              Secure Your Application Today
            </h2>

            {/* Description text */}
            <p className="text-gray-300 text-lg mb-6">
              Don't leave your systems exposed. Run a vulnerability assessment
              now and ensure your web applications are fully protected against
              all vulnerabilities.
            </p>

            {/* ACTION BUTTONS */}
            <div className="flex flex-col sm:flex-row justify-center lg:justify-start gap-4">
              {/* Primary button - Get Started */}
              <Link
                to="/auth/dashboard/signup"
                className="px-8 py-4 bg-[#059669]/80 text-gray-100 font-semibold rounded-lg shadow-lg hover:bg-[#059669] transition"
              >
                Get Started
              </Link>

              {/* Secondary button - Learn More */}
              <a
                href="#learn-more"
                className="px-8 py-4 border border-[#059669] text-[#059669] font-semibold rounded-lg hover:bg-[#059669] hover:text-gray-100 transition"
              >
                Learn More
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
};

// Export the component
export default CTA;
