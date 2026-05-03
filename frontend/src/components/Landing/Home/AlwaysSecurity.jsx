import React from "react";

const SectionTwo = () => {
  return (
    <section className="relative w-full bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 py-45 z-10">
      <div className="max-w-7xl mx-auto px-4 md:px-12 flex flex-col md:flex-row items-center gap-10 top-12 relative z-10">
        {/* Text Content */}
        <div className="md:w-3/4 flex flex-col justify-center">
          <h2 className="text-3xl md:text-4xl font-bold text-gray-100 mb-6">
            Always-On Security for{" "}
            <span className="text-[#059669]">Web Apps</span>
          </h2>

          <p className="text-gray-300 text-lg mb-6">
            The complexity of software development makes web applications a
            prime target for attacks. WebXGuard provides continuous monitoring
            to detect vulnerabilities as they arise, helping you stay secure and
            compliant at all times.
          </p>
        </div>

        {/* Image */}
        <div className="md:w-1/4 relative flex justify-center z-10">
          <div className="absolute w-48 h-48 bg-[#059669] opacity-20 blur-3xl rounded-full top-0 left-1/2 -translate-x-1/2"></div>

          <img
            src="/web-security.png"
            alt="Continuous Security Illustration"
            className="relative w-full max-w-xs object-contain"
          />
        </div>
      </div>
    </section>
  );
};

export default SectionTwo;
