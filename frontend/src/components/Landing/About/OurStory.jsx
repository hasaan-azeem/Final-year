import React from "react";

const OurStory = () => {
  return (
    <section className="relative w-full bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 py-20">
      <div className="max-w-7xl mx-auto px-4 md:px-12 flex flex-col md:flex-row items-center gap-12">
        {/* Left content */}
        <div className="w-full md:w-1/2 flex flex-col justify-center">
          <h2 className="text-3xl md:text-4xl font-bold text-gray-100 mb-6">
            Company Story
          </h2>

          <p className="text-gray-300 text-lg mb-6 leading-relaxed">
            WebXGuard was born from a vision to make the digital world safer.
            What started as a small team of passionate engineers has grown into
            a trusted platform empowering organizations worldwide to detect
            vulnerabilities and secure their applications.
          </p>

          <p className="text-gray-300 text-lg leading-relaxed">
            Every scan, every insight, every report we deliver is designed to
            protect businesses and users alike, giving them the confidence to
            innovate securely.
          </p>
        </div>

        {/* Right image */}
        <div className="relative w-full md:w-1/2 flex justify-center">
          <div className="absolute w-72 h-72 bg-emerald-500/30 blur-3xl rounded-full" />
          <img
            src="/web-security.png"
            alt="Cybersecurity Illustration"
            className="relative w-64 md:w-80 lg:w-96"
          />
        </div>
      </div>
    </section>
  );
};

export default OurStory;
