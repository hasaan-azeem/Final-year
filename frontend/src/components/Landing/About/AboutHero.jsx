import React, { useEffect, useState } from "react";

const AboutHero = () => {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const t = setTimeout(() => setVisible(true), 100);
    return () => clearTimeout(t);
  }, []);

  return (
    <section className="relative w-full h-screen overflow-hidden">
      <img
        src="/About_hero.jpeg"
        alt="About WebXGuard"
        className="absolute inset-0 w-full h-full object-cover"
      />
      <div className="absolute inset-0 bg-black/80" />

      <div className="relative z-10 flex items-center justify-center h-full px-6 md:px-20">
        <div className="max-w-4xl text-center">
          <h1 className="text-3xl sm:text-4xl md:text-5xl font-extrabold text-white max-w-3xl leading-tight">
            Securing the Future of Data
          </h1>
          <p className="mt-6 max-w-2xl text-gray-300 text-base sm:text-lg">
            At WebXGuard, we are dedicated to building a safer digital world
            through relentless innovation in security and an unwavering
            commitment to transparency.
          </p>
          <div
            className="flex flex-wrap justify-center gap-4 mt-10"
            style={{
              opacity: visible ? 1 : 0,
              transition: "opacity 0.55s ease 0.35s",
            }}
          >
            <a
              href="/auth/dashboard/signup"
              className="bg-emerald-600 hover:bg-emerald-700 transition-colors text-white px-7 py-3 rounded-lg font-semibold text-sm"
            >
              Start Free Scan
            </a>
            <a
              href="#our-story"
              className="border border-gray-600 hover:border-emerald-500 hover:text-emerald-400 transition-colors text-gray-300 px-7 py-3 rounded-lg font-semibold text-sm"
            >
              Our Story
            </a>
          </div>
        </div>
      </div>
    </section>
  );
};

export default AboutHero;
