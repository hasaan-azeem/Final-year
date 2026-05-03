import { AnimatedTestimonials } from "@/components/ui/animated-testimonials";
import React from "react";

const CompanyFacts = () => {
  const testimonials = [
  {
    name: "Tehzeeb Kousar",
    designation: "Cyber Security",
    quote:
      "Building secure systems on identifying vulnerabilities, strengthening defenses, and ensuring applications remain protected against modern cyber threats.",
    src: "/testimonials/tk.jfif",
  },
  {
    name: "Warisha Hammad",
    designation: "AI/ML Engineer",
    quote:
      "I design intelligent solutions using machine learning to analyze data, automate processes, and create smarter applications that continuously learn and improve.",
    src: "/testimonials/wari.jpg",
  },
  {
    name: "Hasaan Azeem",
    designation: "Full Stack Developer",
    quote:
      "I develop scalable web applications from frontend to backend, ensuring seamless performance, clean architecture, and a smooth user experience.",
    src: "/testimonials/hasaan.jpeg",
  },
];

  return (
    <section className="relative w-full py-20 bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 text-gray-100">
      <div className="max-w-7xl mx-auto px-4 md:px-12 flex flex-col lg:flex-row items-center gap-12">
        <div className="lg:w-2/3 flex flex-col justify-center">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            Meet Developers
          </h2>
          <p className="text-gray-300 text-base sm:text-lg leading-relaxed">
            Our development team brings together expertise in full stack
            engineering, artificial intelligence, and cybersecurity to build
            powerful and secure digital products. From designing scalable
            architectures to developing intelligent systems and protecting
            applications from modern threats, our developers collaborate to
            create reliable, high-performance solutions that help businesses
            innovate with confidence.
          </p>
        </div>

        <div className="text-white">
          <AnimatedTestimonials testimonials={testimonials} />
        </div>
      </div>
    </section>
  );
};

export default CompanyFacts;
