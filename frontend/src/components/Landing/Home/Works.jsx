import React from "react";

const SectionFour = () => {
  // DATA: Steps for "How It Works" section
  // Keeping this data separate makes it easier to read and modify
  const howItWorksSteps = [
    {
      stepNumber: "01",
      title: "Add Target",
      description:
        "Submit the web application URL you want to scan for vulnerabilities.",
    },
    {
      stepNumber: "02",
      title: "Automated Scan",
      description:
        "Our engine analyzes the application using proven security techniques.",
    },
    {
      stepNumber: "03",
      title: "Analyze Risks",
      description:
        "Detected vulnerabilities are validated and prioritized by severity.",
    },
    {
      stepNumber: "04",
      title: "Actionable Reports",
      description: "Receive detailed insights with clear remediation guidance.",
    },
  ];

  return (
    <section className="relative bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 text-gray-100 py-20 overflow-hidden">
      <div className="max-w-7xl mx-auto px-4 md:px-12">
        {/* Section Header */}
        <div className="mb-20">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            How It Works ?
          </h2>
          <p className="text-gray-300 text-lg mb-6">
            Identify and fix security risks through a simple, automated workflow
            designed for modern web applications.
          </p>
        </div>

        {/* Steps Grid */}
        <div className="relative grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Loop through each step */}
          {howItWorksSteps.map((step, index) => (
            <div
              key={index}
              className="group relative bg-linear-to-br from-[#059669]/30 to-[#059669]/10 backdrop-blur-md border border-[#059669]/80 rounded-2xl p-7
                   hover:-translate-y-2 hover:shadow-2xl hover:shadow-[#059669]/20
                   transition-all duration-300"
            >
              {/* Step Badge */}
              <div className="flex items-center justify-between mb-6">
                <span className="text-sm font-semibold text-[#059669]">
                  STEP {step.stepNumber}
                </span>
                <span className="w-3 h-3 rounded-full bg-[#059669]/70" />
              </div>

              {/* Step Title */}
              <h3 className="text-xl font-semibold mb-3">{step.title}</h3>

              {/* Step Description */}
              <p className="text-gray-300 leading-relaxed">
                {step.description}
              </p>

              {/* Bottom decorative line */}
              <div className="absolute inset-x-0 bottom-0 h-px bg-linear-to-r from-transparent via-[#059669]/40 to-transparent opacity-0 group-hover:opacity-100 transition" />
            </div>
          ))}
        </div>

        {/* Decorative grid image */}
        <div className="items-center justify-center hidden md:block">
          <img
            src="hero-grid.svg"
            alt="Hero Grid"
            className="w-full max-w-7xl h-auto pt-1"
          />
        </div>
      </div>
    </section>
  );
};

export default SectionFour;
