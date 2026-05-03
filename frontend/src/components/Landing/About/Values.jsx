import React from "react";

const VALUES = [
  {
    title: "Innovation",
    desc: "We stay ahead of the evolving cybersecurity landscape using AI, machine learning, and advanced analytics to detect vulnerabilities and anticipate emerging threats.",
  },
  {
    title: "Integrity",
    desc: "Trust is at our core. We operate transparently with honest assessments, ethical practices, and accurate results that our clients can depend on.",
  },
  {
    title: "Customer Focus",
    desc: "We deeply understand each organization’s needs and deliver tailored solutions, personalized support, and long term partnerships that ensure success.",
  },
  {
    title: "Reliability",
    desc: "Our tools provide consistent, dependable protection with real time monitoring and actionable insights so your digital assets stay secure at all times.",
  },
];

const Values = () => {
  return (
    <section
      aria-labelledby="values-heading"
      className="relative w-full bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 py-20"
    >
      <div className="mx-auto max-w-7xl px-4 md:px-12 grid gap-12 lg:grid-cols-3">
        {/* Left intro */}
        <div className="lg:pr-8">
          <h2
            id="values-heading"
            className="text-3xl md:text-4xl font-bold text-gray-100 mb-6"
          >
            Our <span className="text-emerald-500">Values</span>
          </h2>
          <p className="text-gray-300 text-lg leading-relaxed">
            Guiding principles that drive our commitment to excellence,
            innovation, and client success.
          </p>
        </div>

        {/* Values list */}
        <div className="lg:col-span-2 grid gap-8 sm:grid-cols-2">
          {VALUES.map((item, i) => (
            <div
              key={i}
              className="rounded-xl border border-emerald-500/40 bg-linear-to-br from-emerald-500/20 to-emerald-500/5 p-6 hover:scale-[1.03] transition-transform"
            >
              <h3 className="text-lg font-semibold text-white mb-2">
                {item.title}
              </h3>
              <p className="text-gray-300 text-base leading-relaxed">
                {item.desc}
              </p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default Values;
