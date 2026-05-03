import React, { useState } from "react";
import { HelpCircle, ChevronDown, Mail } from "lucide-react";
import { Link } from "react-router-dom"; // for internal docs page redirect

const faqs = [
  {
    question: "What is the Website Scan Engine?",
    answer: (
      <>
        The scan engine automatically crawls your website and identifies
        vulnerabilities such as XSS, SQL injection, misconfigurations, and
        insecure headers. For more details, check the{" "}
        <Link to="/docs/scan-engine" className="text-[#10B981] hover:underline">
          documentation
        </Link>
        .
      </>
    ),
  },
  {
    question: "How does Continuous Monitoring work?",
    answer: (
      <>
        Continuous monitoring periodically scans your assets and alerts you
        instantly when new risks or suspicious activities are detected. Learn
        more in the{" "}
        <Link
          to="/docs/continuous-monitoring"
          className="text-[#10B981] hover:underline"
        >
          guide
        </Link>
        .
      </>
    ),
  },
  {
    question: "What is AI Risk Analysis?",
    answer: (
      <>
        AI models prioritize vulnerabilities based on severity, exploitability,
        and real world impact so you can fix the most critical issues first. See
        the{" "}
        <Link
          to="/docs/ai-risk-analysis"
          className="text-[#10B981] hover:underline"
        >
          full explanation
        </Link>
        .
      </>
    ),
  },
  {
    question: "What is the Website Health and Compliance Checker?",
    answer: (
      <>
        This module validates security headers, SSL configuration, performance
        metrics, and compliance standards such as OWASP and GDPR. Check our{" "}
        <a
          href="https://example.com/docs/health-compliance"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[#10B981] hover:underline"
        >
          docs page
        </a>{" "}
        for more info.
      </>
    ),
  },
  {
    question: "Can I export reports?",
    answer: (
      <>
        Yes, you can export detailed PDF or JSON reports for audits, compliance
        submissions, or sharing with your security team. Learn how{" "}
        <Link
          to="/docs/export-reports"
          className="text-[#10B981] hover:underline"
        >
          here
        </Link>
        .
      </>
    ),
  },
  {
    question: "Does it support real time alerts?",
    answer: (
      <>
        You receive instant notifications via email or dashboard whenever
        critical threats are detected. See the{" "}
        <Link to="/docs/alerts" className="text-[#10B981] hover:underline">
          alerts guide
        </Link>{" "}
        for details.
      </>
    ),
  },
  {
    question: "Is my data secure?",
    answer: (
      <>
        All scans and reports are encrypted in transit and at rest to ensure
        maximum privacy and protection of your information. Read our{" "}
        <a
          href="https://example.com/docs/security"
          target="_blank"
          rel="noopener noreferrer"
          className="text-[#10B981] hover:underline"
        >
          security documentation
        </a>
        .
      </>
    ),
  },
];

const HelpSupport = () => {
  const [openIndex, setOpenIndex] = useState(null);

  const toggle = (i) => {
    setOpenIndex(openIndex === i ? null : i);
  };

  return (
    <section className="w-full min-h-screen p-4 ">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <HelpCircle className="text-[#10B981]" size={24} />
          <h2 className="text-2xl font-bold text-white">Help & Support</h2>
        </div>
        <div className="flex sm:flex-row flex-col gap-3">
          <p className="text-gray-400 text-sm">
            Need help or facing issues, contact our support team anytime.
          </p>

          <a
            href="mailto:webxguard@gmail.com"
            className="inline-flex items-center gap-2 text-[#10B981] hover:underline text-sm"
          >
            <Mail size={16} />
            webxguard@gmail.com
          </a>
        </div>
      </div>

      {/* FAQ Cards */}
      <div className="space-y-4">
        {faqs.map((faq, i) => {
          const isOpen = openIndex === i;

          return (
            <div
              key={i}
              className="
                rounded-2xl
                bg-gray-800
                border border-gray-200 dark:border-gray-700
                shadow-sm hover:shadow-md
                transition
              "
            >
              <button
                onClick={() => toggle(i)}
                className="w-full flex items-center justify-between px-5 py-4 text-left"
              >
                <span className="font-medium text-white">{faq.question}</span>

                <ChevronDown
                  size={18}
                  className={`transition-transform duration-300 ${
                    isOpen ? "rotate-180 text-[#10B981]" : ""
                  }`}
                />
              </button>

              {/* Smooth animation */}
              <div
                className={`grid transition-all duration-300 ease-in-out ${
                  isOpen
                    ? "grid-rows-[1fr] opacity-100"
                    : "grid-rows-[0fr] opacity-0"
                }`}
              >
                <div className="overflow-hidden">
                  <div className="px-5 pb-4 text-sm leading-relaxed text-gray-300">
                    {faq.answer}
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
};

export default HelpSupport;
