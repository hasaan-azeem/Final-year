// FAQ (Frequently Asked Questions) Component
// This creates an accordion-style FAQ section where users can click to expand answers
import React, { useState } from "react";

// FAQ DATA: Array of questions and answers
// Each object has a 'question' and an 'answer'
const faqData = [
  {
    question: "What is a web vulnerability scanner?",
    answer:
      "A web vulnerability scanner is a specialized software tool designed to automatically identify security flaws within web applications. A reliable, robust website security scanner should be able to mimic real attacker tactics and identify realistic, exploitable security issues.\n\nOur Website Vulnerability Scanner is a robust example of this type of tool, offering a comprehensive scan that identifies threats and also validates them to reduce false positives.\n\nIt works by interacting with the target application, sending a series of HTTP requests with specific payloads, and analyzing the responses to detect potential vulnerabilities such as Cross-Site Scripting (XSS), SQL injection, OWASP Top10, and other pressing security issues and misconfigurations.",
  },
  {
    question:
      "What types of web vulnerabilities can the Website Vulnerability Scanner detect?",
    answer:
      "The scanner can detect common vulnerabilities such as SQL Injection, Cross-Site Scripting (XSS), Remote Code Execution (RCE), Security Misconfigurations, Broken Authentication, and other issues listed in the OWASP Top 10.",
  },
  {
    question: "Is my data safe while scanning?",
    answer:
      "Yes, our scanner does not store sensitive information from your application. It only tests for vulnerabilities and provides a report of potential security issues.",
  },
  {
    question: "Is the scanning process safe for my website?",
    answer:
      "Yes. The scanner is designed for testing purposes only and does not exploit or damage the target system. It performs non-destructive security checks to identify vulnerabilities safely.",
  },
  {
    question: "Does the system generate a vulnerability report?",
    answer:
      "Yes, after each scan, the system generates a detailed report highlighting detected vulnerabilities, their severity, and possible mitigation suggestions.",
  },
];

const FAQ = () => {
  // STATE: Track which FAQ item is currently open
  // null means no item is open
  // A number (0, 1, 2, etc.) means that item is open
  const [openIndex, setOpenIndex] = useState(null);

  // FUNCTION: Toggle an FAQ item open or closed
  // If you click an open item, it closes (becomes null)
  // If you click a closed item, it opens (becomes that index)
  function toggleFAQ(index) {
    if (openIndex === index) {
      // If this item is already open, close it
      setOpenIndex(null);
    } else {
      // Otherwise, open this item
      setOpenIndex(index);
    }
  }

  return (
    // SECTION CONTAINER: Dark background with padding
    <section className="bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 text-gray-100 py-20 ">
      <div className="flex flex-col md:flex-row md:gap-16  max-w-7xl mx-auto px-4 md:px-12">
        {/* LEFT SIDE: Heading and description */}
        <div className="md:w-1/3 mb-8 md:mb-0">
          <h2 className="text-3xl md:text-4xl font-bold mb-6">
            <span className="text-[#059669]">Frequently</span>
            <br></br>
            Asked Questions
          </h2>
          <p className="text-gray-300 text-lg mb-6">
            Have questions? We've got answers. Explore our frequently asked
            questions to quickly find the information you need.
          </p>
        </div>

        {/* RIGHT SIDE: FAQ Items */}
        <div className="md:w-2/3 space-y-4">
          {/* Loop through each FAQ item */}
          {faqData.map((faq, index) => {
            // Check if this item is currently open
            const isOpen = openIndex === index;

            return (
              <div
                key={index}
                className="bg-[#059669]/0! bg-linear-to-br from-[#059669]/40 to-[#059669]/10 rounded-xl shadow-lg overflow-hidden border border-[#059669]"
              >
                {/* QUESTION BUTTON: Click to toggle open/closed */}
                <button
                  onClick={() => toggleFAQ(index)}
                  className="w-full bg-[#059669]/0! text-left px-6 py-5 flex justify-between items-center"
                >
                  <span className="text-lg font-medium">{faq.question}</span>

                  {/* PLUS ICON: Rotates when open */}
                  <span
                    className={`text-2xl transform transition-transform duration-300 ${
                      isOpen
                        ? "rotate-45 text-[#059669]"
                        : "rotate-0 text-[#059669] text-"
                    }`}
                  >
                    <svg
                      xmlns="http://www.w3.org/2000/svg"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      strokeLinecap="round"
                      strokeLinejoin="round"
                      className="w-6 h-6"
                    >
                      <circle cx="12" cy="12" r="10" />
                      <line x1="12" y1="8" x2="12" y2="16" />
                      <line x1="8" y1="12" x2="16" y2="12" />
                    </svg>
                  </span>
                </button>

                {/* ANSWER SECTION: Expands when open, collapses when closed */}
                {/* ANSWER SECTION: Expands when open, scrollable if content is too tall */}
                <div
                  className={`px-6 transition-all duration-300 text-sm md:text-base overflow-hidden ${
                    isOpen
                      ? "max-h-96 py-4 overflow-y-auto scrollbar-thin scrollbar-thumb-[#059669]/50 scrollbar-track-gray-900"
                      : "max-h-0"
                  }`}
                >
                  <p className="text-gray-300 whitespace-pre-line">
                    {faq.answer}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </section>
  );
};

// Export the component
export default FAQ;
