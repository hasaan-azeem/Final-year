import React, { useEffect } from "react";
import { useLocation } from "react-router-dom";

const FeatureMain = () => {
  const location = useLocation();

  useEffect(() => {
    if (location.hash) {
      const id = location.hash.replace("#", "");
      const el = document.getElementById(id);

      if (el) {
        setTimeout(() => {
          el.scrollIntoView({ behavior: "smooth", block: "start" });
        }, 150);
      }
    }
  }, [location]);

  const features = [
    {
      id: "overview",
      title: "WebXGuard Overview",
      subtitle: "AI-Driven Web Security Platform",
      description:
        "WebXGuard is a modern, AI-powered web application security platform designed to protect organizations from evolving cyber threats. It combines automated vulnerability scanning, continuous monitoring, intelligent risk analysis, and compliance validation into a single unified system. By continuously analyzing web applications, WebXGuard helps organizations identify security weaknesses early, reduce attack surfaces, and maintain a strong security posture throughout the application lifecycle.",
      image: "/images/overview.svg",
    },
    {
      id: "website-scan",
      title: "Website Vulnerability Scanning",
      subtitle: "Automated & Intelligent Detection",
      description:
        "WebXGuard performs automated vulnerability scanning on target websites to identify common and critical security flaws. It detects vulnerabilities such as SQL Injection (SQLi), Cross-Site Scripting (XSS), open redirects, insecure HTTP headers, weak cookies, and SSL/TLS misconfigurations. The scanner is capable of crawling JavaScript-heavy applications using Playwright, ensuring deep visibility into modern single-page applications and dynamic content that traditional scanners often fail to analyze.",
      image: "images/scanning.svg",
    },
    {
      id: "continuous-monitoring",
      title: "Continuous Website Monitoring",
      subtitle: "Always-On Threat Detection",
      description:
        "WebXGuard provides continuous monitoring of registered websites to identify newly introduced vulnerabilities and configuration changes. It periodically checks SSL certificates, HTTP security headers, website content, endpoints, and URLs to detect suspicious or unauthorized changes. Any abnormal behavior or newly discovered weakness triggers alerts, enabling organizations to respond quickly before vulnerabilities can be exploited.",
      image: "images/monitoring (2).svg",
    },
    {
      id: "ai-risk-analysis",
      title: "AI-Based Risk Analysis",
      subtitle: "Smart Vulnerability Prioritization",
      description:
        "The AI-Based Risk Analysis Engine evaluates detected vulnerabilities and assigns intelligent severity scores. Instead of treating all vulnerabilities equally, WebXGuard prioritizes issues based on impact, exploitability, and likelihood of attack. This reduces false positives and helps security teams focus on the most critical risks first, significantly improving remediation efficiency and decision-making.",
      image: "images/analysis1.svg",
    },
    {
      id: "compliance-checker",
      title: "Website Compliance Checker",
      subtitle: "Security & Compliance Validation",
      description:
        "WebXGuard continuously assesses compliance against recognized standards such as OWASP Top 10 and basic PCI DSS requirements. It verifies HTTPS enforcement, secure cookie usage, Content Security Policy (CSP) implementation, and checks for server information leakage. Based on these assessments, WebXGuard generates an overall security grade that helps organizations understand their compliance readiness at a glance.",
      image: "images/check.svg",
    },
    {
      id: "cwe-integration",
      title: "CWE Integration",
      subtitle: "Industry-Standard Classification",
      description:
        "WebXGuard integrates with Common Weakness Enumeration (CWE) standards to classify vulnerabilities using globally accepted identifiers. Each detected issue is mapped to a CWE ID and includes CWSS severity scores, detailed vulnerability descriptions, and recommended mitigation steps. This ensures consistency, accuracy, and improved collaboration across security and development teams.",
      image: "images/cwe.png",
    },
    {
      id: "predictive-analytics",
      title: "Predictive Analytics",
      subtitle: "Proactive Security Intelligence",
      description:
        "Using historical scan data and observed vulnerability patterns, WebXGuard applies predictive analytics to forecast potential future security risks. By identifying vulnerability trends and recurring weaknesses, organizations can take preventive security measures, strengthen defenses in advance, and reduce the likelihood of future attacks before they occur.",
      image: "images/predictive-analysis.svg",
    },
    {
      id: "alerts-notifications",
      title: "Alerts & Notifications",
      subtitle: "Real-Time Security Awareness",
      description:
        "WebXGuard delivers real-time alerts for critical and high-risk vulnerabilities through multiple channels. Users receive email notifications for severe findings, while the dashboard provides instant, live updates using WebSocket-based notifications without page refresh. Alerts can be filtered based on severity, ensuring teams are informed quickly and accurately when immediate action is required.",
      image: "images/alerts.svg",
    },
    {
      title: "AI-Driven Mitigation Suggestions",
      subtitle: "Actionable Security Guidance",
      description:
        "Beyond detection, WebXGuard provides AI-driven recommendations to help users remediate vulnerabilities effectively. These suggestions include adding missing security headers, improving SSL/TLS configurations, fixing insecure cookies, and recommending relevant software updates. The platform offers guidance-only remediation, allowing development teams to apply fixes safely and responsibly without automated changes to production systems.",
      image: "images/mitigation.svg",
    },
    {
      id: "reporting-dashboard",
      title: "Reporting & Dashboard",
      subtitle: "Insights That Drive Decisions",
      description:
        "WebXGuard features an interactive dashboard that presents complex security data in a clear and visual format. It displays vulnerability summaries, AI-generated risk scores, compliance grades, monitoring status, and historical trends. Reports can be exported in PDF format, making them audit-friendly and suitable for compliance reviews, management reporting, and long-term security tracking.",
      image: "images/dashboard.svg",
    },
  ];

  return (
    <section className="relative w-full bg-linear-to-b from-gray-950 via-gray-900 to-gray-950 py-20">
      <div className="max-w-7xl mx-auto px-4 md:px-12">
        <div className="space-y-36">
          {features.map((feature, index) => (
            <div
              key={feature.id}
              id={feature.id}
              className={`flex flex-col ${
                index % 2 === 0 ? "lg:flex-row" : "lg:flex-row-reverse"
              } items-center gap-20 scroll-mt-32`}
            >
              <div className="lg:w-1/2 relative">
                <div className="absolute inset-0 bg-emerald-500/20 blur-3xl rounded-full"></div>
                <div className="relative backdrop-blur rounded-2xl p-8 shadow-xl">
                  <img
                    src={feature.image}
                    alt={feature.title}
                    className="w-full max-w-sm mx-auto object-contain"
                  />
                </div>
              </div>

              <div className="lg:w-1/2">
                <span className="text-emerald-400 text-sm font-medium">
                  {feature.subtitle}
                </span>
                <h2 className="mt-3 text-3xl md:text-4xl font-semibold text-gray-100">
                  {feature.title}
                </h2>
                <p className="mt-6 text-lg text-gray-300 leading-relaxed">
                  {feature.description}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeatureMain;
