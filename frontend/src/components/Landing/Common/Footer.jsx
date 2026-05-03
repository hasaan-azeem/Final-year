import React from "react";
import { Link } from "react-router-dom";

const Footer = () => {
  // FOOTER COLUMNS DATA: Organized list of links for different sections
  // Each column has a title and an array of links
  const footerColumns = [
    {
      title: "PRODUCT",
      links: [
        { name: "WebXGuard Overview", url: "/overview" },
        { name: "AI Vulnerability Scanner", url: "/scanner" },
        { name: "Continuous Monitoring", url: "/monitoring" },
        { name: "Reporting Dashboard", url: "/dashboard" },
        { name: "Compliance Checker", url: "/compliance" },
      ],
    },
    {
      title: "CAPABILITIES",
      links: [
        { name: "Website Scan", url: "/features#website-scan" },
        { name: "AI Risk Analysis", url: "/features#ai-risk-analysis" },
        { name: "Predictive Analytics", url: "/features#predictive-analytics" },
        { name: "CWE Integration", url: "/features#cwe-integration" },
        {
          name: "Alerts & Notifications",
          url: "/features#alerts-notifications",
        },
      ],
    },
    {
      title: "COMPLIANCE",
      links: [
        { name: "OWASP TOP 10", url: "/features#website-scan" },
        { name: "ISO 27001", url: "/features#ai-risk-analysis" },
        { name: "PCI DSS", url: "/features#predictive-analytics" },
        { name: "HIPAA", url: "/features#cwe-integration" },
        { name: "GDPR", url: "/features#alerts-notifications" },
      ],
    },
    {
      title: "WEB SECURITY",
      links: [
        { name: "Cross-site Scripting", url: "/features#website-scan" },
        { name: "SQL Injection", url: "/features#ai-risk-analysis" },
        { name: "Reflected XSS", url: "/features#predictive-analytics" },
        { name: "CSRF Attacks", url: "/features#cwe-integration" },
        { name: "Directory Traversal", url: "/features#alerts-notifications" },
      ],
    },
    {
      title: "COMPANY/LEGAL",
      links: [
        { name: "About Us", url: "/aboutus" },
        { name: "Contact Us", url: "/contact" },
        { name: "Privacy Policy", url: "/privacy-policy" },
        { name: "Terms of Service", url: "/support/terms" },
      ],
    },
  ];

  // BOTTOM LINKS: Quick links shown at the very bottom
  const bottomLinks = [
    { name: "Login", url: "/auth/dashboard/login" },
    { name: "Privacy Policy", url: "/privacy-policy" },
    { name: "Terms of Use", url: "/terms" },
  ];

  // SOCIAL MEDIA LINKS: Icons and URLs for social platforms
  const socialLinks = [
    {
      name: "LinkedIn",
      url: "https://www.linkedin.com",
      // SVG icon for LinkedIn
      icon: (
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="currentColor"
          viewBox="0 0 24 24"
          className="w-5 h-5"
        >
          <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.762 2.239 5 5 5h14c2.762 0 5-2.238 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-10h3v10zm-1.5-11.27c-.966 0-1.75-.788-1.75-1.75s.784-1.75 1.75-1.75c.964 0 1.75.788 1.75 1.75s-.786 1.75-1.75 1.75zm13.5 11.27h-3v-5.5c0-1.379-1.121-2.5-2.5-2.5s-2.5 1.121-2.5 2.5v5.5h-3v-10h3v1.285c.69-.957 1.863-1.785 3.5-1.785 2.485 0 4.5 2.015 4.5 4.5v6z" />
        </svg>
      ),
    },
    {
      name: "X",
      url: "https://www.twitter.com",
      // SVG icon for X (Twitter)
      icon: (
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="currentColor"
          viewBox="0 0 24 24"
          className="w-5 h-5"
        >
          <path d="M24 4.557c-.883.392-1.832.656-2.828.775 1.017-.609 1.798-1.574 2.165-2.724-.951.564-2.005.974-3.127 1.195-.897-.957-2.178-1.555-3.594-1.555-2.722 0-4.928 2.206-4.928 4.928 0 .386.043.762.127 1.124-4.094-.205-7.725-2.168-10.157-5.146-.424.728-.667 1.574-.667 2.476 0 1.708.869 3.216 2.188 4.101-.807-.026-1.566-.247-2.228-.616v.062c0 2.385 1.697 4.374 3.946 4.827-.413.111-.849.171-1.296.171-.317 0-.626-.031-.928-.088.627 1.956 2.445 3.377 4.6 3.416-1.684 1.32-3.808 2.107-6.115 2.107-.398 0-.791-.023-1.178-.069 2.179 1.397 4.768 2.211 7.557 2.211 9.054 0 14-7.496 14-13.986 0-.21 0-.423-.015-.634.962-.694 1.797-1.562 2.457-2.549z" />
        </svg>
      ),
    },
    {
      name: "Facebook",
      url: "https://www.facebook.com",
      // SVG icon for Facebook
      icon: (
        <svg
          xmlns="http://www.w3.org/2000/svg"
          fill="currentColor"
          viewBox="0 0 24 24"
          className="w-5 h-5"
        >
          <path d="M22.676 0h-21.352c-.733 0-1.324.59-1.324 1.324v21.352c0 .733.591 1.324 1.324 1.324h11.495v-9.294h-3.129v-3.622h3.129v-2.671c0-3.1 1.893-4.788 4.659-4.788 1.325 0 2.464.099 2.797.143v3.24l-1.918.001c-1.504 0-1.795.715-1.795 1.763v2.311h3.587l-.467 3.622h-3.12v9.294h6.116c.733 0 1.324-.591 1.324-1.324v-21.352c0-.734-.591-1.324-1.324-1.324z" />
        </svg>
      ),
    },
  ];

  return (
    <footer className="bg-gray-900 text-gray-100 pt-12">
      {/* MAIN FOOTER COLUMNS SECTION */}
      <div className="max-w-7xl mx-auto px-4 sm:px-12 grid grid-cols-2 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-5 gap-8 pb-8">
        {/* Loop through each column */}
        {footerColumns.map((column, columnIndex) => (
          <div key={columnIndex}>
            {/* Column title */}
            <h4 className="font-bold mb-4">{column.title}</h4>

            {/* Column links */}
            <ul className="space-y-2 text-sm">
              {/* Loop through each link in this column */}
              {column.links.map((link, linkIndex) => (
                <li key={linkIndex}>
                  <Link
                    to={link.url}
                    className="transition-colors duration-300 text-gray-100 hover:text-[#059669]"
                  >
                    {link.name}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>

      {/* BOTTOM SECTION: Links and Social Icons */}
      <div className="border-t border-gray-700 pt-6 pb-4 max-w-7xl mx-auto px-8 flex flex-col md:flex-row justify-between items-center text-sm text-gray-600">
        {/* Bottom links (Login, Privacy, Terms) */}
        <div className="flex flex-wrap gap-4 mb-4 md:mb-0">
          {bottomLinks.map((link, index) => (
            <a
              key={index}
              href={link.url}
              className="transition-colors duration-300 text-gray-100 hover:text-[#059669]"
            >
              {link.name}
            </a>
          ))}
        </div>

        {/* Social media icons */}
        <div className="flex space-x-4 text-gray-100 text-lg">
          {socialLinks.map((social, index) => (
            <a
              key={index}
              href={social.url}
              target="_blank"
              rel="noopener noreferrer"
              className="transition-colors duration-300 text-gray-100 hover:text-[#059669]"
            >
              {social.icon}
            </a>
          ))}
        </div>
      </div>

      {/* COPYRIGHT SECTION */}
      <div className="text-center text-gray-300 text-sm py-4">
        © WebXGuard 2025, By Technologants
      </div>
    </footer>
  );
};

// Export the component
export default Footer;
