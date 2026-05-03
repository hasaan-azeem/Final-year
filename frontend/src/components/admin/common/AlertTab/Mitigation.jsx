import React from "react";
import { SquareCheckBig } from "lucide-react";

const Mitigation = () => {
  return (
    <div className="w-full bg-white dark:bg-gray-800 p-6 rounded-xl shadow mt-10">
      {/* Header */}
      <div className="mb-4 flex items-center gap-2">
        <SquareCheckBig className="text-[#1ABC9C]" />
        <h2 className="text-xl font-medium text-gray-900 dark:text-white">
          Suggested Mitigation Steps
        </h2>
      </div>

      {/* Content Card */}
      <div className="bg-white dark:bg-gray-900 text-black dark:text-gray-200 rounded-lg p-5 border border-gray-300 dark:border-gray-700 text-sm">
        <p className="font-semibold text-black dark:text-white mb-1">XSS Vulnerability</p>
        <p className="text-gray-400 mb-4">For shop.example.com :</p>

        <ol className="list-decimal pl-5 space-y-2">
          <li>
            Ensure all user supplied input is sanitized and validated on the
            server side.
          </li>
          <li>
            Implement output encoding for any data rendered on the page.
          </li>
          <li>
            Deploy a strict Content Security Policy (CSP) header.
          </li>
        </ol>
      </div>
    </div>
  );
};

export default Mitigation;
