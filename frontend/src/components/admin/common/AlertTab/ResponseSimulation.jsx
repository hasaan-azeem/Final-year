import React from "react";
import { Zap } from "lucide-react";

const ResponseSimulation = () => {
  return (
    <div className="w-full bg-white dark:bg-gray-900 text-black dark:text-gray-200 p-6 rounded-xl shadow mt-10">
      {/* Header */}
      <div className="flex items-center gap-2 mb-2">
        <Zap className="text-blue-400" size={20} />
        <h2 className="text-lg font-semibold text-gray-900 dark:text-white">
          Automated Response Simulation
        </h2>
      </div>

      {/* Description */}
      <p className="text-black dark:text-gray-400 text-sm mb-5">
        Safely simulate corrective actions to understand their impact before
        deploying to production.
      </p>

      {/* Inner Card */}
      <div className="border border-gray-200 rounded-lg p-4 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <p className="text-sm">
          Simulate adding{" "}
          <span className="text-black dark:text-white font-medium">
            'Content-Security-Policy'
          </span>{" "}
          header to{" "}
          <span className="text-blue-400">blog.example.com</span>.
        </p>

        <button className="bg-green-600 hover:bg-green-700 transition px-4 py-2 rounded-md text-sm font-medium text-white w-fit">
          Run Simulation
        </button>
      </div>
    </div>
  );
};

export default ResponseSimulation;
