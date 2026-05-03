import React, { useState } from "react";
import SearchBar from "../SearchBar";
import ScanHistory from "./ScanHistory";
import ScanConfiguration from "./ScanConfiguration";

const ScanTabs = () => {
  const tabs = ["New Scan", "Scan History", "Scan Configuration"];
  const [activeTab, setActiveTab] = useState(tabs[0]);

  return (
    <div className="mt-2 p-2 ">
      {/* Tabs Header */}
      <div className="border-b border-gray-300 dark:border-gray-600 flex space-x-6">
        {tabs.map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`pb-2 font-medium text-gray-800 dark:text-gray-200 ${
              activeTab === tab
                ? "border-b-2 border-[#1ABC9C] text-[#1EC8A0]"
                : "hover:text-[#1ABC9C] transition-colors"
            }`}
          >
            {tab}
          </button>
        ))}
      </div>

      {/* Tabs Content */}
      <div className="mt-4">
        {activeTab === "New Scan" && <SearchBar />}
        {activeTab === "Scan History" && <ScanHistory />}
        {activeTab === "Scan Configuration" && <ScanConfiguration />}
      </div>
    </div>
  );
};

export default ScanTabs;
