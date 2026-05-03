import React from "react";
import { Globe, Search } from "lucide-react";

const SearchBar = () => {
  return (
    <>
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-900 dark:text-white">New Website Scan</h1>
        <p className="text-gray-600 dark:text-gray-400">
          Enter a URL to perform a comprehensive, non-destructive security scan.
        </p>
      </div>
      <div className="w-full bg-white dark:bg-gray-800 p-6 rounded-xl shadow">
        <div className="flex flex-col md:flex-row items-center gap-4">
          {/* Input box */}
          <div className="flex items-center w-full bg-gray-100 border border-gray-300 rounded-lg px-4 py-3">
            <Globe size={18} className="text-gray-500 mr-3" />
            <input
              type="text"
              placeholder="Enter website URL (eg, example.com)"
              className="w-full bg-transparent outline-none text-gray-700"
            />
          </div>

          {/* Button */}
          <button className="flex items-center justify-center gap-2 bg-[#1ABC9C] text-white px-4 py-3 rounded-lg hover:bg-[#1EC8A0] transition">
            <Search size={20} />
            <span className="text-sm font-medium">Scan Website</span>
          </button>
        </div>
      </div>
    </>
  );
};

export default SearchBar;
