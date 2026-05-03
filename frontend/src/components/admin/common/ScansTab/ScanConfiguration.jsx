import React from 'react'
import { Settings2 } from "lucide-react";

const ScanConfiguration = () => {
  return (
     <div className="w-full bg-white dark:bg-gray-800 p-6 rounded-xl shadow">
      <div className="mb-6">
        <div className="flex items-center gap-2">
          <Settings2  className="text-[#1ABC9C]" />
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Scan Configuration</h1>
        </div>
        <p className="text-gray-600 dark:text-gray-400">
          Customize the depth and type of your security scans.
        </p>
      </div>
    </div>
  )
}

export default ScanConfiguration