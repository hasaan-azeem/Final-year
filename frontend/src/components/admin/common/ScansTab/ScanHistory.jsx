import React from "react";
import { Clock } from "lucide-react";

const ScanHistory = () => {
  const data = [
    {
      url: "example.com",
      date: "12/10/2025",
      grade: "C+",
      vulns: 3,
    },
    {
      url: "test-site.dev",
      date: "12/9/2025",
      grade: "A",
      vulns: 0,
    },
  ];

  const getGradeColor = (grade) => {
    if (grade.startsWith("A")) return "text-green-600";
    if (grade.startsWith("B")) return "text-blue-600";
    if (grade.startsWith("C")) return "text-yellow-600";
    return "text-red-600";
  };
  return (
    <div className="w-full bg-white dark:bg-gray-800 p-2 rounded-xl shadow">
      <div className="mb-6">
        <div className="flex items-center gap-2">
          <Clock className="text-[#1ABC9C]" />
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">Scan History</h1>
        </div>
        <p className="text-gray-600 dark:text-gray-400">
          Review results from previous security scans.
        </p>
      </div>
      <div>
        <table className="w-full border-collapse">
          <thead>
            <tr className="text-left border-b border-gray-300 dark:text-gray-200">
              <th className="py-3 px-2 font-semibold">URL</th>
              <th className="py-3 px-2 font-semibold">Date</th>
              <th className="py-3 px-2 font-semibold">Grade</th>
              <th className="py-3 px-2 font-semibold">Vulnerabilities</th>
            </tr>
          </thead>

          <tbody className="dark:text-gray-300">
            {data.map((item, index) => (
              <tr key={index} className="border-b border-gray-200">
                <td className="py-3 px-2">{item.url}</td>
                <td className="py-3 px-2">{item.date}</td>
                <td
                  className={`py-3 px-2 font-medium ${getGradeColor(
                    item.grade
                  )}`}
                >
                  {item.grade}
                </td>
                <td className="py-3 px-2">{item.vulns}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};

export default ScanHistory;
