import React from "react";
import { Bar } from "react-chartjs-2";
import {
  Chart as ChartJS,
  BarElement,
  CategoryScale,
  LinearScale,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(BarElement, CategoryScale, LinearScale, Tooltip, Legend);

const BarChart = () => {
  const data = {
    labels: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"],
    datasets: [
      {
        label: "High Vulnerability",
        data: [3, 6, 5, 8, 7, 9, 6],
        backgroundColor: "rgba(239, 68, 68, 0.85)",
        borderRadius: 6,
        borderSkipped: false,
      },
      {
        label: "Medium Vulnerability",
        data: [2, 4, 3, 5, 4, 6, 3],
        backgroundColor: "rgba(245, 158, 11, 0.85)",
        borderRadius: 6,
        borderSkipped: false,
      },
      {
        label: "Low Vulnerability",
        data: [1, 2, 1, 3, 2, 3, 1],
        backgroundColor: "rgba(16, 185, 129, 0.85)",
        borderRadius: 6,
        borderSkipped: false,
      },
    ],
  };

  const options = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: {
        display: true,
        position: "bottom",
        labels: {
          padding: 20,
          boxWidth: 12,
          boxHeight: 12,
          borderRadius: 4,
          useBorderRadius: true,
          color: "#94a3b8",
          font: { size: 12 },
        },
      },
      tooltip: {
        mode: "index",
        intersect: false,
        backgroundColor: "#1e293b",
        borderColor: "#334155",
        borderWidth: 1,
        titleColor: "#cbd5e1",
        bodyColor: "#94a3b8",
        padding: 10,
      },
    },
    layout: {
      padding: { top: 10, bottom: 10, left: 0, right: 0 },
    },
    scales: {
      y: {
        beginAtZero: true,
        grid: { color: "rgba(51, 65, 85, 0.5)" },
        ticks: { color: "#64748b", font: { size: 11 } },
        border: { display: false },
      },
      x: {
        grid: { display: false },
        ticks: { color: "#64748b", font: { size: 11 }, padding: 8 },
        border: { display: false },
      },
    },
  };

  return <Bar data={data} options={options} />;
};

export default BarChart;
