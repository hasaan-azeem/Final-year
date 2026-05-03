import React from "react";

const RealAlerts = () => {
  const alerts = [
    { id: 1, message: "Server CPU usage is high", type: "warning" },
    { id: 2, message: "New user registered", type: "info" },
    { id: 3, message: "Payment failed for order #1234", type: "error" },
  ];

  const getAlertStyle = (type) => {
    switch (type) {
      case "error":
        return "border-l-6 border-red-600 bg-red-100 text-red-800";
      case "warning":
        return "border-l-6 border-yellow-500 bg-yellow-100 text-yellow-800";
      case "info":
      default:
        return "border-l-6 border-blue-500 bg-blue-100 text-blue-800";
    }
  };

  return (
    <div className="w-full bg-white dark:bg-gray-800 p-6 rounded-xl shadow mt-10">
      <div className="mb-4">
        <h2 className="text-xl font-medium text-gray-900 dark:text-white">Real-time Alerts</h2>
      </div>

      <div className="flex flex-col gap-3">
        {alerts.map((alert) => (
          <div
            key={alert.id}
            className={`p-3 ${getAlertStyle(alert.type)}`}
          >
            {alert.message}
          </div>
        ))}
      </div>
    </div>
  );
};

export default RealAlerts;
