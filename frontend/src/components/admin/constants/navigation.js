import {
  ChartNoAxesColumn,
  Shield,
  AlertCircle,
  Activity,
  FileText,
  Settings,
  HelpCircle,
  TriangleAlert,
} from "lucide-react";

export const NAV_ITEMS = [
  {
    name: "Dashboard",
    path: "/dashboard",
    icon: ChartNoAxesColumn,
  },
  {
    name: "Websites",
    path: "/dashboard/websites",
    icon: Shield,
  },
  {
    name: "Continuous Monitoring",
    path: "/dashboard/continuousmonitoring",
    icon: Activity,
  },
  {
    name: "Alerts",
    path: "/dashboard/alerts",
    icon: TriangleAlert,
  },
  {
    name: "Vulnerabilities",
    path: "/dashboard/vulnerabilities",
    icon: AlertCircle,
  },
  {
    name: "Reports",
    path: "/dashboard/reports",
    icon: FileText,
  },
  {
    name: "Settings",
    path: "/dashboard/settings",
    icon: Settings,
  },
  {
    name: "Help & Support",
    path: "/dashboard/HelpSupport",
    icon: HelpCircle,
  },
];
