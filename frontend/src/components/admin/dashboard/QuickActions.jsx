import { useNavigate } from "react-router-dom";

export default function QuickActions() {
  const navigate = useNavigate();

  return (
    <div className="space-y-2">
      <button
        onClick={() => navigate("/dashboard/scanner")}
        className="w-full bg-slate-800 p-2 rounded"
      >
        New Scan
      </button>

      <button
        onClick={() => navigate("/dashboard/vulnerability")}
        className="w-full bg-slate-800 p-2 rounded"
      >
        View Scans
      </button>
    </div>
  );
}