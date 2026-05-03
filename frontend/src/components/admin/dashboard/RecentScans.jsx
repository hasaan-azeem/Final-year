import { useNavigate } from "react-router-dom";

export default function RecentScans({ data }) {
  const navigate = useNavigate();

  return (
    <table className="w-full text-sm">
      <thead>
        <tr className="text-slate-500">
          <th>Website</th>
          <th>Status</th>
          <th>Score</th>
          <th>View</th>
        </tr>
      </thead>
      <tbody>
        {data.map((r) => (
          <tr
            key={r.session_id}
            className="hover:bg-slate-800 cursor-pointer"
            onClick={() =>
              navigate(`/dashboard/vulnerability/${r.session_id}`)
            }
          >
            <td>{r.domain}</td>
            <td>{r.status}</td>
            <td>{r.score}</td>
            <td>→</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}