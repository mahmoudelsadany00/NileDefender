export default function Badge({ status, className = '' }) {
  const statusClass = `badge badge-${status?.toLowerCase() || 'info'}`;
  return <span className={`${statusClass} ${className}`}>{status}</span>;
}

export function SeverityBadge({ severity }) {
  const sev = (severity || 'info').toLowerCase();
  return <span className={`badge severity-${sev}`}>{severity}</span>;
}

export function MethodBadge({ method }) {
  const m = (method || 'GET').toLowerCase();
  return <span className={`badge badge-${m}`}>{method}</span>;
}
