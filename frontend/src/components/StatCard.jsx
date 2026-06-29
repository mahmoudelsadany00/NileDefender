export default function StatCard({ icon, value, label, color = 'teal' }) {
  return (
    <div className={`card stat-card ${color}`}>
      <div className="stat-icon">{icon}</div>
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
