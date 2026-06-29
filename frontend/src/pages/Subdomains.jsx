import { useState, useEffect } from 'react';
import { fetchScans, fetchSubdomains } from '../services/api';
import { exportAggregatedData } from '../services/api';

export default function Subdomains() {
  const [allSubdomains, setAllSubdomains] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [search, setSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [exportOpen, setExportOpen] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const scans = await fetchScans();
        const all = [];
        for (const scan of scans) {
          const subs = await fetchSubdomains(scan.id);
          subs.forEach((s) => all.push({ ...s, target: scan.domain }));
        }
        setAllSubdomains(all);
        setFiltered(all);
      } catch (err) { console.error(err); }
      setLoading(false);
    })();
  }, []);

  useEffect(() => {
    if (!search.trim()) { setFiltered(allSubdomains); return; }
    const q = search.toLowerCase();
    setFiltered(allSubdomains.filter((s) =>
      s.subdomain?.toLowerCase().includes(q) || s.target?.toLowerCase().includes(q)
    ));
  }, [search, allSubdomains]);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = () => setExportOpen(false);
    if (exportOpen) document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, [exportOpen]);

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>All Subdomains</h2>
          <p>Subdomains discovered across all scans</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="badge badge-completed">{allSubdomains.length} total</span>
          <div className="export-dropdown" onClick={(e) => e.stopPropagation()}>
            <button className="btn btn-secondary" onClick={() => setExportOpen(!exportOpen)} disabled={allSubdomains.length === 0}>
              <span>📤</span> Export <span style={{ fontSize: 10 }}>▾</span>
            </button>
            <div className={`export-menu ${exportOpen ? 'show' : ''}`}>
              <div className="export-menu-section">Export Subdomains</div>
              <button onClick={() => { exportAggregatedData(filtered, 'subdomains', 'json'); setExportOpen(false); }}>📋 Export as JSON</button>
              <button onClick={() => { exportAggregatedData(filtered, 'subdomains', 'csv'); setExportOpen(false); }}>📊 Export as CSV</button>
            </div>
          </div>
        </div>
      </div>

      <div className="card card-body">
        <div style={{ marginBottom: 16 }}>
          <input
            type="text"
            className="search-input"
            placeholder="🔍  Search subdomains..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="table-container">
          <table>
            <thead><tr><th>Subdomain</th><th>Target</th><th>HTTP Code</th><th>Title</th></tr></thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={4} className="loading"><div className="spinner" /> Loading...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={4}><div className="empty-state"><div className="empty-icon">🌐</div><h4>No subdomains found</h4></div></td></tr>
              ) : filtered.map((s, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 500 }}>{s.subdomain}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{s.target}</td>
                  <td>{s.status_code || '-'}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.title || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
