import { useState, useEffect } from 'react';
import { fetchScans, fetchVulnerabilities } from '../services/api';
import { exportAggregatedData } from '../services/api';
import { SeverityBadge } from '../components/Badge';

export default function Vulnerabilities() {
  const [allVulns, setAllVulns] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [search, setSearch] = useState('');
  const [sevFilter, setSevFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [counts, setCounts] = useState({});
  const [exportOpen, setExportOpen] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const scans = await fetchScans();
        const all = [];
        for (const scan of scans) {
          const vs = await fetchVulnerabilities(scan.id);
          vs.forEach((v) => all.push({ ...v, target: scan.domain }));
        }
        setAllVulns(all);
        setFiltered(all);

        const c = {};
        all.forEach((v) => {
          const s = (v.severity || 'info').toLowerCase();
          c[s] = (c[s] || 0) + 1;
        });
        setCounts(c);
      } catch (err) { console.error(err); }
      setLoading(false);
    })();
  }, []);

  useEffect(() => {
    let result = allVulns;
    if (sevFilter !== 'all') result = result.filter((v) => (v.severity || '').toLowerCase() === sevFilter.toLowerCase());
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter((v) =>
        v.url?.toLowerCase().includes(q) ||
        v.type?.toLowerCase().includes(q) ||
        v.parameter?.toLowerCase().includes(q) ||
        v.target?.toLowerCase().includes(q)
      );
    }
    setFiltered(result);
  }, [search, sevFilter, allVulns]);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = () => setExportOpen(false);
    if (exportOpen) document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, [exportOpen]);

  const pills = ['all', 'Critical', 'High', 'Medium', 'Low'];

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>All Vulnerabilities</h2>
          <p>Security vulnerabilities found across all scans</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {Object.entries(counts).map(([sev, count]) => (
            <span key={sev} className={`badge severity-${sev}`}>{count} {sev}</span>
          ))}
          <div className="export-dropdown" onClick={(e) => e.stopPropagation()}>
            <button className="btn btn-secondary" onClick={() => setExportOpen(!exportOpen)} disabled={allVulns.length === 0}>
              <span>📤</span> Export <span style={{ fontSize: 10 }}>▾</span>
            </button>
            <div className={`export-menu ${exportOpen ? 'show' : ''}`}>
              <div className="export-menu-section">Export Vulnerabilities</div>
              <button onClick={() => { exportAggregatedData(filtered, 'vulnerabilities', 'json'); setExportOpen(false); }}>📋 Export as JSON</button>
              <button onClick={() => { exportAggregatedData(filtered, 'vulnerabilities', 'csv'); setExportOpen(false); }}>📊 Export as CSV</button>
            </div>
          </div>
        </div>
      </div>

      <div className="card card-body">
        <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
          <input
            type="text"
            className="search-input"
            placeholder="🔍  Search vulnerabilities..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ flex: 1, minWidth: 200 }}
          />
          <div className="filter-pills" style={{ marginBottom: 0 }}>
            {pills.map((p) => (
              <button key={p} className={`filter-pill ${sevFilter === p ? 'active' : ''}`} onClick={() => setSevFilter(p)}>
                {p === 'all' ? 'All' : p}
              </button>
            ))}
          </div>
        </div>

        <div className="table-container">
          <table>
            <thead><tr><th>Type</th><th>Severity</th><th>URL</th><th>Method</th><th>Parameter</th><th>Target</th><th>Payload</th></tr></thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={7} className="loading"><div className="spinner" /> Loading...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={7}><div className="empty-state"><div className="empty-icon">🔒</div><h4>No vulnerabilities found</h4></div></td></tr>
              ) : filtered.map((v, i) => (
                <tr key={i}>
                  <td style={{ fontWeight: 500 }}>{v.type}</td>
                  <td><SeverityBadge severity={v.severity} /></td>
                  <td className="url-cell">{v.url}</td>
                  <td>{v.method || '-'}</td>
                  <td className="params-cell">{v.parameter || '-'}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{v.target}</td>
                  <td className="params-cell" style={{ maxWidth: 180 }}>{v.payload || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
