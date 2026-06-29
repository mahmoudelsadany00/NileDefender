import { useState, useEffect } from 'react';
import { fetchScans, fetchEndpoints } from '../services/api';
import { exportAggregatedData } from '../services/api';
import { MethodBadge } from '../components/Badge';

export default function Endpoints() {
  const [allEndpoints, setAllEndpoints] = useState([]);
  const [filtered, setFiltered] = useState([]);
  const [search, setSearch] = useState('');
  const [methodFilter, setMethodFilter] = useState('all');
  const [loading, setLoading] = useState(true);
  const [counts, setCounts] = useState({ get: 0, post: 0, total: 0 });
  const [exportOpen, setExportOpen] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const scans = await fetchScans();
        const all = [];
        for (const scan of scans) {
          const eps = await fetchEndpoints(scan.id);
          eps.forEach((e) => all.push({ ...e, target: scan.domain }));
        }
        setAllEndpoints(all);
        setFiltered(all);
        setCounts({
          get: all.filter((e) => e.method === 'GET').length,
          post: all.filter((e) => e.method === 'POST').length,
          total: all.length,
        });
      } catch (err) { console.error(err); }
      setLoading(false);
    })();
  }, []);

  useEffect(() => {
    let result = allEndpoints;
    if (methodFilter === 'GET') result = result.filter((e) => e.method === 'GET');
    else if (methodFilter === 'POST') result = result.filter((e) => e.method === 'POST');
    else if (methodFilter === 'params') result = result.filter((e) => e.parameters || e.body_params);

    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter((e) => e.url?.toLowerCase().includes(q) || e.target?.toLowerCase().includes(q));
    }
    setFiltered(result);
  }, [search, methodFilter, allEndpoints]);

  // Close dropdown on outside click
  useEffect(() => {
    const handler = () => setExportOpen(false);
    if (exportOpen) document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, [exportOpen]);

  const pills = [
    { id: 'all', label: 'All' },
    { id: 'GET', label: 'GET' },
    { id: 'POST', label: 'POST' },
    { id: 'params', label: 'With Params' },
  ];

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>All Endpoints</h2>
          <p>Endpoints discovered across all scans</p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span className="badge badge-get">{counts.get} GET</span>
          <span className="badge badge-post">{counts.post} POST</span>
          <span className="badge badge-completed">{counts.total} total</span>
          <div className="export-dropdown" onClick={(e) => e.stopPropagation()}>
            <button className="btn btn-secondary" onClick={() => setExportOpen(!exportOpen)} disabled={allEndpoints.length === 0}>
              <span>📤</span> Export <span style={{ fontSize: 10 }}>▾</span>
            </button>
            <div className={`export-menu ${exportOpen ? 'show' : ''}`}>
              <div className="export-menu-section">Export Endpoints</div>
              <button onClick={() => { exportAggregatedData(filtered, 'endpoints', 'json'); setExportOpen(false); }}>📋 Export as JSON</button>
              <button onClick={() => { exportAggregatedData(filtered, 'endpoints', 'csv'); setExportOpen(false); }}>📊 Export as CSV</button>
            </div>
          </div>
        </div>
      </div>

      <div className="card card-body">
        <div style={{ display: 'flex', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
          <input
            type="text"
            className="search-input"
            placeholder="🔍  Search endpoints..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{ flex: 1, minWidth: 200 }}
          />
          <div className="filter-pills" style={{ marginBottom: 0 }}>
            {pills.map((p) => (
              <button key={p.id} className={`filter-pill ${methodFilter === p.id ? 'active' : ''}`} onClick={() => setMethodFilter(p.id)}>
                {p.label}
              </button>
            ))}
          </div>
        </div>

        <div className="table-container">
          <table>
            <thead><tr><th>Method</th><th>URL</th><th>Parameters</th><th>Target</th><th>Source</th></tr></thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={5} className="loading"><div className="spinner" /> Loading...</td></tr>
              ) : filtered.length === 0 ? (
                <tr><td colSpan={5}><div className="empty-state"><div className="empty-icon">🔗</div><h4>No endpoints found</h4></div></td></tr>
              ) : filtered.map((e, i) => (
                <tr key={i}>
                  <td><MethodBadge method={e.method} /></td>
                  <td className="url-cell">{e.url}</td>
                  <td className="params-cell">
                    {e.method === 'GET'
                      ? (e.parameters ? Object.keys(e.parameters).join(', ') : '-')
                      : (e.body_params ? Object.keys(e.body_params).join(', ') : '-')}
                  </td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{e.target}</td>
                  <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{e.source || '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
