import { useState, useEffect, useRef } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import {
  fetchScanDetails, fetchScanStats, fetchSubdomains, fetchEndpoints,
  fetchVulnerabilities, deleteScan as apiDeleteScan,
  exportScanData, generateAIReport,
} from '../services/api';
import StatCard from '../components/StatCard';
import Badge, { MethodBadge, SeverityBadge } from '../components/Badge';
import DeleteModal from '../components/DeleteModal';
import { useNotification } from '../components/Notification';

export default function ScanDetails({ socketEvents }) {
  const { id } = useParams();
  const scanId = parseInt(id);
  const navigate = useNavigate();
  const notify = useNotification();

  const [scan, setScan] = useState(null);
  const [stats, setStats] = useState({ total_subdomains: 0, get_endpoints: 0, post_endpoints: 0, vulnerability_count: 0 });
  const [subdomains, setSubdomains] = useState([]);
  const [endpoints, setEndpoints] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [activeTab, setActiveTab] = useState('subdomains');
  const [deleteModal, setDeleteModal] = useState(false);
  const [exportOpen, setExportOpen] = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const exportRef = useRef(null);

  const loadAll = async () => {
    try {
      const [details, st, subs, eps, vs] = await Promise.all([
        fetchScanDetails(scanId),
        fetchScanStats(scanId),
        fetchSubdomains(scanId),
        fetchEndpoints(scanId),
        fetchVulnerabilities(scanId),
      ]);
      setScan(details.scan);
      setStats(st);
      setSubdomains(subs);
      setEndpoints(eps);
      setVulns(vs);
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => { loadAll(); }, [scanId]);

  useEffect(() => {
    if (!socketEvents) return;
    socketEvents.joinScan(scanId);
    const unsub1 = socketEvents.onScanUpdate((data) => { if (data.scan_id === scanId) loadAll(); });
    const unsub2 = socketEvents.onScanCompleted((data) => { if (data.scan_id === scanId) loadAll(); });
    const unsub3 = socketEvents.onVulnscanCompleted((data) => { if (data.scan_id === scanId) loadAll(); });
    const unsub4 = socketEvents.onScanError((data) => { if (data.scan_id === scanId) loadAll(); });
    return () => { unsub1(); unsub2(); unsub3(); unsub4(); };
  }, [socketEvents, scanId]);

  // Close export dropdown on outside click
  useEffect(() => {
    const handler = (e) => { if (exportRef.current && !exportRef.current.contains(e.target)) setExportOpen(false); };
    document.addEventListener('click', handler);
    return () => document.removeEventListener('click', handler);
  }, []);

  const handleDelete = async () => {
    try {
      await apiDeleteScan(scanId);
      notify('Scan deleted!', 'success');
      navigate('/scans');
    } catch (err) { notify(err.message, 'error'); }
  };

  const handleExport = async (format, dataType) => {
    try {
      await exportScanData(scanId, format, dataType);
      setExportOpen(false);
    } catch (err) { notify(err.message, 'error'); }
  };

  const handleReport = async () => {
    setReportLoading(true);
    try {
      await generateAIReport(scanId);
      notify('Report downloaded!', 'success');
    } catch (err) { notify(err.message, 'error'); }
    setReportLoading(false);
  };

  const getEndpoints = endpoints.filter((e) => e.method === 'GET');
  const postEndpoints = endpoints.filter((e) => e.method === 'POST');

  const tabs = [
    { id: 'subdomains', label: 'Subdomains' },
    { id: 'get-endpoints', label: 'GET Endpoints' },
    { id: 'post-endpoints', label: 'POST Endpoints' },
    { id: 'vulnerabilities', label: 'Vulnerabilities' },
  ];

  if (!scan) return <div className="loading"><div className="spinner" /> Loading scan details...</div>;

  return (
    <div>
      <button className="back-link" onClick={() => navigate('/scans')}>← Back to Scans</button>

      {/* Header */}
      <div className="detail-header">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 16 }}>
          <div>
            <div className="domain">{scan.domain}</div>
            <div className="meta">
              <span>Scan ID: <strong>{scan.id}</strong></span>
              <span>Date: <strong>{scan.scan_date ? new Date(scan.scan_date).toLocaleString() : 'N/A'}</strong></span>
            </div>
          </div>
          <div className="detail-actions">
            <Badge status={scan.status} />

            {/* AI Report */}
            <button className="btn-generate-report" onClick={handleReport} disabled={reportLoading} title="Generate AI-powered security report">
              <span>📄</span>
              <span>{reportLoading ? 'Generating...' : 'Generate Report'}</span>
              <span className="ai-badge">🤖 AI</span>
            </button>

            {/* Export */}
            <div className="export-dropdown" ref={exportRef}>
              <button className="btn btn-secondary" onClick={() => setExportOpen(!exportOpen)} style={{ padding: '9px 14px' }}>
                <span>📤</span> Export <span style={{ fontSize: 10 }}>▾</span>
              </button>
              <div className={`export-menu ${exportOpen ? 'show' : ''}`}>
                <div className="export-menu-section">All Data</div>
                <button onClick={() => handleExport('json', 'all')}>📋 Export All (JSON)</button>
                <button onClick={() => handleExport('csv', 'all')}>📊 Export All (CSV)</button>
                <div className="export-menu-divider" />
                <div className="export-menu-section">Subdomains</div>
                <button onClick={() => handleExport('json', 'subdomains')}>📋 Subdomains (JSON)</button>
                <button onClick={() => handleExport('csv', 'subdomains')}>📊 Subdomains (CSV)</button>
                <div className="export-menu-divider" />
                <div className="export-menu-section">Endpoints</div>
                <button onClick={() => handleExport('json', 'endpoints')}>📋 Endpoints (JSON)</button>
                <button onClick={() => handleExport('csv', 'endpoints')}>📊 Endpoints (CSV)</button>
                <div className="export-menu-divider" />
                <div className="export-menu-section">Vulnerabilities</div>
                <button onClick={() => handleExport('json', 'vulnerabilities')}>📋 Vulnerabilities (JSON)</button>
                <button onClick={() => handleExport('csv', 'vulnerabilities')}>📊 Vulnerabilities (CSV)</button>
              </div>
            </div>

            <button className="btn-icon danger" onClick={() => setDeleteModal(true)} title="Delete scan">🗑️</button>
          </div>
        </div>
      </div>

      {/* Stats */}
      <div className="stats-grid">
        <StatCard icon="🌐" value={stats.total_subdomains} label="Subdomains (Alive)" color="green" />
        <StatCard icon="🔗" value={stats.get_endpoints} label="GET Endpoints" color="orange" />
        <StatCard icon="📝" value={stats.post_endpoints} label="POST Endpoints" color="red" />
        <StatCard icon="⚠️" value={stats.vulnerability_count} label="Vulnerabilities" color="purple" />
      </div>

      {/* Tabs */}
      <div className="tabs">
        {tabs.map((t) => (
          <button key={t.id} className={`tab ${activeTab === t.id ? 'active' : ''}`} onClick={() => setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="card card-body">
        {activeTab === 'subdomains' && (
          <div className="table-container">
            <table>
              <thead><tr><th>Subdomain</th><th>HTTP Code</th><th>Title</th></tr></thead>
              <tbody>
                {subdomains.length === 0 ? (
                  <tr><td colSpan={3}><div className="empty-state"><div className="empty-icon">🌐</div><h4>No subdomains found</h4></div></td></tr>
                ) : subdomains.map((s, i) => (
                  <tr key={i}>
                    <td style={{ fontWeight: 500 }}>{s.subdomain}</td>
                    <td>{s.status_code || '-'}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }}>{s.title || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'get-endpoints' && (
          <div className="table-container">
            <table>
              <thead><tr><th>Method</th><th>URL</th><th>Parameters</th><th>Source</th></tr></thead>
              <tbody>
                {getEndpoints.length === 0 ? (
                  <tr><td colSpan={4}><div className="empty-state"><div className="empty-icon">🔗</div><h4>No GET endpoints</h4></div></td></tr>
                ) : getEndpoints.map((e, i) => (
                  <tr key={i}>
                    <td><MethodBadge method="GET" /></td>
                    <td className="url-cell">{e.url}</td>
                    <td className="params-cell">{e.parameters ? Object.keys(e.parameters).join(', ') : '-'}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{e.source || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'post-endpoints' && (
          <div className="table-container">
            <table>
              <thead><tr><th>Method</th><th>URL</th><th>Body Parameters</th><th>Source</th></tr></thead>
              <tbody>
                {postEndpoints.length === 0 ? (
                  <tr><td colSpan={4}><div className="empty-state"><div className="empty-icon">📝</div><h4>No POST endpoints</h4></div></td></tr>
                ) : postEndpoints.map((e, i) => (
                  <tr key={i}>
                    <td><MethodBadge method="POST" /></td>
                    <td className="url-cell">{e.url}</td>
                    <td className="params-cell">{e.body_params ? Object.keys(e.body_params).join(', ') : '-'}</td>
                    <td style={{ color: 'var(--text-muted)', fontSize: 12 }}>{e.source || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <div>
            {vulns.length === 0 ? (
              <div className="empty-state">
                <div className="empty-icon">🔒</div>
                <h4>No Vulnerability Data</h4>
                <p>Run a vulnerability scan from "New Scan" to discover security issues</p>
              </div>
            ) : (
              <div className="table-container">
                <table>
                  <thead><tr><th>Type</th><th>Severity</th><th>URL</th><th>Method</th><th>Parameter</th><th>Payload</th></tr></thead>
                  <tbody>
                    {vulns.map((v, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 500 }}>{v.type}</td>
                        <td><SeverityBadge severity={v.severity} /></td>
                        <td className="url-cell">{v.url}</td>
                        <td>{v.method || '-'}</td>
                        <td className="params-cell">{v.parameter || '-'}</td>
                        <td className="params-cell" style={{ maxWidth: 200 }}>{v.payload || '-'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}
      </div>

      <DeleteModal show={deleteModal} domain={scan.domain} onClose={() => setDeleteModal(false)} onConfirm={handleDelete} />
    </div>
  );
}
