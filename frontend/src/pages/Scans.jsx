import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchScans, deleteScan as apiDeleteScan, deleteAllScans as apiDeleteAll } from '../services/api';
import Badge from '../components/Badge';
import NewScanModal from '../components/NewScanModal';
import DeleteModal from '../components/DeleteModal';
import { useNotification } from '../components/Notification';

export default function Scans({ socketEvents }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [deleteModal, setDeleteModal] = useState({ show: false, id: null, domain: '' });
  const [deleteAllModal, setDeleteAllModal] = useState(false);
  const navigate = useNavigate();
  const notify = useNotification();

  const loadScans = async () => {
    try {
      const data = await fetchScans();
      setScans(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { loadScans(); }, []);

  useEffect(() => {
    if (!socketEvents) return;
    const unsub1 = socketEvents.onScanCompleted(() => loadScans());
    const unsub2 = socketEvents.onVulnscanCompleted(() => loadScans());
    return () => { unsub1(); unsub2(); };
  }, [socketEvents]);

  const handleDelete = async () => {
    try {
      await apiDeleteScan(deleteModal.id);
      setDeleteModal({ show: false, id: null, domain: '' });
      notify('Scan deleted!', 'success');
      loadScans();
    } catch (err) { notify(err.message, 'error'); }
  };

  const handleDeleteAll = async () => {
    try {
      await apiDeleteAll();
      setDeleteAllModal(false);
      notify('All scans deleted!', 'success');
      loadScans();
    } catch (err) { notify(err.message, 'error'); }
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>Scans</h2>
          <p>Manage your security reconnaissance scans</p>
        </div>
        <div className="page-header-actions">
          <button className="btn btn-danger-outline" onClick={() => setDeleteAllModal(true)}>
            <span>🗑️</span> Delete All
          </button>
          <button className="btn btn-primary" onClick={() => setShowModal(true)}>
            <span>+</span> New Scan
          </button>
        </div>
      </div>

      {loading ? (
        <div className="loading"><div className="spinner" /> Loading scans...</div>
      ) : scans.length === 0 ? (
        <div className="empty-state" style={{ gridColumn: '1 / -1' }}>
          <div className="empty-icon">🔍</div>
          <h4>No scans found</h4>
          <p>Start a new scan to begin reconnaissance</p>
        </div>
      ) : (
        <div className="scans-grid">
          {scans.map((scan) => (
            <div key={scan.id} className="card scan-card" onClick={() => navigate(`/scans/${scan.id}`)}>
              <div className="scan-card-header">
                <h3>{scan.domain}</h3>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <Badge status={scan.status} />
                  <button className="btn-icon danger" onClick={(e) => { e.stopPropagation(); setDeleteModal({ show: true, id: scan.id, domain: scan.domain }); }} title="Delete">🗑️</button>
                </div>
              </div>
              <div className="scan-meta">
                <span>Scan ID: {scan.id}</span>
                <span>{scan.scan_date ? new Date(scan.scan_date).toLocaleString() : 'N/A'}</span>
              </div>
              <div className="scan-stats-row">
                <div className="scan-stat"><div className="value">{scan.subdomain_count}</div><div className="label">Subdomains</div></div>
                <div className="scan-stat"><div className="value">{scan.endpoint_count}</div><div className="label">Endpoints</div></div>
                <div className="scan-stat"><div className="value">{scan.vulnerability_count || 0}</div><div className="label">Vulns</div></div>
              </div>
            </div>
          ))}
        </div>
      )}

      <NewScanModal show={showModal} onClose={() => setShowModal(false)} onScanCreated={(id) => { loadScans(); navigate(`/scans/${id}`); }} />
      <DeleteModal show={deleteModal.show} domain={deleteModal.domain} onClose={() => setDeleteModal({ show: false, id: null, domain: '' })} onConfirm={handleDelete} />
      <DeleteModal show={deleteAllModal} isDeleteAll count={scans.length} onClose={() => setDeleteAllModal(false)} onConfirm={handleDeleteAll} />
    </div>
  );
}
