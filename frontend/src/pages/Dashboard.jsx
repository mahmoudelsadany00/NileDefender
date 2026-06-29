import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { fetchDashboardStats, fetchScans, deleteScan as apiDeleteScan, deleteAllScans as apiDeleteAll } from '../services/api';
import StatCard from '../components/StatCard';
import Badge from '../components/Badge';
import NewScanModal from '../components/NewScanModal';
import DeleteModal from '../components/DeleteModal';
import { useNotification } from '../components/Notification';

export default function Dashboard({ socketEvents }) {
  const [stats, setStats] = useState({ total_scans: 0, running_scans: 0, total_subdomains: 0, total_endpoints: 0, total_vulnerabilities: 0 });
  const [recentScans, setRecentScans] = useState([]);
  const [showModal, setShowModal] = useState(false);
  const [deleteModal, setDeleteModal] = useState({ show: false, id: null, domain: '' });
  const [deleteAllModal, setDeleteAllModal] = useState(false);
  const navigate = useNavigate();
  const notify = useNotification();

  const loadData = async () => {
    try {
      const [s, scans] = await Promise.all([fetchDashboardStats(), fetchScans()]);
      setStats(s);
      setRecentScans(scans.slice(0, 5));
    } catch (err) {
      console.error('Dashboard load error:', err);
    }
  };

  useEffect(() => { loadData(); }, []);

  // Listen for socket events to refresh
  useEffect(() => {
    if (!socketEvents) return;
    const unsub1 = socketEvents.onScanCompleted(() => loadData());
    const unsub2 = socketEvents.onVulnscanCompleted(() => loadData());
    return () => { unsub1(); unsub2(); };
  }, [socketEvents]);

  const handleDelete = async () => {
    try {
      await apiDeleteScan(deleteModal.id);
      setDeleteModal({ show: false, id: null, domain: '' });
      notify('Scan deleted successfully!', 'success');
      loadData();
    } catch (err) {
      notify('Error: ' + err.message, 'error');
    }
  };

  const handleDeleteAll = async () => {
    try {
      await apiDeleteAll();
      setDeleteAllModal(false);
      notify('All scans deleted!', 'success');
      loadData();
    } catch (err) {
      notify(err.message, 'error');
    }
  };

  const onScanCreated = (scanId) => {
    loadData();
    navigate(`/scans/${scanId}`);
  };

  return (
    <div>
      <div className="page-header">
        <div>
          <h2>Dashboard</h2>
          <p>Overview of your reconnaissance and scanning activity</p>
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

      <div className="stats-grid">
        <StatCard icon="🎯" value={stats.total_scans} label="Total Scans" color="teal" />
        <StatCard icon="⚡" value={stats.running_scans} label="Running" color="blue" />
        <StatCard icon="🌐" value={stats.total_subdomains} label="Subdomains" color="green" />
        <StatCard icon="🔗" value={stats.total_endpoints} label="Endpoints" color="orange" />
        <StatCard icon="⚠️" value={stats.total_vulnerabilities} label="Vulnerabilities" color="red" />
      </div>

      <div className="card card-body">
        <h3 style={{ fontSize: 18, fontWeight: 600, marginBottom: 20 }}>Recent Scans</h3>
        {recentScans.length === 0 ? (
          <div className="empty-state">
            <div className="empty-icon">🔍</div>
            <h4>No scans yet</h4>
            <p>Start your first reconnaissance scan</p>
          </div>
        ) : (
          recentScans.map((scan) => (
            <div
              key={scan.id}
              className="recent-scan-row"
              onClick={() => navigate(`/scans/${scan.id}`)}
            >
              <div>
                <div style={{ fontWeight: 600, marginBottom: 4 }}>{scan.domain}</div>
                <div style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {scan.scan_date ? new Date(scan.scan_date).toLocaleString() : 'N/A'}
                </div>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                <div style={{ textAlign: 'right', fontSize: 12, color: 'var(--text-muted)' }}>
                  <div>{scan.subdomain_count} subdomains</div>
                  <div>{scan.endpoint_count} endpoints</div>
                  <div>{scan.vulnerability_count || 0} vulns</div>
                </div>
                <Badge status={scan.status} />
                <button
                  className="btn-icon danger"
                  onClick={(e) => { e.stopPropagation(); setDeleteModal({ show: true, id: scan.id, domain: scan.domain }); }}
                  title="Delete scan"
                >🗑️</button>
              </div>
            </div>
          ))
        )}
      </div>

      <NewScanModal show={showModal} onClose={() => setShowModal(false)} onScanCreated={onScanCreated} />
      <DeleteModal show={deleteModal.show} domain={deleteModal.domain} onClose={() => setDeleteModal({ show: false, id: null, domain: '' })} onConfirm={handleDelete} />
      <DeleteModal show={deleteAllModal} isDeleteAll count={recentScans.length} onClose={() => setDeleteAllModal(false)} onConfirm={handleDeleteAll} />
    </div>
  );
}
