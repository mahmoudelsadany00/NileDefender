import { useState, useCallback, useEffect, useRef } from 'react';
import {
  createReconScan,
  startVulnScanNew,
  startVulnScanExisting,
  searchExistingScans,
} from '../services/api';

export default function NewScanModal({ show, onClose, onScanCreated }) {
  const [scanType, setScanType] = useState('recon');
  const [target, setTarget] = useState('');
  const [passive, setPassive] = useState(true);
  const [active, setActive] = useState(false);
  const [crawl, setCrawl] = useState(true);
  const [vulnMode, setVulnMode] = useState('full');
  const [modules, setModules] = useState({ sqli: true, pt: true, htmli: true, xss: true, idor: true, cmdi: true });
  const [loading, setLoading] = useState(false);

  // Existing scans lookup
  const [existingScans, setExistingScans] = useState([]);
  const [selectedExisting, setSelectedExisting] = useState(null);
  const [dismissed, setDismissed] = useState(false);
  const searchTimer = useRef(null);

  const resetForm = useCallback(() => {
    setTarget('');
    setPassive(true);
    setActive(false);
    setCrawl(true);
    setScanType('recon');
    setVulnMode('full');
    setModules({ sqli: true, pt: true, htmli: true, xss: true, idor: true, cmdi: true });
    setLoading(false);
    setExistingScans([]);
    setSelectedExisting(null);
    setDismissed(false);
  }, []);

  const handleClose = () => {
    resetForm();
    onClose();
  };

  // Search existing scans debounced
  const onTargetInput = (val) => {
    setTarget(val);
    if (scanType !== 'vulnscan' || dismissed) return;
    clearTimeout(searchTimer.current);
    searchTimer.current = setTimeout(async () => {
      if (val.trim().length >= 3) {
        const scans = await searchExistingScans(val.trim());
        setExistingScans(scans);
        if (scans.length > 0) setSelectedExisting(scans[0].id);
      } else {
        setExistingScans([]);
        setSelectedExisting(null);
      }
    }, 400);
  };

  useEffect(() => {
    if (scanType === 'vulnscan' && target.trim().length >= 3 && !dismissed) {
      searchExistingScans(target.trim()).then((scans) => {
        setExistingScans(scans);
        if (scans.length > 0) setSelectedExisting(scans[0].id);
      });
    }
  }, [scanType]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!target.trim()) return alert('Please enter a target.');

    setLoading(true);
    try {
      if (scanType === 'recon') {
        const data = await createReconScan(target.trim(), { passive, active, crawl });
        handleClose();
        onScanCreated(data.scan_id);
      } else {
        // Vuln scan
        const mods = [];
        if (vulnMode === 'full') {
          mods.push('sqli', 'pt', 'htmli', 'xss', 'idor', 'cmdi');
        } else {
          if (modules.sqli) mods.push('sqli');
          if (modules.pt) mods.push('pt');
          if (modules.htmli) mods.push('htmli');
          if (modules.xss) mods.push('xss');
          if (modules.idor) mods.push('idor');
          if (modules.cmdi) mods.push('cmdi');
        }
        if (mods.length === 0) {
          alert('Please select at least one module.');
          setLoading(false);
          return;
        }

        const savedExisting = selectedExisting;
        const freshRequested = existingScans.length > 0 && selectedExisting === null;

        if (savedExisting && savedExisting !== 'new') {
          await startVulnScanExisting(savedExisting, { scanType: vulnMode, modules: mods });
          handleClose();
          onScanCreated(savedExisting);
        } else {
          const data = await startVulnScanNew(target.trim(), {
            scanType: vulnMode,
            modules: mods,
            fresh: freshRequested,
          });
          handleClose();
          onScanCreated(data.scan_id);
        }
      }
    } catch (err) {
      alert('Error: ' + err.message);
      setLoading(false);
    }
  };

  if (!show) return null;

  return (
    <div className={`modal-overlay ${show ? 'active' : ''}`} onClick={(e) => e.target === e.currentTarget && handleClose()}>
      <div className="modal" style={{ maxWidth: 520 }}>
        <h3>New Scan</h3>

        {/* Scan Type Toggle */}
        <div className="form-group" style={{ marginBottom: 16 }}>
          <div className="scan-mode-toggle">
            <button type="button" className={`mode-btn ${scanType === 'recon' ? 'active' : ''}`} onClick={() => setScanType('recon')}>
              <span className="mode-icon">🔍</span>
              <span className="mode-label">Recon Scan</span>
              <span className="mode-desc">Discover subdomains & endpoints</span>
            </button>
            <button type="button" className={`mode-btn ${scanType === 'vulnscan' ? 'active' : ''}`} onClick={() => setScanType('vulnscan')}>
              <span className="mode-icon">🛡️</span>
              <span className="mode-label">Vulnerability Scan</span>
              <span className="mode-desc">Find security vulnerabilities</span>
            </button>
          </div>
        </div>

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>Target</label>
            <input
              type="text"
              value={target}
              onChange={(e) => onTargetInput(e.target.value)}
              placeholder="example.com or http://localhost/bWAPP/"
            />
          </div>

          {/* ── RECON PANEL ── */}
          {scanType === 'recon' && (
            <div>
              <div className="info-box accent">
                Enter a <strong>domain</strong> (e.g. example.com) or <strong>local URL</strong> to start reconnaissance.
              </div>
              <div className="form-group">
                <label>Options</label>
                <div className="options-panel">
                  <label className="option-row">
                    <input type="checkbox" checked={passive} onChange={(e) => setPassive(e.target.checked)} />
                    <span>🔍 Passive Recon</span>
                    <span className="option-hint">(CT logs, APIs — safe, remote only)</span>
                  </label>
                  <label className="option-row">
                    <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} />
                    <span>⚡ Active Recon</span>
                    <span className="option-hint">(DNS brute-force — intrusive, remote only)</span>
                  </label>
                  <label className="option-row">
                    <input type="checkbox" checked={crawl} onChange={(e) => setCrawl(e.target.checked)} />
                    <span>🌐 URL Crawling</span>
                    <span className="option-hint">(Find endpoints & parameters)</span>
                  </label>
                </div>
              </div>
            </div>
          )}

          {/* ── VULNSCAN PANEL ── */}
          {scanType === 'vulnscan' && (
            <div>
              <div className="info-box danger">
                Enter a target URL. If previously scanned, existing endpoints will be reused. Otherwise, crawling runs first automatically.
              </div>

              {/* Existing scans banner */}
              {existingScans.length > 0 && !dismissed && (
                <div className="existing-scans-banner">
                  <div className="existing-scans-header">
                    <span>📦</span>
                    <span className="existing-scans-title">Existing data found!</span>
                    <button className="btn-icon" onClick={() => setDismissed(true)} style={{ width: 24, height: 24, fontSize: 12 }}>✕</button>
                  </div>
                  <p className="existing-scans-desc">This target was previously scanned. Skip crawling and use existing endpoints:</p>
                  <select
                    className="existing-scan-select"
                    value={selectedExisting || 'new'}
                    onChange={(e) => setSelectedExisting(e.target.value === 'new' ? null : parseInt(e.target.value))}
                  >
                    {existingScans.map((s) => (
                      <option key={s.id} value={s.id}>
                        Scan #{s.id} — {s.domain} ({s.endpoint_count} endpoints, {s.scan_date ? new Date(s.scan_date).toLocaleDateString() : 'N/A'})
                      </option>
                    ))}
                    <option value="new">🔄 Scan Fresh (new crawl)</option>
                  </select>
                </div>
              )}

              {/* Scan Mode */}
              <div className="form-group" style={{ marginBottom: 10 }}>
                <label style={{ fontSize: 12, marginBottom: 4 }}>Scan Mode</label>
                <div className="scan-mode-toggle">
                  <button type="button" className={`mode-btn compact ${vulnMode === 'full' ? 'active' : ''}`} onClick={() => setVulnMode('full')}>
                    <span className="mode-icon">🚀</span>
                    <span className="mode-label">Full Scan</span>
                    <span className="mode-desc">All vulnerability checks</span>
                  </button>
                  <button type="button" className={`mode-btn compact ${vulnMode === 'custom' ? 'active' : ''}`} onClick={() => setVulnMode('custom')}>
                    <span className="mode-icon">🎯</span>
                    <span className="mode-label">Custom Scan</span>
                    <span className="mode-desc">Choose specific modules</span>
                  </button>
                </div>
              </div>

              {/* Module Selection */}
              {vulnMode === 'custom' && (
                <div className="form-group" style={{ marginBottom: 6 }}>
                  <label style={{ fontSize: 12, marginBottom: 4 }}>Vulnerability Modules</label>
                  <div className="module-grid">
                    <label className="module-card">
                      <input type="checkbox" checked={modules.sqli} onChange={(e) => setModules({ ...modules, sqli: e.target.checked })} />
                      <span className="module-icon">💉</span>
                      <span className="module-name">SQL Injection</span>
                      <span className="module-severity severity-high">High</span>
                    </label>
                    <label className="module-card">
                      <input type="checkbox" checked={modules.xss} onChange={(e) => setModules({ ...modules, xss: e.target.checked })} />
                      <span className="module-icon">📜</span>
                      <span className="module-name">XSS</span>
                      <span className="module-severity severity-high">High</span>
                    </label>
                    <label className="module-card">
                      <input type="checkbox" checked={modules.pt} onChange={(e) => setModules({ ...modules, pt: e.target.checked })} />
                      <span className="module-icon">📂</span>
                      <span className="module-name">Path Traversal</span>
                      <span className="module-severity severity-high">High</span>
                    </label>
                    <label className="module-card">
                      <input type="checkbox" checked={modules.htmli} onChange={(e) => setModules({ ...modules, htmli: e.target.checked })} />
                      <span className="module-icon">🧩</span>
                      <span className="module-name">HTML Injection</span>
                      <span className="module-severity severity-high">High</span>
                    </label>

                    <label className="module-card">
                      <input type="checkbox" checked={modules.idor} onChange={(e) => setModules({ ...modules, idor: e.target.checked })} />
                      <span className="module-icon">🔓</span>
                      <span className="module-name">IDOR</span>
                      <span className="module-severity severity-high">High</span>
                    </label>
                    <label className="module-card">
                      <input type="checkbox" checked={modules.cmdi} onChange={(e) => setModules({ ...modules, cmdi: e.target.checked })} />
                      <span className="module-icon">⚡</span>
                      <span className="module-name">Command Injection</span>
                      <span className="module-severity severity-high">High</span>
                    </label>
                  </div>
                </div>
              )}
            </div>
          )}

          <div className="modal-actions">
            <button type="button" className="btn btn-secondary" onClick={handleClose}>Cancel</button>
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? <><span className="spinner" style={{ width: 16, height: 16, borderWidth: 2 }} /> Starting...</> : 'Start Scan'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
