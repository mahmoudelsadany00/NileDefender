// NileDefender — API Service Layer

const API_BASE = '/api';

// ── Helpers ──
function escapeHtml(unsafe) {
  if (unsafe === null || unsafe === undefined) return '';
  return String(unsafe)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

// ── Dashboard ──
export async function fetchDashboardStats() {
  const res = await fetch(`${API_BASE}/dashboard/stats`);
  const data = await res.json();
  if (data.success) return data.stats;
  throw new Error(data.error || 'Failed to load stats');
}

// ── Scans ──
export async function fetchScans() {
  const res = await fetch(`${API_BASE}/scans`);
  const data = await res.json();
  if (data.success) return data.scans;
  throw new Error(data.error || 'Failed to load scans');
}

export async function fetchScanDetails(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}`);
  const data = await res.json();
  if (data.success) return data.scan;
  throw new Error(data.error || 'Scan not found');
}

export async function fetchScanStats(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}/stats`);
  const data = await res.json();
  if (data.success) return data.stats;
  throw new Error(data.error || 'Failed to load stats');
}

export async function fetchSubdomains(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}/subdomains`);
  const data = await res.json();
  if (data.success) return data.subdomains;
  throw new Error(data.error || 'Failed to load subdomains');
}

export async function fetchEndpoints(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}/endpoints`);
  const data = await res.json();
  if (data.success) return data.endpoints;
  throw new Error(data.error || 'Failed to load endpoints');
}

export async function fetchVulnerabilities(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}/vulnerabilities`);
  const data = await res.json();
  if (data.success) return data.vulnerabilities;
  throw new Error(data.error || 'Failed to load vulnerabilities');
}

// ── Create Scan ──
export async function createReconScan(target, options = {}) {
  const res = await fetch(`${API_BASE}/scans`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target,
      passive: options.passive ?? true,
      active: options.active ?? false,
      crawl: options.crawl ?? true,
    }),
  });
  const data = await res.json();
  if (data.success) return data;
  throw new Error(data.error || 'Failed to create scan');
}

export async function startVulnScanNew(target, options = {}) {
  const res = await fetch(`${API_BASE}/vulnscan/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      target,
      scan_type: options.scanType || 'full',
      modules: options.modules || ['sqli'],
      fresh: options.fresh || false,
    }),
  });
  const data = await res.json();
  if (data.success) return data;
  throw new Error(data.error || 'Failed to start vuln scan');
}

export async function startVulnScanExisting(scanId, options = {}) {
  const res = await fetch(`${API_BASE}/scans/${scanId}/vulnscan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scan_type: options.scanType || 'full',
      modules: options.modules || ['sqli'],
    }),
  });
  const data = await res.json();
  if (data.success || res.status === 409) return data;
  throw new Error(data.error || 'Failed to start vuln scan');
}

// ── Search Existing Scans ──
export async function searchExistingScans(target) {
  const res = await fetch(`${API_BASE}/scans/search?target=${encodeURIComponent(target)}`);
  const data = await res.json();
  if (data.success) return data.scans;
  return [];
}

// ── Delete ──
export async function deleteScan(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}`, { method: 'DELETE' });
  const data = await res.json();
  if (data.success) return data;
  throw new Error(data.error || 'Failed to delete scan');
}

export async function deleteAllScans() {
  const res = await fetch(`${API_BASE}/scans/all`, { method: 'DELETE' });
  const data = await res.json();
  if (data.success) return data;
  throw new Error(data.error || 'Failed to delete scans');
}

// ── Export ──
export async function exportScanData(scanId, format, dataType) {
  let data = {};

  if (dataType === 'all' || dataType === 'subdomains') {
    data.subdomains = await fetchSubdomains(scanId);
  }
  if (dataType === 'all' || dataType === 'endpoints') {
    data.endpoints = await fetchEndpoints(scanId);
  }
  if (dataType === 'all' || dataType === 'vulnerabilities') {
    data.vulnerabilities = await fetchVulnerabilities(scanId);
  }

  const filename = `niledefender_${dataType}_${scanId}`;

  if (format === 'json') {
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `${filename}.json`);
  } else if (format === 'csv') {
    const items = dataType === 'all'
      ? [...(data.subdomains || []), ...(data.endpoints || []), ...(data.vulnerabilities || [])]
      : data[dataType] || [];
    if (items.length === 0) return;
    const headers = Object.keys(items[0]);
    const csv = [headers.join(','), ...items.map(item =>
      headers.map(h => `"${String(item[h] ?? '').replace(/"/g, '""')}"`).join(',')
    )].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    downloadBlob(blob, `${filename}.csv`);
  }
}

// Export aggregated data (all scans) — used by Subdomains, Endpoints, Vulnerabilities pages
export function exportAggregatedData(items, dataType, format) {
  if (!items || items.length === 0) return;

  const filename = `niledefender_all_${dataType}`;

  if (format === 'json') {
    const blob = new Blob([JSON.stringify(items, null, 2)], { type: 'application/json' });
    downloadBlob(blob, `${filename}.json`);
  } else if (format === 'csv') {
    const headers = Object.keys(items[0]);
    const csv = [headers.join(','), ...items.map(item =>
      headers.map(h => `"${String(item[h] ?? '').replace(/"/g, '""')}"`).join(',')
    )].join('\n');
    const blob = new Blob([csv], { type: 'text/csv' });
    downloadBlob(blob, `${filename}.csv`);
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// ── AI Report ──
export async function generateAIReport(scanId) {
  const res = await fetch(`${API_BASE}/scans/${scanId}/report`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!res.ok) {
    const data = await res.json();
    throw new Error(data.error || 'Report generation failed');
  }
  const blob = await res.blob();
  downloadBlob(blob, `NileDefender_Report_Scan${scanId}.pdf`);
}

export { escapeHtml };
