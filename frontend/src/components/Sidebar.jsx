import { useLocation, useNavigate } from 'react-router-dom';
import ThemeSwitcher from './ThemeSwitcher';

const navItems = [
  {
    section: 'Main',
    links: [
      { path: '/', icon: '📊', label: 'Dashboard' },
      { path: '/scans', icon: '🔍', label: 'Scans' },
    ],
  },
  {
    section: 'Recon',
    links: [
      { path: '/subdomains', icon: '🌐', label: 'Subdomains' },
      { path: '/endpoints', icon: '🔗', label: 'Endpoints' },
    ],
  },
  {
    section: 'Security',
    links: [
      { path: '/vulnerabilities', icon: '⚠️', label: 'Vulnerabilities' },
    ],
  },
];

export default function Sidebar({ connected }) {
  const location = useLocation();
  const navigate = useNavigate();

  return (
    <aside className="sidebar">
      <div className="logo">
        <img src="/logo.png" alt="Logo" style={{ height: '42px', width: 'auto', borderRadius: '8px', objectFit: 'contain' }} />
        <div className="logo-text">
          <h1>NileDefender</h1>
          <span>Vulnerability Scanner</span>
        </div>
      </div>

      <nav>
        {navItems.map((section) => (
          <div className="nav-section" key={section.section}>
            <div className="nav-section-title">{section.section}</div>
            {section.links.map((link) => (
              <a
                key={link.path}
                className={`nav-link ${location.pathname === link.path ? 'active' : ''}`}
                onClick={() => navigate(link.path)}
              >
                <span className="icon">{link.icon}</span>
                <span>{link.label}</span>
              </a>
            ))}
          </div>
        ))}
      </nav>

      <div style={{ marginTop: 'auto' }}>
        <ThemeSwitcher />
        <div className="connection-status" style={{ marginTop: '12px' }}>
          <span className={`connection-dot ${connected ? 'connected' : 'disconnected'}`} />
          <span>{connected ? 'Connected' : 'Disconnected'}</span>
        </div>
      </div>
    </aside>
  );
}
