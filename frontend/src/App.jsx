import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { useSocket } from './hooks/useSocket';
import { NotificationProvider } from './components/Notification';
import { ThemeProvider } from './hooks/useTheme';
import Sidebar from './components/Sidebar';
import Dashboard from './pages/Dashboard';
import Scans from './pages/Scans';
import ScanDetails from './pages/ScanDetails';
import Subdomains from './pages/Subdomains';
import Endpoints from './pages/Endpoints';
import Vulnerabilities from './pages/Vulnerabilities';
import './index.css';

function AppContent() {
  const socket = useSocket();

  return (
    <NotificationProvider>
      <div className="bg-gradient" />
      <div className="app-layout">
        <Sidebar connected={socket.connected} />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard socketEvents={socket} />} />
            <Route path="/scans" element={<Scans socketEvents={socket} />} />
            <Route path="/scans/:id" element={<ScanDetails socketEvents={socket} />} />
            <Route path="/subdomains" element={<Subdomains />} />
            <Route path="/endpoints" element={<Endpoints />} />
            <Route path="/vulnerabilities" element={<Vulnerabilities />} />
          </Routes>
        </main>
      </div>
    </NotificationProvider>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <ThemeProvider>
        <AppContent />
      </ThemeProvider>
    </BrowserRouter>
  );
}
