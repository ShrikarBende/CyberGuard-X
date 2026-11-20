import React, { useState, useEffect, useRef, lazy, Suspense } from 'react';
import Sidebar from './components/Sidebar';
import Header from './components/Header';
const Overview = lazy(() => import('./pages/Overview'));
const LiveMonitoring = lazy(() => import('./pages/LiveMonitoring'));
const ThreatIntelligence = lazy(() => import('./pages/ThreatIntelligence'));
const IncidentManagement = lazy(() => import('./pages/IncidentManagement'));
const Explainability = lazy(() => import('./pages/Explainability'));
const AIAssistant = lazy(() => import('./pages/AIAssistant'));
const DataManagement = lazy(() => import('./pages/DataManagement'));
const Evaluation = lazy(() => import('./pages/Evaluation'));
import { api } from './services/api';

export default function App() {
  const [activePage, setActivePage] = useState('overview');
  const [selectedIncidentIdForAssistant, setSelectedIncidentIdForAssistant] = useState(null);
  const [liveEvents, setLiveEvents] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [hasSyntheticDemo, setHasSyntheticDemo] = useState(false);
  const [authToken, setAuthToken] = useState(() => window.sessionStorage.getItem('cyberguardx_access_token'));
  const [analyst, setAnalyst] = useState(() => {
    try { return JSON.parse(window.sessionStorage.getItem('cyberguardx_analyst') || 'null'); }
    catch { return null; }
  });
  const [loginName, setLoginName] = useState('');
  const [loginPassword, setLoginPassword] = useState('');
  const [loginError, setLoginError] = useState('');
  const [loginPending, setLoginPending] = useState(false);
  const [forbiddenMessage, setForbiddenMessage] = useState('');
  const wsRef = useRef(null);

  useEffect(() => {
    const expired = () => {
      setAuthToken(null);
      setAnalyst(null);
      setLoginError('Your session expired. Please sign in again.');
    };
    const forbidden = (event) => setForbiddenMessage(event.detail || 'Your role does not have permission to do that.');
    window.addEventListener('analyst-session-expired', expired);
    window.addEventListener('analyst-forbidden', forbidden);
    return () => {
      window.removeEventListener('analyst-session-expired', expired);
      window.removeEventListener('analyst-forbidden', forbidden);
    };
  }, []);

  useEffect(() => {
    if (!authToken) return;
    api.getCurrentAnalyst().then((current) => {
      setAnalyst(current);
      window.sessionStorage.setItem('cyberguardx_analyst', JSON.stringify(current));
    }).catch(() => {});
  }, [authToken]);

  const handleLogin = async (event) => {
    event.preventDefault();
    setLoginPending(true);
    setLoginError('');
    try {
      const result = await api.login(loginName, loginPassword);
      window.sessionStorage.setItem('cyberguardx_access_token', result.access_token);
      window.sessionStorage.setItem('cyberguardx_analyst', JSON.stringify(result.analyst));
      setAuthToken(result.access_token);
      setAnalyst(result.analyst);
      setLoginPassword('');
    } catch (error) {
      setLoginError(error.message || 'Login failed.');
    } finally {
      setLoginPending(false);
    }
  };

  const handleLogout = () => {
    window.sessionStorage.removeItem('cyberguardx_access_token');
    window.sessionStorage.removeItem('cyberguardx_analyst');
    setAuthToken(null);
    setAnalyst(null);
  };

  useEffect(() => {
    let mounted = true;
    const refreshDemoStatus = () => api.getDemoStatus()
      .then((status) => { if (mounted) setHasSyntheticDemo(Boolean(status.has_synthetic_demo)); })
      .catch((err) => console.error('Failed to check demo-data status:', err));
    if (authToken) refreshDemoStatus();
    const interval = setInterval(refreshDemoStatus, 15000);
    window.addEventListener('synthetic-demo-updated', refreshDemoStatus);
    return () => {
      mounted = false;
      clearInterval(interval);
      window.removeEventListener('synthetic-demo-updated', refreshDemoStatus);
    };
  }, [authToken]);

  // WebSocket Live Connection
  useEffect(() => {
    if (!authToken) {
      setWsConnected(false);
      return undefined;
    }
    let reconnectTimeout = null;
    let isMounted = true;

    function connect() {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const host = window.location.host;
      const wsUrl = `${protocol}//${host}/ws/live-events?token=${encodeURIComponent(authToken)}`;

      try {
        const ws = new WebSocket(wsUrl);
        wsRef.current = ws;

        ws.onopen = () => {
          if (isMounted) setWsConnected(true);
        };

        ws.onmessage = (event) => {
          try {
            const data = JSON.parse(event.data);
            if (data.type === 'SECURITY_EVENT') {
              setLiveEvents((prev) => [data, ...prev.slice(0, 150)]);
            }
          } catch (e) {
            console.error('Failed to parse WS payload:', e);
          }
        };

        ws.onclose = (event) => {
          if (isMounted) {
            setWsConnected(false);
            if (event.code === 4401) {
              window.dispatchEvent(new Event('analyst-session-expired'));
            } else {
              reconnectTimeout = setTimeout(connect, 3000);
            }
          }
        };

        ws.onerror = () => {
          ws.close();
        };
      } catch (err) {
        console.error('WS Connection error:', err);
        reconnectTimeout = setTimeout(connect, 4000);
      }
    }

    connect();

    return () => {
      isMounted = false;
      if (reconnectTimeout) clearTimeout(reconnectTimeout);
      if (wsRef.current) wsRef.current.close();
    };
  }, [authToken]);

  const handleSelectIncidentForAssistant = (incId) => {
    setSelectedIncidentIdForAssistant(incId);
    setActivePage('assistant');
  };

  const pageTitles = {
    overview: 'Executive Overview Dashboard',
    live: 'Live Security Telemetry Stream',
    threats: 'Threat Intelligence & Open-Set Analysis',
    incidents: 'Incident Management & Correlation',
    explain: 'SHAP Explainability & Risk Scoring',
    assistant: 'Grounded AI Security Assistant (RAG)',
    data: 'Data Governance & Model Training',
    evaluation: 'CICIDS Evaluation Summary',
  };

  if (!authToken) {
    return (
      <div className="min-h-screen bg-[#0A0F1D] text-slate-100 flex items-center justify-center p-6">
        <form onSubmit={handleLogin} className="w-full max-w-sm rounded-2xl border border-[#1E293B] bg-[#10182E] p-7 space-y-4">
          <div><h1 className="text-lg font-bold">CyberGuard X analyst sign in</h1><p className="mt-1 text-xs text-slate-400">Sign in with your assigned analyst account.</p></div>
          {loginError && <p role="alert" className="rounded-lg bg-rose-500/10 border border-rose-500/30 p-3 text-xs text-rose-300">{loginError}</p>}
          <label className="block text-xs text-slate-400">Username<input value={loginName} onChange={(event) => setLoginName(event.target.value)} autoComplete="username" required className="mt-1 w-full rounded-lg bg-[#0D1527] border border-[#1E293B] p-3 text-sm text-white" /></label>
          <label className="block text-xs text-slate-400">Password<input type="password" value={loginPassword} onChange={(event) => setLoginPassword(event.target.value)} autoComplete="current-password" required className="mt-1 w-full rounded-lg bg-[#0D1527] border border-[#1E293B] p-3 text-sm text-white" /></label>
          <button disabled={loginPending} className="w-full rounded-lg bg-blue-600 px-4 py-3 text-sm font-semibold disabled:opacity-50">{loginPending ? 'Signing in…' : 'Sign in'}</button>
        </form>
      </div>
    );
  }

  return (
    <div className="flex h-screen w-screen bg-[#0A0F1D] text-[#F8FAFC] overflow-hidden">
      {/* Sidebar Navigation */}
      <Sidebar activePage={activePage} setActivePage={setActivePage} role={analyst?.role} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header pageTitle={pageTitles[activePage] || 'SOC Dashboard'} wsConnected={wsConnected} analyst={analyst} onLogout={handleLogout} />

        {forbiddenMessage && (
          <div role="alert" className="mx-8 mt-4 flex items-center justify-between rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-2 text-xs text-rose-200">
            <span>403 — {forbiddenMessage}</span>
            <button onClick={() => setForbiddenMessage('')} aria-label="Dismiss permission message">Dismiss</button>
          </div>
        )}
        {hasSyntheticDemo && (
          <div role="status" className="mx-8 mt-4 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-2 text-xs font-semibold text-amber-200">
            Synthetic demo data — synthetic_demo events are present in this workspace.
          </div>
        )}

        <main className="flex-1 overflow-y-auto p-8">
          <Suspense fallback={<div className="p-8 text-center text-slate-400">Loading page…</div>}>
          {activePage === 'overview' && (
            <Overview onSelectIncident={handleSelectIncidentForAssistant} />
          )}
          {activePage === 'live' && <LiveMonitoring liveEvents={liveEvents} />}
          {activePage === 'threats' && <ThreatIntelligence />}
          {activePage === 'incidents' && (
            <IncidentManagement onSelectIncidentForAssistant={analyst?.role !== 'viewer' ? handleSelectIncidentForAssistant : null} role={analyst?.role} />
          )}
          {activePage === 'explain' && <Explainability />}
          {activePage === 'assistant' && (
            <AIAssistant initialIncidentId={selectedIncidentIdForAssistant} />
          )}
          {activePage === 'data' && <DataManagement role={analyst?.role} />}
          {activePage === 'evaluation' && <Evaluation />}
          </Suspense>
        </main>
      </div>
    </div>
  );
}

