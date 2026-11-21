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
import LoginScreen from './components/LoginScreen';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from './lib/motion';
import Modal from './components/ui/Modal';
import ErrorBoundary from './components/ErrorBoundary';

export default function App() {
  const [activePage, setActivePage] = useState('overview');
  const [selectedIncidentIdForAssistant, setSelectedIncidentIdForAssistant] = useState(null);
  const [liveEvents, setLiveEvents] = useState([]);
  const [unreadLiveEvents, setUnreadLiveEvents] = useState(0);
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
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
  const shellRef = useRef(null);
  const pageRef = useRef(null);
  const lastSeenLiveEventId = useRef(null);
  const gPrefixActive = useRef(false);
  const gPrefixTimeout = useRef(null);

  useEffect(() => {
    if (!authToken) return undefined;
    const pagesByShortcut = { o: 'overview', l: 'live', i: 'incidents', t: 'threats', e: 'explain', a: 'assistant', d: 'data', v: 'evaluation' };
    const isEditableTarget = (target) => target instanceof HTMLElement && (
      target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName) || Boolean(target.closest('[contenteditable="true"]'))
    );
    const clearGPrefix = () => {
      gPrefixActive.current = false;
      if (gPrefixTimeout.current) window.clearTimeout(gPrefixTimeout.current);
      gPrefixTimeout.current = null;
    };
    const onKeyDown = (event) => {
      if (isEditableTarget(event.target)) return;
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        clearGPrefix();
        setCommandPaletteOpen(true);
        return;
      }
      if (event.key === '?') {
        event.preventDefault();
        clearGPrefix();
        setShortcutsOpen(true);
        return;
      }
      if (event.key === '[') {
        event.preventDefault();
        clearGPrefix();
        window.dispatchEvent(new Event('cyberguardx-toggle-sidebar'));
        return;
      }
      if (gPrefixActive.current) {
        clearGPrefix();
        const page = pagesByShortcut[event.key.toLowerCase()];
        if (page && !(page === 'assistant' && analyst?.role === 'viewer')) setActivePage(page);
        return;
      }
      if (!event.ctrlKey && !event.metaKey && !event.altKey && event.key.toLowerCase() === 'g') {
        gPrefixActive.current = true;
        gPrefixTimeout.current = window.setTimeout(clearGPrefix, 900);
      }
    };
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      clearGPrefix();
    };
  }, [authToken, analyst?.role]);

  useEffect(() => {
    if (activePage === 'live') setUnreadLiveEvents(0);
  }, [activePage]);

  useEffect(() => {
    const newestEventId = liveEvents[0]?.event_id;
    if (!newestEventId || newestEventId === lastSeenLiveEventId.current) return;
    lastSeenLiveEventId.current = newestEventId;
    setUnreadLiveEvents((count) => (activePage === 'live' ? 0 : count + 1));
  }, [liveEvents, activePage]);

  useGSAP(() => {
    if (!authToken) return undefined;
    return createMotionScope(shellRef.current, (reduced) => {
      const duration = reduced ? 0.18 : motion.duration.base;
      gsap.fromTo('.shell-sidebar', { autoAlpha: 0, x: reduced ? 0 : -10 }, { autoAlpha: 1, x: 0, duration, ease: motion.ease });
      gsap.fromTo('.shell-header', { autoAlpha: 0, y: reduced ? 0 : -8 }, { autoAlpha: 1, y: 0, duration, ease: motion.ease, delay: reduced ? 0 : 0.08 });
    });
  }, { scope: shellRef, dependencies: [authToken], revertOnUpdate: true });

  useGSAP(() => {
    if (!authToken || !pageRef.current) return undefined;
    return createMotionScope(pageRef.current, (reduced) => {
      gsap.fromTo(pageRef.current, { autoAlpha: 0, y: reduced ? 0 : 12 }, { autoAlpha: 1, y: 0, duration: reduced ? 0.18 : 0.25, ease: motion.ease });
    });
  }, { scope: pageRef, dependencies: [activePage, authToken], revertOnUpdate: true });

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
      <LoginScreen loginName={loginName} setLoginName={setLoginName} loginPassword={loginPassword} setLoginPassword={setLoginPassword} loginError={loginError} loginPending={loginPending} handleLogin={handleLogin} />
    );
  }

  return (
    <div ref={shellRef} className="flex h-screen w-screen overflow-hidden bg-soc-bg text-soc-text">
      {/* Sidebar Navigation */}
      <div className="shell-sidebar flex"><Sidebar activePage={activePage} setActivePage={setActivePage} role={analyst?.role} liveEventsCount={unreadLiveEvents} wsConnected={wsConnected} analyst={analyst} onLogout={handleLogout} /></div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <div className="shell-header"><Header pageTitle={pageTitles[activePage] || 'SOC Dashboard'} wsConnected={wsConnected} analyst={analyst} onLogout={handleLogout} liveEvents={liveEvents} role={analyst?.role} setActivePage={setActivePage} commandPaletteOpen={commandPaletteOpen} setCommandPaletteOpen={setCommandPaletteOpen} /></div>

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

        <main className="flex-1 overflow-y-auto p-soc-page">
          <ErrorBoundary resetKey={activePage}>
          <Suspense fallback={<div className="p-8 text-center text-slate-400">Loading page…</div>}>
          <div ref={pageRef} key={activePage}>
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
          </div>
          </Suspense>
          </ErrorBoundary>
        </main>
      </div>
      <Modal open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} title="Keyboard shortcuts" className="p-5 sm:p-6">
        <div className="flex items-start justify-between gap-4">
          <div><p className="text-[9px] font-bold uppercase tracking-[0.18em] text-blue-300">Keyboard shortcuts</p><h2 className="mt-1 font-display text-lg font-semibold text-slate-100">Navigate CyberGuard X</h2></div>
          <button type="button" onClick={() => setShortcutsOpen(false)} aria-label="Close keyboard shortcuts" className="rounded-lg border border-white/10 px-2 py-1 font-mono text-[10px] text-slate-400 hover:text-white">Esc</button>
        </div>
        <dl className="mt-5 divide-y divide-white/[0.06]">
          <div className="flex items-center justify-between gap-4 py-3"><dt className="text-xs text-slate-300">Open command palette</dt><dd><kbd className="rounded-md border border-white/10 px-2 py-1 font-mono text-[10px] text-slate-200">Ctrl / ⌘ + K</kbd></dd></div>
          <div className="flex items-center justify-between gap-4 py-3"><dt className="text-xs text-slate-300">Open this help</dt><dd><kbd className="rounded-md border border-white/10 px-2 py-1 font-mono text-[10px] text-slate-200">?</kbd></dd></div>
          <div className="flex items-center justify-between gap-4 py-3"><dt className="text-xs text-slate-300">Toggle sidebar</dt><dd><kbd className="rounded-md border border-white/10 px-2 py-1 font-mono text-[10px] text-slate-200">[</kbd></dd></div>
          <div className="py-3"><dt className="mb-2 text-xs text-slate-300">Go to a page</dt><dd className="flex flex-wrap gap-2">{[
            ['o', 'Overview'], ['l', 'Live Feed'], ['i', 'Incidents'], ['t', 'Threats'], ['e', 'Explainability'], ...(analyst?.role === 'viewer' ? [] : [['a', 'AI Assistant']]), ['d', 'Data & Models'], ['v', 'Evaluation'],
          ].map(([key, label]) => <span key={key} className="inline-flex items-center gap-1.5 rounded-lg border border-white/[0.07] bg-white/[0.025] px-2 py-1"><kbd className="font-mono text-[9px] text-blue-200">g {key}</kbd><span className="text-[9px] text-slate-400">{label}</span></span>)}</dd></div>
        </dl>
      </Modal>
    </div>
  );
}

