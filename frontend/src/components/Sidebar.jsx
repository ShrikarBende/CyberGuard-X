import React, { useEffect, useRef, useState } from 'react';
import {
  ShieldAlert, Activity, Radar, FileWarning, Sparkles, Bot, Database, Layers,
  BarChart3, Menu, X, PanelLeftClose, PanelLeftOpen, LogOut, Clock3,
} from 'lucide-react';
import { api } from '../services/api';

let dashboardStatsRequest = null;

function fetchDashboardStatsOnce() {
  if (!dashboardStatsRequest) {
    dashboardStatsRequest = api.getDashboardStats().finally(() => { dashboardStatsRequest = null; });
  }
  return dashboardStatsRequest;
}

const sections = [
  { title: 'Operate', ids: ['overview', 'live', 'incidents'] },
  { title: 'Investigate', ids: ['threats', 'assistant', 'explain'] },
  { title: 'Platform', ids: ['data', 'evaluation'] },
];

const navItems = [
  { id: 'overview', label: 'Overview', fullLabel: 'Overview Dashboard', icon: Activity },
  { id: 'live', label: 'Live Feed', fullLabel: 'Live Monitoring', icon: Radar },
  { id: 'incidents', label: 'Incidents', fullLabel: 'Incident Management', icon: FileWarning },
  { id: 'threats', label: 'Threats', fullLabel: 'Threat Intelligence', icon: ShieldAlert },
  { id: 'assistant', label: 'AI Assistant', fullLabel: 'AI Security Assistant', icon: Bot },
  { id: 'explain', label: 'Explainability', fullLabel: 'SHAP Explainability', icon: Sparkles },
  { id: 'data', label: 'Data & Models', fullLabel: 'Data & Model Training', icon: Database },
  { id: 'evaluation', label: 'Evaluation', fullLabel: 'Evaluation Summary', icon: BarChart3 },
];

function formatUpdatedAt(value) {
  return value ? value.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) : '—';
}

export default function Sidebar({
  activePage,
  setActivePage,
  role,
  liveEventsCount = 0,
  wsConnected = false,
  analyst = null,
  onLogout = () => {},
}) {
  const [collapsed, setCollapsed] = useState(() => {
    try {
      const saved = window.localStorage.getItem('cyberguardx_sidebar_collapsed');
      if (saved !== null) return saved === 'true';
    } catch { /* Local storage may be disabled. */ }
    return window.matchMedia('(max-width: 1023px)').matches;
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [systemStatus, setSystemStatus] = useState('');
  const [criticalIncidents, setCriticalIncidents] = useState(null);
  const [statsUpdatedAt, setStatsUpdatedAt] = useState(null);
  const lastRequestAt = useRef(0);
  const requestInFlight = useRef(false);
  const mounted = useRef(false);

  useEffect(() => {
    try { window.localStorage.setItem('cyberguardx_sidebar_collapsed', String(collapsed)); }
    catch { /* The rail remains usable without persistence. */ }
  }, [collapsed]);

  useEffect(() => {
    mounted.current = true;
    const refreshStats = async () => {
      const now = Date.now();
      if (document.hidden || requestInFlight.current || now - lastRequestAt.current < 30000) return;
      requestInFlight.current = true;
      lastRequestAt.current = now;
      try {
        const stats = await fetchDashboardStatsOnce();
        if (!mounted.current) return;
        setSystemStatus(typeof stats.system_status === 'string' ? stats.system_status : '');
        setCriticalIncidents(Number.isFinite(stats.critical_incidents) ? stats.critical_incidents : null);
        setStatsUpdatedAt(new Date());
      } catch {
        if (mounted.current) {
          setSystemStatus('');
          setCriticalIncidents(null);
        }
      } finally {
        requestInFlight.current = false;
      }
    };

    refreshStats();
    const timer = window.setInterval(refreshStats, 30000);
    const onVisibilityChange = () => { if (!document.hidden) refreshStats(); };
    document.addEventListener('visibilitychange', onVisibilityChange);
    return () => {
      mounted.current = false;
      window.clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisibilityChange);
    };
  }, []);

  useEffect(() => {
    if (!mobileOpen) return undefined;
    const onKeyDown = (event) => { if (event.key === 'Escape') setMobileOpen(false); };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [mobileOpen]);

  useEffect(() => {
    const toggle = () => setCollapsed((value) => !value);
    window.addEventListener('cyberguardx-toggle-sidebar', toggle);
    return () => window.removeEventListener('cyberguardx-toggle-sidebar', toggle);
  }, []);

  const visibleItems = navItems.filter((item) => role !== 'viewer' || item.id !== 'assistant');
  const itemsById = new Map(visibleItems.map((item) => [item.id, item]));

  const onNavKeyDown = (event) => {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) return;
    const buttons = [...event.currentTarget.querySelectorAll('[data-nav-item="true"]')];
    const currentIndex = buttons.indexOf(document.activeElement);
    if (!buttons.length) return;
    event.preventDefault();
    if (event.key === 'Home') buttons[0].focus();
    else if (event.key === 'End') buttons.at(-1).focus();
    else if (currentIndex < 0) buttons[event.key === 'ArrowDown' ? 0 : buttons.length - 1].focus();
    else buttons[(currentIndex + (event.key === 'ArrowDown' ? 1 : -1) + buttons.length) % buttons.length].focus();
  };

  const toggleCollapsed = () => setCollapsed((value) => !value);
  const mobile = window.matchMedia('(max-width: 767px)').matches;
  const iconRail = collapsed && !mobileOpen;
  const navContent = <nav id="soc-sidebar-nav" aria-label="Primary navigation" onKeyDown={onNavKeyDown} className="min-h-0 flex-1 overflow-y-auto px-2 pb-3 pt-4 xl:px-3">
    <span className="sr-only" aria-live="polite" aria-atomic="true">{liveEventsCount > 0 ? `${liveEventsCount} new live events` : ''}</span>
    {sections.map((section) => {
      const items = section.ids.map((id) => itemsById.get(id)).filter(Boolean);
      if (!items.length) return null;
      return <div key={section.title} className="mb-5">
        {!iconRail && <h2 className="mb-2 px-3 text-[9px] font-bold uppercase tracking-[0.18em] text-slate-500">{section.title}</h2>}
        <div className="space-y-1">
          {items.map(({ id, label, fullLabel, icon: Icon }) => {
            const isActive = activePage === id;
            const badgeCount = id === 'live' ? liveEventsCount : id === 'incidents' ? criticalIncidents : null;
            return <button
              key={id}
              type="button"
              data-nav-item="true"
              onClick={() => { setActivePage(id); setMobileOpen(false); }}
              aria-label={fullLabel}
              aria-current={isActive ? 'page' : undefined}
              title={iconRail ? fullLabel : undefined}
              className={`group relative flex w-full items-center gap-3 rounded-xl border-l-[3px] px-2.5 py-2.5 text-left text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/80 ${iconRail ? 'justify-center' : ''} ${isActive ? 'border-blue-400 bg-blue-400/[0.09] text-slate-100' : 'border-transparent text-slate-400 hover:bg-white/[0.045] hover:text-slate-100'}`}
            >
              <Icon aria-hidden="true" className={`h-4 w-4 shrink-0 ${isActive ? 'text-blue-200' : 'text-slate-400'}`} />
              {!iconRail && <span className="min-w-0 flex-1 truncate">{label}</span>}
              {badgeCount != null && badgeCount > 0 && <span aria-live={id === 'live' ? 'polite' : undefined} aria-atomic={id === 'live' ? 'true' : undefined} aria-label={id === 'live' ? `${badgeCount} new events` : `${badgeCount} critical incidents`} className={`${iconRail ? 'absolute -right-1 -top-1' : 'ml-auto'} min-w-5 rounded-full border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-center font-mono text-[9px] font-bold text-slate-200`}>
                {badgeCount > 99 ? '99+' : badgeCount}
              </span>}
              {iconRail && <span role="tooltip" className="pointer-events-none absolute left-full top-1/2 z-[60] ml-2 -translate-y-1/2 whitespace-nowrap rounded-lg border border-white/10 bg-slate-950 px-2.5 py-1.5 text-[10px] text-slate-100 opacity-0 shadow-xl transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">{fullLabel}</span>}
            </button>;
          })}
        </div>
      </div>;
    })}
  </nav>;

  return <>
    {mobile && !mobileOpen && <button type="button" onClick={() => setMobileOpen(true)} aria-label="Open navigation" aria-expanded="false" className="fixed left-3 top-3 z-50 flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-slate-900 text-slate-200 shadow-xl md:hidden"><Menu className="h-5 w-5" /></button>}
    {mobileOpen && <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation" className="fixed inset-0 z-40 bg-black/60 md:hidden" />}
    <aside aria-label="CyberGuard X sidebar" className={`z-50 flex h-full shrink-0 flex-col border-r border-white/[0.07] bg-[#0d1527] transition-[width,transform] duration-200 ${mobile ? `fixed inset-y-0 left-0 w-64 ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}` : collapsed ? 'w-16' : 'w-64'}`}>
      <div className={`flex h-16 shrink-0 items-center gap-3 border-b border-white/[0.07] px-3 ${collapsed && !mobileOpen ? 'justify-center' : ''}`}>
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-blue-400/25 bg-blue-400/10 text-blue-200"><Layers aria-hidden="true" className="h-4 w-4" /></div>
        {(!collapsed || mobileOpen) && <div className="min-w-0 flex-1"><h1 className="font-display text-sm font-bold tracking-wide text-slate-100">CyberGuard X</h1><p className="font-mono text-[9px] uppercase tracking-[0.14em] text-blue-300">Enterprise SOC</p></div>}
        {mobile && <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation" className="rounded-lg p-2 text-slate-400 hover:bg-white/5 hover:text-white"><X className="h-4 w-4" /></button>}
      </div>

      {navContent}

      <div className={`shrink-0 border-t border-white/[0.07] p-2 ${collapsed && !mobileOpen ? 'items-center' : ''}`}>
        {(!collapsed || mobileOpen) ? <>
          <div className="mb-2 rounded-xl bg-slate-950/35 p-2.5 text-[10px]">
            <div className="flex items-center justify-between gap-2"><span className="text-slate-400">Engine</span><span className="max-w-28 truncate font-mono text-slate-200">{systemStatus || '—'}</span></div>
            <div className="mt-1.5 flex items-center justify-between gap-2"><span className="text-slate-400">WebSocket</span><span className={`font-mono ${wsConnected ? 'text-emerald-300' : 'text-amber-200'}`}>{wsConnected ? 'Connected' : 'Polling'}</span></div>
            <div className="mt-1.5 flex items-center justify-between gap-2"><span className="text-slate-400">Last updated</span><span className="font-mono text-slate-300">{formatUpdatedAt(statsUpdatedAt)}</span></div>
          </div>
          <div className="flex items-center gap-2 rounded-xl px-1.5 py-1.5">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-blue-400/25 bg-blue-400/10 text-[10px] font-bold text-blue-100">{(analyst?.username || 'A').slice(0, 2).toUpperCase()}</div>
            <div className="min-w-0 flex-1"><p className="truncate text-[11px] font-semibold text-slate-200">{analyst?.username || 'Analyst'}</p><p className="font-mono text-[9px] uppercase text-slate-400">{analyst?.role || role || 'viewer'}</p></div>
            <button type="button" onClick={onLogout} aria-label="Log out" title="Log out" className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"><LogOut className="h-4 w-4" /></button>
          </div>
        </> : <div className="flex flex-col items-center gap-2 py-2">
          <span role="status" aria-label={systemStatus ? `Engine ${systemStatus}` : 'Engine status unavailable'} title={systemStatus ? `Engine ${systemStatus}` : 'Engine status unavailable'} className={`h-2 w-2 rounded-full ${systemStatus.toLowerCase() === 'operational' ? 'bg-emerald-400' : 'bg-slate-500'}`} />
          <span aria-label={wsConnected ? 'WebSocket connected' : 'WebSocket polling'} title={wsConnected ? 'WebSocket connected' : 'WebSocket polling'} className={`h-2 w-2 rounded-full ${wsConnected ? 'bg-emerald-400' : 'bg-amber-300'}`} />
          <span aria-label={`Last stats update ${formatUpdatedAt(statsUpdatedAt)}`} title={`Last stats update ${formatUpdatedAt(statsUpdatedAt)}`}><Clock3 className="h-3.5 w-3.5 text-slate-500" /></span>
          <button type="button" onClick={onLogout} aria-label="Log out" title="Log out" className="rounded-lg p-2 text-slate-400 hover:bg-white/5 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"><LogOut className="h-4 w-4" /></button>
        </div>}
        {!mobile && <button type="button" onClick={toggleCollapsed} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} aria-expanded={!collapsed} aria-controls="soc-sidebar-nav" title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} className={`mt-1 flex w-full items-center rounded-lg p-2 text-slate-500 transition-colors hover:bg-white/5 hover:text-slate-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${collapsed ? 'justify-center' : 'justify-end'}`}>
          {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
        </button>}
      </div>
    </aside>
  </>;
}
