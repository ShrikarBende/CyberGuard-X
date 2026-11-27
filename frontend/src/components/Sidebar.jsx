import React, { useEffect, useLayoutEffect, useRef, useState } from 'react';
import {
  ShieldAlert, ShieldCheck, Activity, Radar, FileWarning, Sparkles, Bot, Database,
  BarChart3, Menu, X, LogOut, ClipboardCheck,
} from '../lib/icons';
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
  { title: 'Investigate', ids: ['threats', 'assistant', 'explain', 'agent', 'approvals'] },
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
  { id: 'agent', label: 'Agent Runs', fullLabel: 'Agent Investigation Runs', icon: Bot },
  { id: 'approvals', label: 'Approvals', fullLabel: 'Action Approvals Queue', icon: ClipboardCheck },
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
  const [mobile, setMobile] = useState(() => window.matchMedia('(max-width: 899px)').matches);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [systemStatus, setSystemStatus] = useState('');
  const [criticalIncidents, setCriticalIncidents] = useState(null);
  const [statsUpdatedAt, setStatsUpdatedAt] = useState(null);
  const navRef = useRef(null);
  const [activePill, setActivePill] = useState({ y: 0, height: 44, visible: false });
  const lastRequestAt = useRef(0);
  const requestInFlight = useRef(false);
  const mounted = useRef(false);

  useEffect(() => {
    const media = window.matchMedia('(max-width: 899px)');
    const update = () => setMobile(media.matches);
    media.addEventListener?.('change', update);
    return () => media.removeEventListener?.('change', update);
  }, []);

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

  const iconRail = false;
  useLayoutEffect(() => {
    const nav = navRef.current;
    const update = () => {
      const active = nav?.querySelector('[aria-current="page"]');
      if (!nav || !active) { setActivePill((value) => ({ ...value, visible: false })); return; }
      const navRect = nav.getBoundingClientRect();
      const itemRect = active.getBoundingClientRect();
      setActivePill({ y: itemRect.top - navRect.top + nav.scrollTop, height: itemRect.height, visible: true });
    };
    update();
    const observer = nav ? new ResizeObserver(update) : null;
    if (nav) observer.observe(nav);
    nav?.addEventListener('scroll', update);
    return () => { observer?.disconnect(); nav?.removeEventListener('scroll', update); };
  }, [activePage, mobileOpen, role]);

  const navContent = <nav ref={navRef} id="soc-sidebar-nav" aria-label="Primary navigation" onKeyDown={onNavKeyDown} className="relative min-h-0 flex-1 overflow-y-auto px-2 pb-3 pt-4 xl:px-3">
    <span className="sr-only" aria-live="polite" aria-atomic="true">{liveEventsCount > 0 ? `${liveEventsCount} new live events` : ''}</span>
    <span aria-hidden="true" className="nav-active-pill absolute left-2 right-2 z-0 rounded-full" style={{ height: activePill.height, transform: `translateY(${activePill.y}px)`, opacity: activePill.visible ? 1 : 0 }} />
    {sections.map((section) => {
      const items = section.ids.map((id) => itemsById.get(id)).filter(Boolean);
      if (!items.length) return null;
      return <div key={section.title} className="mb-5">
        <h2 className="mb-2 px-3 text-xs font-normal text-slate-400">{section.title}</h2>
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
              className={`group relative z-10 flex min-h-11 w-full items-center gap-3 rounded-full border border-transparent px-3 py-2 text-left text-sm font-medium transition-colors duration-300 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/80 ${isActive ? 'text-white' : 'text-slate-300 hover:border-white/80 hover:bg-white/45 hover:text-slate-100'}`}
            >
              <Icon aria-hidden="true" weight="regular" className={`h-5 w-5 shrink-0 ${isActive ? 'text-white' : 'text-slate-400'}`} />
              <span className="min-w-0 flex-1 truncate">{label}</span>
              {badgeCount != null && badgeCount > 0 && <span aria-live={id === 'live' ? 'polite' : undefined} aria-atomic={id === 'live' ? 'true' : undefined} aria-label={id === 'live' ? `${badgeCount} new events` : `${badgeCount} critical incidents`} className="nav-badge ml-auto min-w-5 rounded-full border border-slate-700 bg-slate-900 px-1.5 py-0.5 text-center text-xs font-semibold text-slate-200">
                {badgeCount > 99 ? '99+' : badgeCount}
              </span>}
            </button>;
          })}
        </div>
      </div>;
    })}
  </nav>;

  return <>
    {mobile && !mobileOpen && <button type="button" onClick={() => setMobileOpen(true)} aria-label="Open navigation" aria-expanded="false" className="glass fixed left-3 top-3 z-50 flex h-10 w-10 items-center justify-center rounded-xl text-[var(--ink)] shadow-xl min-[900px]:hidden"><Menu className="h-5 w-5" /></button>}
    {mobileOpen && <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation" className="fixed inset-0 z-40 bg-slate-900/20 backdrop-blur-sm min-[900px]:hidden" />}
    <aside aria-label="CyberGuard X sidebar" className={`soc-sidebar ${mobile ? 'glass--strong' : ''} z-50 flex min-h-0 shrink-0 flex-col p-2 transition-[width,transform] duration-300 ease-[cubic-bezier(.2,.8,.2,1)] ${mobile ? `fixed inset-y-3 left-3 w-64 ${mobileOpen ? 'translate-x-0' : '-translate-x-[120%]'}` : 'w-[240px]'}`}>
      <div className="flex h-16 shrink-0 items-center gap-3 px-3">
        <div className="flex h-10 w-10 shrink-0 items-center justify-center text-[var(--cobalt)]"><ShieldCheck aria-hidden="true" className="h-6 w-6" /></div>
        <div className="min-w-0 flex-1"><h1 className="font-display text-[19px] font-extrabold leading-tight text-[var(--ink)]">CyberGuard X</h1><p className="text-xs leading-4 text-[var(--muted)]">Enterprise Security Operations</p></div>
        {mobile && <button type="button" onClick={() => setMobileOpen(false)} aria-label="Close navigation" className="rounded-lg p-2 text-slate-400 hover:bg-white/5 hover:text-white"><X className="h-4 w-4" /></button>}
      </div>

      {navContent}

      <div className="shrink-0 border-t border-white/[0.08] p-2">
          <div className="mb-2 rounded-xl p-2.5 font-mono text-xs">
            <div className="flex items-center justify-between gap-2"><span className="text-slate-400">Engine</span><span className="max-w-28 truncate text-slate-200">{systemStatus || '—'}</span></div>
            <div className="mt-1.5 flex items-center justify-between gap-2"><span className="text-slate-400">WebSocket</span><span className={wsConnected ? 'text-emerald-300' : 'text-amber-200'}>{wsConnected ? 'Connected' : 'Polling'}</span></div>
            <div className="mt-1.5 flex items-center justify-between gap-2"><span className="text-slate-400">Last updated</span><span className="text-slate-300">{formatUpdatedAt(statsUpdatedAt)}</span></div>
          </div>
          <div className="flex items-center gap-2 rounded-full border border-white/[0.10] bg-white/[0.035] px-2 py-2">
            <div className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-blue-400/25 bg-blue-400/10 text-xs font-bold text-blue-100">{(analyst?.username || 'A').slice(0, 2).toUpperCase()}</div>
            <div className="min-w-0 flex-1"><p className="truncate text-xs font-semibold text-slate-200">{analyst?.username || 'Analyst'}</p><p className="text-xs text-slate-400">{analyst?.role || role || 'viewer'}</p></div>
            <button type="button" onClick={onLogout} aria-label="Log out" title="Log out" className="rounded-lg p-2 text-slate-400 transition-colors hover:bg-white/5 hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400"><LogOut className="h-4 w-4" /></button>
          </div>
      </div>
    </aside>
  </>;
}
