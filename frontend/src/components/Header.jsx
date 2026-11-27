import React, { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { Bell, Radio, Search } from '../lib/icons';

const CommandPalette = lazy(() => import('./CommandPalette'));

export default function Header({ pageTitle, wsConnected, analyst, onLogout, liveEvents = [], role, setActivePage, commandPaletteOpen = false, setCommandPaletteOpen = () => {} }) {
  const [reduceMotion, setReduceMotion] = useState(() => {
    const saved = window.localStorage.getItem('cyberguardx_reduce_motion');
    return saved === null ? window.matchMedia('(prefers-reduced-motion: reduce)').matches : saved === 'true';
  });
  const [notificationsOpen, setNotificationsOpen] = useState(false);
  const [notificationsUnread, setNotificationsUnread] = useState(false);
  const [paletteMounted, setPaletteMounted] = useState(false);
  const notificationSeenId = useRef(null);
  const highSeverityEvents = useMemo(() => liveEvents.filter((event) => {
    const severity = String(event.risk_breakdown?.fusion?.severity || '').toUpperCase();
    return severity === 'HIGH' || severity === 'CRITICAL';
  }).slice(0, 10), [liveEvents]);
  const newestHighSeverityId = highSeverityEvents[0]?.event_id || null;

  useEffect(() => {
    if (newestHighSeverityId && newestHighSeverityId !== notificationSeenId.current) {
      notificationSeenId.current = newestHighSeverityId;
      if (!notificationsOpen) setNotificationsUnread(true);
    }
  }, [newestHighSeverityId, notificationsOpen]);

  useEffect(() => {
    if (commandPaletteOpen) setPaletteMounted(true);
  }, [commandPaletteOpen]);

  useEffect(() => {
    if (!notificationsOpen) return undefined;
    const onKeyDown = (event) => { if (event.key === 'Escape') setNotificationsOpen(false); };
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [notificationsOpen]);

  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    document.documentElement.classList.toggle('motion-reduced', reduceMotion);
    document.documentElement.classList.toggle('motion-full', window.localStorage.getItem('cyberguardx_reduce_motion') === 'false');
    const onPreferenceChange = () => {
      if (window.localStorage.getItem('cyberguardx_reduce_motion') === null) setReduceMotion(media.matches);
    };
    media.addEventListener?.('change', onPreferenceChange);
    return () => media.removeEventListener?.('change', onPreferenceChange);
  }, [reduceMotion]);

  return (
    <header className="soc-header glass flex min-h-12 max-w-full flex-wrap items-center justify-between gap-2 rounded-full px-3 py-2 sm:gap-3 sm:px-4">
      <p className="soc-mono text-xs text-[var(--muted)]">CyberGuard X <span className="px-1.5 text-[var(--subtle)]">/</span> Security operations</p>

      <div className="flex min-w-0 items-center justify-end gap-1 sm:gap-2">
        <button type="button" onClick={() => setCommandPaletteOpen(true)} aria-label="Search pages and incidents" title="Search pages and incidents (Ctrl/Cmd+K)" className="button-sm inline-flex items-center gap-2 rounded-full bg-white/55 px-2.5 py-2 text-[var(--ink)] transition-colors hover:bg-white/80 sm:px-3">
          <Search className="h-4 w-4" /><span className="hidden sm:inline">Search</span><kbd className="hidden rounded-full bg-white/80 px-2 py-1 font-mono text-xs text-[var(--muted)] sm:inline">Ctrl/⌘ K</kbd>
        </button>
        <div className="relative">
          <button type="button" onClick={() => { const next = !notificationsOpen; setNotificationsOpen(next); if (next) { setNotificationsUnread(false); notificationSeenId.current = newestHighSeverityId; } }} aria-label="Notifications" aria-expanded={notificationsOpen} aria-controls="soc-notifications" className="relative rounded-lg p-2 text-slate-300 transition-colors hover:bg-white/5 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">
            <Bell aria-hidden="true" className="h-4 w-4" />
            {notificationsUnread && highSeverityEvents.length > 0 && <span aria-hidden="true" className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-rose-400 ring-2 ring-white" />}
          </button>
          <span className="sr-only" aria-live="polite" aria-atomic="true">{notificationsUnread ? `${highSeverityEvents.length} unread high-severity notifications` : ''}</span>
          {notificationsOpen && createPortal(<>
            <button type="button" aria-label="Close notifications" onClick={() => setNotificationsOpen(false)} className="fixed inset-0 z-[9998] cursor-default" />
            <section id="soc-notifications" aria-label="Recent high-severity notifications" className="soc-notification-panel fixed right-4 top-16 z-[9999] w-[min(22rem,calc(100vw-2rem))] overflow-hidden rounded-2xl">
              <div className="flex items-center justify-between border-b border-[var(--line)] px-4 py-3"><div><h2 className="text-sm font-semibold text-[var(--ink)]">Notifications</h2><p className="mt-0.5 text-xs text-[var(--muted)]">Recent high-severity events</p></div><span className="rounded-full bg-[var(--critical-tint)] px-2.5 py-1 text-xs font-semibold text-[var(--critical)]">{highSeverityEvents.length}</span></div>
              {highSeverityEvents.length === 0 ? <div className="flex flex-col items-center px-5 py-7 text-center"><span className="mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-[var(--chip)] text-[var(--muted)]"><Bell aria-hidden="true" className="h-4 w-4" /></span><p className="text-sm font-semibold text-[var(--ink)]">You’re all caught up</p><p className="mt-1 text-xs text-[var(--muted)]">No recent high-severity events.</p></div> : <ul className="max-h-80 divide-y divide-[var(--line)] overflow-y-auto">
                {highSeverityEvents.map((event) => {
                  const severity = String(event.risk_breakdown?.fusion?.severity || '').toUpperCase();
                  return <li key={event.event_id}><button type="button" onClick={() => { setActivePage?.('live'); setNotificationsOpen(false); }} className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-white/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-400">
                    <span className={`mt-0.5 rounded-full border px-2 py-0.5 text-xs font-semibold ${severity === 'CRITICAL' ? 'border-rose-400/30 bg-rose-400/10 text-rose-200' : 'border-orange-400/30 bg-orange-400/10 text-orange-200'}`}>{severity}</span>
                    <span className="min-w-0 flex-1"><span className="block truncate text-sm font-normal text-slate-200">{event.event_type || 'Event details unavailable'}</span><span className="mt-1 block truncate text-xs text-slate-400"><span className="font-mono">{event.event_id}</span> · {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'Timestamp unavailable'}</span></span>
                  </button></li>;
                })}
              </ul>}
            </section>
          </>, document.body)}
        </div>
        {/* WebSocket Live Status */}
        <div role="status" aria-label={wsConnected ? 'Live event stream connected' : 'Live event stream polling'} className="flex items-center gap-2 rounded-full bg-white/55 px-3 py-2 text-xs">
          <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-[var(--normal)]' : 'text-[var(--medium)]'}`} />
          <span className="hidden text-xs text-[var(--muted)] sm:inline">
            {wsConnected ? 'Connected' : 'Polling'}
          </span>
        </div>

        {/* Analyst Profile */}
        <div className="flex items-center gap-2 border-l border-[var(--line)] pl-2 sm:pl-3">
          <div className="flex h-8 w-8 items-center justify-center rounded-full bg-[var(--cobalt-tint)] text-xs font-semibold text-[var(--cobalt)]">
            {(analyst?.username || 'A').slice(0, 2).toUpperCase()}
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-xs font-medium text-slate-200">{analyst?.username || 'Analyst'}</p>
            <p className="text-xs text-slate-400">{analyst?.role || 'viewer'}</p>
          </div>
        </div>
      </div>
      <Suspense fallback={null}>{paletteMounted && <CommandPalette open={commandPaletteOpen} onClose={() => setCommandPaletteOpen(false)} role={role} setActivePage={setActivePage} />}</Suspense>
    </header>
  );
}

