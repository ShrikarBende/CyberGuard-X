import React, { lazy, Suspense, useEffect, useMemo, useRef, useState } from 'react';
import { Accessibility, Bell, Radio, Search } from '../lib/icons';

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

  const toggleMotion = () => {
    const next = !reduceMotion;
    setReduceMotion(next);
    window.localStorage.setItem('cyberguardx_reduce_motion', String(next));
    document.documentElement.classList.toggle('motion-reduced', next);
    document.documentElement.classList.toggle('motion-full', !next);
    window.dispatchEvent(new Event('cyberguardx-motion-change'));
  };

  return (
    <header className="soc-header flex min-h-[72px] shrink-0 flex-wrap items-center justify-between gap-3 border-b px-4 py-3 md:px-6">
      <div className="min-w-0 flex-1 basis-full pl-12 sm:basis-auto sm:pl-0">
        <p className="soc-mono caption-3 uppercase tracking-wide text-slate-500">CyberGuard X <span className="px-1.5 text-slate-600">/</span> Security operations</p>
        <h1 className="heading-6 mt-1 text-slate-100">{pageTitle}</h1>
      </div>

      <div className="flex w-full items-center justify-end gap-2 sm:w-auto sm:gap-4">
        <button type="button" onClick={toggleMotion} aria-pressed={reduceMotion} aria-label={reduceMotion ? 'Enable motion' : 'Reduce motion'} title={reduceMotion ? 'Enable motion' : 'Reduce motion'} className="button-sm inline-flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-slate-300 transition-colors duration-300 hover:bg-white/5">
          <Accessibility className="h-3.5 w-3.5" /><span className="hidden lg:inline">Reduce motion</span>
        </button>
        <button type="button" onClick={() => setCommandPaletteOpen(true)} aria-label="Search pages and incidents" title="Search pages and incidents (Ctrl/Cmd+K)" className="button-sm inline-flex items-center gap-2 rounded-lg border border-white/10 bg-white/[0.025] px-3 py-2 text-slate-300 transition-colors duration-300 hover:bg-white/[0.06] sm:px-3">
          <Search className="h-3.5 w-3.5" /><span className="hidden sm:inline">Search</span><kbd className="hidden rounded border border-white/10 px-1.5 py-0.5 font-mono text-[9px] text-slate-500 sm:inline">Ctrl/⌘ K</kbd>
        </button>
        <div className="relative">
          <button type="button" onClick={() => { const next = !notificationsOpen; setNotificationsOpen(next); if (next) { setNotificationsUnread(false); notificationSeenId.current = newestHighSeverityId; } }} aria-label="Notifications" aria-expanded={notificationsOpen} aria-controls="soc-notifications" className="relative rounded-lg p-2 text-slate-300 transition-colors hover:bg-white/5 hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">
            <Bell aria-hidden="true" className="h-4 w-4" />
            {notificationsUnread && highSeverityEvents.length > 0 && <span aria-hidden="true" className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-rose-400 ring-2 ring-[#181818]" />}
          </button>
          <span className="sr-only" aria-live="polite" aria-atomic="true">{notificationsUnread ? `${highSeverityEvents.length} unread high-severity notifications` : ''}</span>
          {notificationsOpen && <>
            <button type="button" aria-label="Close notifications" onClick={() => setNotificationsOpen(false)} className="fixed inset-0 z-30 cursor-default" />
            <section id="soc-notifications" aria-label="Recent high-severity notifications" className="absolute right-0 top-full z-40 mt-2 w-[min(22rem,calc(100vw-1.5rem))] overflow-hidden rounded-2xl border border-white/10 bg-[#181818] shadow-2xl">
              <div className="flex items-center justify-between border-b border-white/[0.07] px-4 py-3"><h2 className="text-[15px] font-medium text-slate-100">Notifications</h2><span className="text-[13px] text-slate-400">High severity</span></div>
              {highSeverityEvents.length === 0 ? <p className="px-4 py-8 text-center text-[13px] text-slate-400">No recent high-severity events.</p> : <ul className="max-h-80 divide-y divide-white/[0.06] overflow-y-auto">
                {highSeverityEvents.map((event) => {
                  const severity = String(event.risk_breakdown?.fusion?.severity || '').toUpperCase();
                  return <li key={event.event_id}><button type="button" onClick={() => { setActivePage?.('live'); setNotificationsOpen(false); }} className="flex w-full items-start gap-3 px-4 py-3 text-left hover:bg-white/[0.04] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-blue-400">
                    <span className={`mt-0.5 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${severity === 'CRITICAL' ? 'border-rose-400/30 bg-rose-400/10 text-rose-200' : 'border-orange-400/30 bg-orange-400/10 text-orange-200'}`}>{severity}</span>
                    <span className="min-w-0 flex-1"><span className="block truncate text-[14px] font-normal text-slate-200">{event.event_type || 'Event details unavailable'}</span><span className="mt-1 block truncate text-[13px] text-slate-400"><span className="font-mono">{event.event_id}</span> · {event.timestamp ? new Date(event.timestamp).toLocaleTimeString() : 'Timestamp unavailable'}</span></span>
                  </button></li>;
                })}
              </ul>}
            </section>
          </>}
        </div>
        {/* WebSocket Live Status */}
        <div role="status" aria-label={wsConnected ? 'Live event stream connected' : 'Live event stream polling'} className="flex items-center gap-2 rounded-lg border border-white/10 bg-[#1F1F1F] px-3 py-2 text-sm">
          <Radio className={`w-3.5 h-3.5 ${wsConnected ? 'text-emerald-400 animate-pulse' : 'text-amber-400'}`} />
          <span className="hidden text-sm text-slate-300 sm:inline">
            {wsConnected ? 'WS stream: connected' : 'WS stream: polling'}
          </span>
        </div>

        {/* Analyst Profile */}
        <div className="flex items-center gap-2.5 pl-4 border-l border-[#313131]">
          <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-blue-500/40 bg-blue-500/20 text-xs font-semibold text-blue-200">
            {(analyst?.username || 'A').slice(0, 2).toUpperCase()}
          </div>
          <div className="hidden sm:block text-left">
            <p className="text-[13px] font-medium text-slate-200">{analyst?.username || 'Analyst'}</p>
            <p className="text-[13px] text-slate-400">{analyst?.role || 'viewer'}</p>
          </div>
        </div>
      </div>
      <Suspense fallback={null}>{paletteMounted && <CommandPalette open={commandPaletteOpen} onClose={() => setCommandPaletteOpen(false)} role={role} setActivePage={setActivePage} />}</Suspense>
    </header>
  );
}

