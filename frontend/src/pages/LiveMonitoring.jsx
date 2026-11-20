import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Activity, Check, Copy, Filter, Search, ShieldAlert, X } from 'lucide-react';
import { api } from '../services/api';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';
import Badge from '../components/ui/Badge';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import Modal from '../components/ui/Modal';
import Skeleton from '../components/ui/Skeleton';

const CATEGORIES = ['all', 'auth', 'endpoint', 'network', 'access'];

function displayField(value) {
  if (value === null) return 'null';
  if (value === undefined) return 'undefined';
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
}

function statusTone(status) {
  const normalized = String(status || '').toLowerCase();
  if (normalized === 'success') return 'normal';
  if (normalized === 'failure') return 'critical';
  if (normalized === 'blocked' || normalized === 'denied') return 'high';
  if (normalized === 'pending' || normalized === 'review') return 'medium';
  return 'neutral';
}

function isBlank(value) {
  return value == null || value === '' || value === '—' || value === '-';
}

export default function LiveMonitoring({ liveEvents }) {
  const [initialEvents, setInitialEvents] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [copiedField, setCopiedField] = useState('');
  const pageRef = useRef(null);
  const seenLiveId = useRef(null);
  const streamRef = useRef(null);
  const filterControlRef = useRef(null);
  const searchRef = useRef(null);
  const drawerContentRef = useRef(null);
  const copyResetTimer = useRef(null);

  useGSAP(() => createMotionScope(pageRef.current, (reduced) => {
    gsap.fromTo('.live-entrance', { autoAlpha: 0, y: reduced ? 0 : 12 }, {
      autoAlpha: 1,
      y: 0,
      duration: reduced ? 0.18 : 0.48,
      stagger: reduced ? 0 : 0.06,
      ease: motion.ease,
      clearProps: 'transform,visibility',
    });
  }), { scope: pageRef, dependencies: [], revertOnUpdate: false });

  useGSAP(() => createMotionScope(streamRef.current, (reduced) => {
    const newestId = liveEvents[0]?.event_id;
    if (!newestId || newestId === seenLiveId.current) return;
    seenLiveId.current = newestId;
    const row = Array.from(streamRef.current?.querySelectorAll('[data-live-id]') || [])
      .find((item) => item.dataset.liveId === String(newestId));
    if (!row) return;
    gsap.fromTo(row, { autoAlpha: 0, y: reduced ? 0 : -8 }, {
      autoAlpha: 1,
      y: 0,
      duration: reduced ? 0.18 : motion.duration.base,
      ease: motion.ease,
      clearProps: 'transform,visibility',
    });
    const flash = row.querySelectorAll('[data-live-flash]');
    if (flash.length) gsap.fromTo(flash, { opacity: 0.8 }, { opacity: 0, duration: reduced ? 0.18 : 1, ease: 'power2.out' });
  }), { scope: streamRef, dependencies: [liveEvents], revertOnUpdate: true });

  useEffect(() => {
    async function loadInitial() {
      try {
        const events = await api.getEvents('', 100);
        setInitialEvents(events);
        setLoadError(false);
      } catch (err) {
        console.error('Failed to load initial events:', err);
        setLoadError(true);
      } finally {
        setLoading(false);
      }
    }
    loadInitial();
  }, []);

  useEffect(() => () => window.clearTimeout(copyResetTimer.current), []);

  useEffect(() => {
    function focusSearch(event) {
      const target = event.target;
      const editing = target instanceof HTMLElement && (
        target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)
      );
      if (event.key === '/' && !event.metaKey && !event.ctrlKey && !event.altKey && !editing) {
        event.preventDefault();
        searchRef.current?.focus();
      }
    }
    window.addEventListener('keydown', focusSearch);
    return () => window.removeEventListener('keydown', focusSearch);
  }, []);

  // Merge live WebSocket events with initial historical events
  const allEvents = useMemo(() => {
    const map = new Map();
    // Prioritize live events at the top
    liveEvents.forEach((ev) => map.set(ev.event_id, ev));
    initialEvents.forEach((ev) => {
      if (!map.has(ev.event_id)) map.set(ev.event_id, ev);
    });
    return Array.from(map.values());
  }, [liveEvents, initialEvents]);

  // Filter & Search
  const filteredEvents = useMemo(() => {
    return allEvents.filter((ev) => {
      const matchCat = selectedCategory === 'all' || (ev.event_category || ev.category) === selectedCategory;
      const q = searchQuery.toLowerCase();
      const matchSearch =
        !q ||
        (ev.user_id && ev.user_id.toLowerCase().includes(q)) ||
        (ev.device_id && ev.device_id.toLowerCase().includes(q)) ||
        (ev.source_ip && ev.source_ip.toLowerCase().includes(q)) ||
        (ev.event_type && ev.event_type.toLowerCase().includes(q));
      return matchCat && matchSearch;
    });
  }, [allEvents, selectedCategory, searchQuery]);

  const filterCounts = useMemo(() => Object.fromEntries(CATEGORIES.map((category) => [
    category,
    category === 'all'
      ? allEvents.length
      : allEvents.filter((ev) => (ev.event_category || ev.category) === category).length,
  ])), [allEvents]);

  const selectedFilterIndex = Math.max(0, CATEGORIES.indexOf(selectedCategory));

  useGSAP(() => createMotionScope(drawerContentRef.current, (reduced) => {
    if (!drawerContentRef.current) return;
    gsap.fromTo(drawerContentRef.current, { autoAlpha: 0, x: reduced ? 0 : 14 }, {
      autoAlpha: 1,
      x: 0,
      duration: reduced ? 0.16 : 0.24,
      ease: motion.ease,
      clearProps: 'transform,visibility',
    });
  }), { scope: drawerContentRef, dependencies: [selectedEvent], revertOnUpdate: true });

  const copyField = async (field, value) => {
    try {
      await navigator.clipboard.writeText(displayField(value));
      setCopiedField(field);
      window.clearTimeout(copyResetTimer.current);
      copyResetTimer.current = window.setTimeout(() => setCopiedField((current) => current === field ? '' : current), 1400);
    } catch (error) {
      console.warn('Unable to copy event field:', error);
      setCopiedField('');
    }
  };

  const openEvent = (event) => {
    setSelectedEvent(event);
    setCopiedField('');
  };

  return (
    <div ref={pageRef} className="mx-auto w-full max-w-[1600px] space-y-6">
      <Card className="live-entrance flex flex-wrap items-center justify-between gap-4 p-4 sm:p-5">
        <div className="relative w-full min-w-0 flex-1 sm:w-auto sm:min-w-[15rem] sm:max-w-md">
          <Search aria-hidden="true" className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
          <input
            ref={searchRef}
            type="text"
            aria-label="Search user, device, IP, type"
            placeholder="Search user, device, IP, type..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full rounded-xl border border-white/[0.09] bg-slate-950/45 py-2.5 pl-10 pr-20 text-xs text-slate-100 placeholder:text-slate-400 transition focus:border-blue-400/60 focus:outline-none focus:ring-2 focus:ring-blue-400/25"
          />
          {searchQuery ? (
            <button type="button" aria-label="Clear search" onClick={() => setSearchQuery('')} className="absolute right-2 top-1/2 inline-flex h-7 w-7 -translate-y-1/2 items-center justify-center rounded-lg text-slate-400 transition hover:bg-white/[0.07] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">
              <X aria-hidden="true" className="h-3.5 w-3.5" />
            </button>
          ) : (
            <kbd aria-hidden="true" className="pointer-events-none absolute right-3 top-1/2 -translate-y-1/2 rounded border border-white/10 bg-white/[0.04] px-1.5 py-0.5 font-mono text-[11px] text-slate-400">/</kbd>
          )}
        </div>

        <div className="flex w-full items-center gap-3 sm:w-auto sm:flex-1 sm:justify-end">
          <div ref={filterControlRef} role="group" aria-label="Filter events by layer" className="relative flex min-w-0 flex-1 rounded-xl border border-white/[0.08] bg-slate-950/45 p-1 sm:flex-none">
            <span aria-hidden="true" style={{ width: 'calc((100% - 0.5rem) / 5)', transform: `translateX(${selectedFilterIndex * 100}%)` }} className="pointer-events-none absolute bottom-1 left-1 top-1 rounded-lg border border-blue-300/20 bg-gradient-to-r from-blue-500 to-violet-500 shadow-[0_4px_18px_rgba(61,126,255,0.24)] transition-transform duration-200" />
            {CATEGORIES.map((cat) => (
              <button
                key={cat}
                type="button"
                aria-pressed={selectedCategory === cat}
                onClick={() => setSelectedCategory(cat)}
                className={`relative z-[1] inline-flex min-w-0 flex-1 items-center justify-center gap-1.5 rounded-lg px-2.5 py-2 text-[11px] font-semibold uppercase tracking-wider transition-colors sm:flex-none sm:px-3 ${selectedCategory === cat ? 'text-white' : 'text-slate-400 hover:text-slate-100'}`}
              >
                <span>{cat}</span>
                <span className={`soc-mono text-[11px] ${selectedCategory === cat ? 'text-white/90' : 'text-slate-500'}`}>{filterCounts[cat]}</span>
              </button>
            ))}
          </div>
        </div>
      </Card>

      <Card className="live-entrance overflow-hidden p-0">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/[0.07] px-5 py-4 sm:px-6">
          <div className="flex items-center gap-3">
            <span className="relative flex h-2.5 w-2.5" aria-hidden="true">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-300/50 [animation-duration:2.4s]" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-emerald-300 shadow-[0_0_12px_rgba(52,211,153,.45)]" />
            </span>
            <div>
              <h2 className="text-sm font-semibold text-slate-100">Continuous Security Telemetry Stream</h2>
              <span className="mt-1 inline-flex items-center gap-1.5 text-[11px] font-semibold tracking-[0.12em] text-emerald-200">
                <Activity aria-hidden="true" className="h-3 w-3" /> LIVE
              </span>
            </div>
          </div>
          <span className="inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.035] px-3 py-1.5 text-[11px] text-slate-300">
            Displaying <span className="font-mono font-semibold tabular-nums text-slate-100">{filteredEvents.length}</span> events
          </span>
        </div>

        <div ref={streamRef} className="max-h-[min(70vh,52rem)] overflow-auto">
          {loadError && allEvents.length > 0 && <p role="status" className="border-b border-amber-400/15 bg-amber-400/[0.045] px-5 py-2.5 text-xs text-amber-100 sm:px-6">Historical events could not be loaded. Live events will continue to appear here.</p>}
          <table className="w-full min-w-[1050px] text-left text-xs">
            <thead className="sticky top-0 z-20 border-b border-white/[0.07] bg-[var(--soc-panel)] text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-400 shadow-[0_1px_0_rgba(255,255,255,.06)]">
              <tr>
                <th scope="col" className="px-4 py-3">Timestamp</th>
                <th scope="col" className="px-4 py-3">User / Identity</th>
                <th scope="col" className="px-4 py-3">Device / Host</th>
                <th scope="col" className="px-4 py-3">Network IP</th>
                <th scope="col" className="px-4 py-3">Event Type</th>
                <th scope="col" className="px-4 py-3">Layer</th>
                <th scope="col" className="px-4 py-3">Dataset</th>
                <th scope="col" className="px-4 py-3">Status</th>
              </tr>
            </thead>
            <tbody aria-live="polite" aria-relevant="additions" aria-atomic="false" className="divide-y divide-white/[0.05] text-slate-300">
              {filteredEvents.length === 0 && loading && allEvents.length === 0 ? (
                <tr role="status" aria-label="Loading events">
                  <td colSpan={8} className="px-4 py-5">
                    <div className="space-y-3" aria-hidden="true">
                      {Array.from({ length: 4 }, (_, index) => <Skeleton key={index} className="h-8 w-full" />)}
                    </div>
                    <span className="sr-only">Loading security events...</span>
                  </td>
                </tr>
              ) : filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="px-4 py-7">
                    <EmptyState
                      icon={loadError && allEvents.length === 0 ? ShieldAlert : allEvents.length === 0 ? Activity : Filter}
                      title={loadError && allEvents.length === 0 ? 'Historical events unavailable' : allEvents.length === 0 ? 'No security events yet' : 'No events match these filters'}
                      description={loadError && allEvents.length === 0 ? 'Live events will appear here when received.' : allEvents.length === 0 ? 'Events will appear here when they are received.' : 'Try another layer or clear the search to see more events.'}
                      className="min-h-28 border-0 bg-transparent py-4"
                    />
                  </td>
                </tr>
              ) : filteredEvents.map((ev, idx) => {
                const cat = ev.event_category || ev.category || 'endpoint';
                const status = ev.status || 'success';
                const normalizedStatus = String(status).toLowerCase();
                const failed = normalizedStatus === 'failure' || normalizedStatus === 'blocked' || normalizedStatus === 'denied';
                const timestamp = ev.timestamp ? new Date(ev.timestamp) : null;
                const validTimestamp = timestamp && !Number.isNaN(timestamp.getTime());
                const isLive = liveEvents.includes(ev);
                const dateLabel = validTimestamp ? timestamp.toLocaleString() : 'Timestamp unavailable';
                const eventLabel = ev.event_type || 'Event';
                const rowLabel = `${eventLabel} · ${ev.user_id || '—'} · ${dateLabel}`;
                return (
                  <tr
                    key={ev.event_id || idx}
                    data-live-id={isLive ? ev.event_id : undefined}
                    tabIndex={0}
                    aria-label={`View event details: ${rowLabel}`}
                    aria-haspopup="dialog"
                    onClick={() => openEvent(ev)}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        openEvent(ev);
                      }
                    }}
                    className="group cursor-pointer transition-colors duration-150 hover:bg-white/[0.035] focus-visible:outline focus-visible:outline-2 focus-visible:outline-inset focus-visible:outline-blue-400"
                  >
                    <td className="relative whitespace-nowrap px-4 py-3">
                      <span aria-hidden="true" className={`absolute inset-y-0 left-0 w-[3px] ${failed ? 'bg-rose-400/80' : normalizedStatus === 'success' ? 'bg-emerald-400/65' : 'bg-transparent'}`} />
                      {isLive && <span data-live-flash aria-hidden="true" className={`pointer-events-none absolute inset-0 opacity-0 ${failed ? 'bg-rose-400/10' : 'bg-emerald-400/[0.08]'}`} />}
                      <time className="relative z-[1] soc-mono text-slate-400" dateTime={validTimestamp ? timestamp.toISOString() : undefined} title={dateLabel}>
                        {validTimestamp ? timestamp.toLocaleTimeString() : 'Timestamp unavailable'}
                      </time>
                    </td>
                    <td className="relative whitespace-nowrap px-4 py-3 font-medium">
                      {isLive && <span data-live-flash aria-hidden="true" className={`pointer-events-none absolute inset-0 opacity-0 ${failed ? 'bg-rose-400/10' : 'bg-emerald-400/[0.08]'}`} />}
                      <span className={`relative z-[1] ${isBlank(ev.user_id) ? 'text-slate-500' : 'text-slate-200'}`}>{ev.user_id || '—'}</span>
                    </td>
                    <td className="relative whitespace-nowrap px-4 py-3">
                      {isLive && <span data-live-flash aria-hidden="true" className={`pointer-events-none absolute inset-0 opacity-0 ${failed ? 'bg-rose-400/10' : 'bg-emerald-400/[0.08]'}`} />}
                      <span className={`relative z-[1] ${isBlank(ev.device_id) ? 'text-slate-500' : 'text-slate-300'}`}>{ev.device_id || '—'}</span>
                    </td>
                    <td className="relative whitespace-nowrap px-4 py-3">
                      {isLive && <span data-live-flash aria-hidden="true" className={`pointer-events-none absolute inset-0 opacity-0 ${failed ? 'bg-rose-400/10' : 'bg-emerald-400/[0.08]'}`} />}
                      <span className="relative z-[1] soc-mono">
                        <span className={isBlank(ev.source_ip) ? 'text-slate-500' : 'text-slate-300'}>{ev.source_ip || '—'}</span>
                        <span className="px-1.5 text-slate-600">→</span>
                        <span className={isBlank(ev.destination_ip) ? 'text-slate-500' : 'text-slate-300'}>{ev.destination_ip || '—'}</span>
                      </span>
                    </td>
                    <td className="relative whitespace-nowrap px-4 py-3 font-sans font-medium">
                      {isLive && <span data-live-flash aria-hidden="true" className={`pointer-events-none absolute inset-0 opacity-0 ${failed ? 'bg-rose-400/10' : 'bg-emerald-400/[0.08]'}`} />}
                      <span className={`relative z-[1] ${isBlank(ev.event_type) ? 'text-slate-500' : 'text-slate-200'}`}>{ev.event_type || '—'}</span>
                    </td>
                    <td className="relative whitespace-nowrap px-4 py-3">
                      {isLive && <span data-live-flash aria-hidden="true" className={`pointer-events-none absolute inset-0 opacity-0 ${failed ? 'bg-rose-400/10' : 'bg-emerald-400/[0.08]'}`} />}
                      <Badge tone="low" className="relative z-[1] px-2 py-1 text-[11px] font-mono uppercase">{cat}</Badge>
                    </td>
                    <td className="relative whitespace-nowrap px-4 py-3">
                      {isLive && <span data-live-flash aria-hidden="true" className={`pointer-events-none absolute inset-0 opacity-0 ${failed ? 'bg-rose-400/10' : 'bg-emerald-400/[0.08]'}`} />}
                      <span className={`relative z-[1] ${isBlank(ev.dataset) ? 'text-slate-500' : 'text-slate-400'}`}>{ev.dataset || '—'}</span>
                    </td>
                    <td className="relative whitespace-nowrap px-4 py-3">
                      {isLive && <span data-live-flash aria-hidden="true" className={`pointer-events-none absolute inset-0 opacity-0 ${failed ? 'bg-rose-400/10' : 'bg-emerald-400/[0.08]'}`} />}
                      <Badge tone={statusTone(status)} className="relative z-[1] px-2 py-1 font-mono">{String(status).toUpperCase()}</Badge>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>

      <Modal open={!!selectedEvent} onClose={() => setSelectedEvent(null)} title="Event details" side className="max-w-xl rounded-r-none p-0">
        {selectedEvent && (
          <div ref={drawerContentRef} className="flex max-h-full flex-col">
            <header className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-white/[0.08] bg-[var(--soc-panel)]/95 px-5 py-4 backdrop-blur-xl sm:px-6">
              <div className="min-w-0">
                <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-blue-200">Read-only event record</p>
                <h2 className="mt-1 break-all font-[family-name:var(--soc-font-display)] text-lg font-semibold text-slate-100">{selectedEvent.event_type || 'Event details'}</h2>
                {selectedEvent.event_id && <p className="mt-1 break-all font-mono text-[11px] text-slate-400">{selectedEvent.event_id}</p>}
              </div>
              <button type="button" aria-label="Close event details" onClick={() => setSelectedEvent(null)} className="inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-xl border border-white/[0.08] bg-white/[0.03] text-slate-300 transition hover:bg-white/[0.08] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">
                <X aria-hidden="true" className="h-4 w-4" />
              </button>
            </header>
            <div className="min-h-0 flex-1 space-y-3 overflow-y-auto p-5 sm:p-6">
              {Object.entries(selectedEvent).map(([field, value]) => {
                const copied = copiedField === field;
                return (
                  <div key={field} className="rounded-xl border border-white/[0.07] bg-slate-950/30 p-3.5">
                    <div className="mb-2 flex items-center justify-between gap-3">
                      <span className="text-[11px] font-semibold uppercase tracking-[0.1em] text-slate-400">{field.replace(/_/g, ' ')}</span>
                      <button type="button" onClick={() => copyField(field, value)} aria-label={`${copied ? 'Copied' : 'Copy'} ${field}`} className="inline-flex items-center gap-1.5 rounded-md px-2 py-1 text-[11px] text-slate-400 transition hover:bg-white/[0.06] hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">
                        {copied ? <Check aria-hidden="true" className="h-3.5 w-3.5 text-emerald-300" /> : <Copy aria-hidden="true" className="h-3.5 w-3.5" />}
                        {copied ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-slate-200">{displayField(value)}</pre>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
}
