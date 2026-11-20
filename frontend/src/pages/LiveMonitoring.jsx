import React, { useState, useEffect, useMemo, useRef } from 'react';
import { Radar, Filter, Search, ShieldAlert, AlertTriangle, CheckCircle, RefreshCw } from 'lucide-react';
import { api } from '../services/api';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';

export default function LiveMonitoring({ liveEvents }) {
  const [initialEvents, setInitialEvents] = useState([]);
  const [selectedCategory, setSelectedCategory] = useState('all');
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const seenLiveId = useRef(null);
  const streamRef = useRef(null);

  useGSAP(() => createMotionScope(streamRef.current, (reduced) => {
    const newestId = liveEvents[0]?.event_id;
    if (!newestId || newestId === seenLiveId.current) return;
    seenLiveId.current = newestId;
    const row = streamRef.current?.querySelector(`[data-live-id="${CSS.escape(String(newestId))}"]`);
    if (row) gsap.fromTo(row, { autoAlpha: 0, y: reduced ? 0 : -8 }, { autoAlpha: 1, y: 0, duration: reduced ? 0.18 : motion.duration.base, ease: motion.ease });
  }), { scope: streamRef, dependencies: [liveEvents], revertOnUpdate: true });

  useEffect(() => {
    async function loadInitial() {
      try {
        const events = await api.getEvents('', 100);
        setInitialEvents(events);
      } catch (err) {
        console.error('Failed to load initial events:', err);
      } finally {
        setLoading(false);
      }
    }
    loadInitial();
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

  return (
    <div className="space-y-6">
      {/* Top Controls Bar */}
      <div className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-4 flex flex-wrap items-center justify-between gap-4">
        <div className="flex items-center gap-2">
          {['all', 'auth', 'endpoint', 'network', 'access'].map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold uppercase tracking-wider transition-all ${
                selectedCategory === cat
                  ? 'bg-blue-600 text-white shadow-md shadow-blue-600/30'
                  : 'bg-[#0D1527] text-slate-400 hover:text-slate-200 border border-[#1E293B]'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>

        <div className="relative w-72">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            aria-label="Search user, device, IP, type"
            placeholder="Search user, device, IP, type..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#0D1527] border border-[#1E293B] text-slate-200 text-xs rounded-xl pl-9 pr-3 py-2 focus:outline-none focus:border-blue-500"
          />
        </div>
      </div>

      {/* Live Stream Table */}
      <div ref={streamRef} className="bg-[#10182E] border border-[#1E293B] rounded-2xl p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <div className="w-2.5 h-2.5 rounded-full bg-emerald-400 animate-ping"></div>
            <h3 className="text-sm font-bold text-slate-200">Continuous Security Telemetry Stream</h3>
          </div>
          <span className="text-xs font-mono text-slate-400">
            Displaying {filteredEvents.length} events
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#1E293B] text-slate-400 font-semibold uppercase tracking-wider">
                <th className="pb-3">Timestamp</th>
                <th className="pb-3">User / Identity</th>
                <th className="pb-3">Device / Host</th>
                <th className="pb-3">Network IP</th>
                <th className="pb-3">Event Type</th>
                <th className="pb-3">Layer</th>
                <th className="pb-3">Dataset</th>
                <th className="pb-3">Status</th>
              </tr>
            </thead>
            <tbody aria-live="polite" aria-relevant="additions" aria-atomic="false" className="divide-y divide-[#1E293B]/60 text-slate-300 font-mono">
              {filteredEvents.map((ev, idx) => {
                const cat = ev.event_category || ev.category || 'endpoint';
                const status = ev.status || 'success';
                const isFailed = status === 'failure' || status === 'blocked';
                return (
                  <tr key={ev.event_id || idx} data-live-id={liveEvents.includes(ev) ? ev.event_id : undefined} className="hover:bg-[#131D38]/50 transition-colors">
                    <td className="py-2.5 text-slate-500">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </td>
                    <td className="py-2.5 font-medium text-slate-200">
                      {ev.user_id || '—'}
                    </td>
                    <td className="py-2.5 text-slate-300">{ev.device_id || '—'}</td>
                    <td className="py-2.5 text-slate-400">
                      {ev.source_ip || '—'} → {ev.destination_ip || '—'}
                    </td>
                    <td className="py-2.5 font-sans font-medium text-slate-200">
                      {ev.event_type}
                    </td>
                    <td className="py-2.5">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-[#0D1527] border border-[#1E293B] text-slate-300">
                        {cat}
                      </span>
                    </td>
                    <td className="py-2.5 text-slate-400">{ev.dataset || '—'}</td>
                    <td className="py-2.5">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          isFailed
                            ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40'
                            : 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40'
                        }`}
                      >
                        {status.toUpperCase()}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

