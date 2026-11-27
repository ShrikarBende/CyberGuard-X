import React, { useEffect, useMemo, useRef, useState } from 'react';
import { ArrowDown, ArrowUp, CornerDownLeft, Search } from '../lib/icons';
import { api } from '../services/api';
import Modal from './ui/Modal';

const pages = [
  { id: 'overview', label: 'Overview Dashboard', terms: 'home executive' },
  { id: 'live', label: 'Live Feed', terms: 'live monitoring telemetry' },
  { id: 'incidents', label: 'Incident Management', terms: 'incidents cases' },
  { id: 'threats', label: 'Threat Intelligence', terms: 'threats novel' },
  { id: 'explain', label: 'Explainability', terms: 'shap risk scoring' },
  { id: 'assistant', label: 'AI Assistant', terms: 'rag chat assistant' },
  { id: 'data', label: 'Data & Models', terms: 'upload datasets governance' },
  { id: 'evaluation', label: 'Evaluation Summary', terms: 'evaluation metrics' },
];

const actions = [
  { page: 'live', label: 'Go to Live Feed' },
  { page: 'incidents', label: 'Go to Incidents' },
];

function loadIncidentText(incident) {
  return [
    incident.incident_id,
    incident.title,
    incident.severity,
    incident.status,
    ...(incident.mitre_mappings || []).flatMap((mapping) => [mapping.technique_id, mapping.technique_name, mapping.tactic]),
  ].filter(Boolean).join(' ').toLowerCase();
}

export default function CommandPalette({ open, onClose, role, setActivePage }) {
  const [query, setQuery] = useState('');
  const [incidents, setIncidents] = useState(null);
  const [loadError, setLoadError] = useState(false);
  const [loading, setLoading] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);
  const incidentCache = useRef({ data: null, fetchedAt: 0, failed: false });
  const incidentRequest = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    if (!open) return undefined;
    let active = true;
    const cached = incidentCache.current;
    if (cached.fetchedAt && Date.now() - cached.fetchedAt < 60000) {
      setIncidents(cached.data);
      setLoadError(cached.failed);
      setLoading(false);
      return () => { active = false; };
    }

    setLoading(true);
    setLoadError(false);
    if (!incidentRequest.current) {
      incidentRequest.current = api.getIncidents()
        .then((data) => {
          incidentCache.current = { data, fetchedAt: Date.now(), failed: false };
          return { data, failed: false };
        })
        .catch(() => {
          incidentCache.current = { data: [], fetchedAt: Date.now(), failed: true };
          return { data: [], failed: true };
        })
        .finally(() => { incidentRequest.current = null; });
    }
    incidentRequest.current.then((result) => {
      if (!active) return;
      setIncidents(result.data);
      setLoadError(result.failed);
      setLoading(false);
    });
    return () => { active = false; };
  }, [open]);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
      window.requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  const groups = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    const allowedPages = pages.filter((page) => role !== 'viewer' || page.id !== 'assistant');
    const pageItems = allowedPages.filter((page) => !normalized || `${page.label} ${page.terms}`.toLowerCase().includes(normalized))
      .map((page) => ({ kind: 'page', id: `page-${page.id}`, page: page.id, title: page.label, subtitle: 'Page' }));
    const incidentItems = (incidents || []).filter((incident) => !normalized || loadIncidentText(incident).includes(normalized))
      .map((incident) => ({ kind: 'incident', id: `incident-${incident.incident_id}`, page: 'incidents', title: incident.title || incident.incident_id, subtitle: `${incident.severity} · ${incident.status} · ${incident.incident_id}`, incidentId: incident.incident_id }));
    const actionItems = actions.filter((action) => !normalized || action.label.toLowerCase().includes(normalized))
      .map((action) => ({ kind: 'action', id: `action-${action.page}`, page: action.page, title: action.label, subtitle: 'Safe navigation' }));
    return [
      { title: 'Pages', items: pageItems },
      { title: 'Incidents', items: incidentItems },
      { title: 'Actions', items: actionItems },
    ].filter((group) => group.items.length);
  }, [query, incidents, role]);

  const results = useMemo(() => groups.flatMap((group) => group.items), [groups]);

  useEffect(() => { setActiveIndex((index) => Math.min(index, Math.max(results.length - 1, 0))); }, [results.length]);

  const selectResult = (result) => {
    if (!result) return;
    if (result.page === 'assistant' && role === 'viewer') return;
    setActivePage(result.page);
    onClose();
  };

  const onKeyDown = (event) => {
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (!results.length) return;
      event.preventDefault();
      const direction = event.key === 'ArrowDown' ? 1 : -1;
      setActiveIndex((index) => (index + direction + results.length) % results.length);
    } else if (event.key === 'Enter') {
      event.preventDefault();
      selectResult(results[activeIndex]);
    } else if (event.key === 'Home' && results.length) {
      event.preventDefault();
      setActiveIndex(0);
    } else if (event.key === 'End' && results.length) {
      event.preventDefault();
      setActiveIndex(results.length - 1);
    }
  };

  let resultIndex = 0;
  return <Modal open={open} onClose={onClose} title="Command palette" className="max-w-2xl overflow-hidden p-0" >
    <div onKeyDown={onKeyDown} className="overflow-hidden rounded-2xl">
      <label className="sr-only" htmlFor="soc-command-search">Search pages and incidents</label>
      <div className="flex items-center gap-3 border-b border-white/10 px-5 py-4">
        <Search aria-hidden="true" className="h-4 w-4 shrink-0 text-slate-400" />
        <input ref={inputRef} id="soc-command-search" type="text" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search pages, incidents, techniques…" aria-label="Search pages, incidents, and MITRE techniques" aria-activedescendant={results[activeIndex] ? `command-${results[activeIndex].id}` : undefined} role="combobox" aria-autocomplete="list" aria-expanded="true" aria-controls="soc-command-results" className="min-w-0 flex-1 bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500" />
        <button type="button" onClick={onClose} aria-label="Close command palette" title="Close" className="rounded-md border border-white/10 px-2 py-1 font-mono text-xs text-slate-400 hover:text-white">Esc</button>
      </div>

      <div id="soc-command-results" role="listbox" aria-label="Command palette results" className="max-h-[min(60vh,30rem)] overflow-y-auto p-2">
        {loading && <p role="status" className="px-3 py-5 text-xs text-slate-400">Loading incidents…</p>}
        {loadError && incidents?.length === 0 && <p role="status" className="px-3 py-3 text-xs text-amber-200">Incidents are currently unavailable.</p>}
        {groups.map((group) => <section key={group.title} role="group" aria-label={group.title} className="mb-2 last:mb-0">
          <h2 className="px-3 pb-1 pt-2 text-xs font-semibold text-[var(--muted)]">{group.title}</h2>
          {group.items.map((item) => {
            const currentIndex = resultIndex++;
            return <button key={item.id} id={`command-${item.id}`} type="button" role="option" aria-selected={currentIndex === activeIndex} onMouseEnter={() => setActiveIndex(currentIndex)} onClick={() => selectResult(item)} className={`flex w-full items-center justify-between gap-4 rounded-xl px-3 py-2.5 text-left transition-colors ${currentIndex === activeIndex ? 'bg-blue-500/15 text-slate-100' : 'text-slate-300 hover:bg-white/[0.04]'}`}>
              <span className="min-w-0"><span className="block truncate text-xs font-medium">{item.title}</span><span className="mt-0.5 block truncate text-xs text-slate-500">{item.subtitle}</span></span>
              {currentIndex === activeIndex && <CornerDownLeft aria-hidden="true" className="h-3.5 w-3.5 shrink-0 text-blue-200" />}
            </button>;
          })}
        </section>)}
        {!loading && !loadError && results.length === 0 && <p className="px-3 py-6 text-center text-xs text-slate-500">No matching pages or incidents.</p>}
        {!loading && incidents?.length === 0 && !loadError && <p className="px-3 pb-3 text-center text-xs text-slate-500">No incidents are currently available.</p>}
      </div>

      <div className="flex items-center justify-between border-t border-white/10 px-4 py-2.5 text-xs text-slate-500">
        <span>Press ? for keyboard shortcuts</span><span className="flex items-center gap-2"><span className="inline-flex items-center gap-1"><ArrowUp className="h-3 w-3" /><ArrowDown className="h-3 w-3" /> Navigate</span><span><CornerDownLeft className="mr-1 inline h-3 w-3" />Open</span></span>
      </div>
    </div>
  </Modal>;
}
