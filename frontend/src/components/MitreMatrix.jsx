import React, { useEffect, useMemo, useState } from 'react';
import { RefreshCw, ShieldAlert } from 'lucide-react';
import { api } from '../services/api';
import EmptyState from './ui/EmptyState';
import Skeleton from './ui/Skeleton';

const CACHE_MS = 30000;
const incidentCache = new Map();
const severityRank = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const severityColors = {
  CRITICAL: { variable: '--soc-critical', text: 'text-rose-100', border: 'border-rose-300/40' },
  HIGH: { variable: '--soc-high', text: 'text-orange-100', border: 'border-orange-300/40' },
  MEDIUM: { variable: '--soc-medium', text: 'text-amber-100', border: 'border-amber-300/40' },
  LOW: { variable: '--soc-low', text: 'text-blue-100', border: 'border-blue-300/40' },
};

function requestIncidentsCached(token) {
  const now = Date.now();
  const cached = incidentCache.get(token);
  if (cached?.promise) return cached.promise;
  if (cached && now - cached.fetchedAt < CACHE_MS) return Promise.resolve(cached);

  const request = api.getIncidents()
    .then((data) => {
      const result = { data, error: null, fetchedAt: Date.now(), promise: null };
      incidentCache.set(token, result);
      return result;
    })
    .catch((error) => {
      const result = { data: [], error: error.message || 'Incident data could not be loaded.', fetchedAt: Date.now(), promise: null };
      incidentCache.set(token, result);
      return result;
    });
  incidentCache.set(token, { data: [], error: null, fetchedAt: now, promise: request });
  return request;
}

function aggregateIncidents(incidents) {
  const tactics = new Map();
  const incidentById = new Map(incidents.map((incident) => [incident.incident_id, incident]));

  incidents.forEach((incident) => {
    const seen = new Set();
    (incident.mitre_mappings || []).forEach((mapping) => {
      const tactic = typeof mapping.tactic === 'string' ? mapping.tactic.trim() : '';
      const techniqueId = typeof mapping.technique_id === 'string' ? mapping.technique_id.trim() : '';
      if (!tactic || !techniqueId) return;
      const key = `${tactic}\u0000${techniqueId}`;
      if (seen.has(key)) return;
      seen.add(key);

      if (!tactics.has(tactic)) tactics.set(tactic, new Map());
      const techniques = tactics.get(tactic);
      if (!techniques.has(techniqueId)) {
        techniques.set(techniqueId, {
          id: techniqueId,
          name: mapping.technique_name || techniqueId,
          count: 0,
          severity: '',
          incidentIds: [],
        });
      }
      const technique = techniques.get(techniqueId);
      technique.count += 1;
      technique.incidentIds.push(incident.incident_id);
      const severity = String(incident.severity || '').toUpperCase();
      if ((severityRank[severity] || 0) > (severityRank[technique.severity] || 0)) technique.severity = severity;
    });
  });

  return {
    tactics: [...tactics.entries()].map(([name, techniques]) => ({ name, techniques: [...techniques.values()] })),
    incidentById,
  };
}

export default function MitreMatrix() {
  const [incidents, setIncidents] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [retryAt, setRetryAt] = useState(0);
  const [clock, setClock] = useState(Date.now());
  const [reloadKey, setReloadKey] = useState(0);
  const [selectedTechnique, setSelectedTechnique] = useState(null);

  useEffect(() => {
    let active = true;
    const token = window.sessionStorage.getItem('cyberguardx_access_token') || '';
    setLoading(true);
    setError('');
    requestIncidentsCached(token).then((result) => {
      if (!active) return;
      setIncidents(result.data);
      setError(result.error || '');
      setRetryAt(result.fetchedAt + CACHE_MS);
      setLoading(false);
    });
    return () => { active = false; };
  }, [reloadKey]);

  useEffect(() => {
    if (!error || !retryAt || clock >= retryAt) return undefined;
    const timer = window.setTimeout(() => setClock(Date.now()), 1000);
    return () => window.clearTimeout(timer);
  }, [clock, error, retryAt]);

  const { tactics, incidentById } = useMemo(() => aggregateIncidents(incidents || []), [incidents]);
  const allTechniques = tactics.flatMap((tactic) => tactic.techniques);
  const maxCount = Math.max(1, ...allTechniques.map((technique) => technique.count));
  const linkedIncidents = selectedTechnique
    ? selectedTechnique.incidentIds.map((id) => incidentById.get(id)).filter(Boolean)
    : [];
  const retrySeconds = Math.max(0, Math.ceil((retryAt - clock) / 1000));

  if (loading) return <section aria-label="MITRE ATT&CK matrix loading" aria-busy="true" className="space-y-4 rounded-2xl border border-white/[0.07] bg-[#10182E] p-5">
    <Skeleton className="h-5 w-44" /><Skeleton className="h-4 w-72 max-w-full" />
    <div className="flex gap-4 overflow-hidden pt-2">{[0, 1, 2, 3].map((item) => <div key={item} className="min-w-56 flex-1 space-y-2"><Skeleton className="h-8" /><Skeleton className="h-20" /><Skeleton className="h-14" /></div>)}</div>
  </section>;

  if (error) return <section aria-label="MITRE ATT&CK matrix error" className="rounded-2xl border border-white/[0.07] bg-[#10182E] p-6">
    <div className="mx-auto max-w-lg text-center"><div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-xl border border-rose-400/20 bg-rose-400/10 text-rose-200"><ShieldAlert className="h-5 w-5" /></div><h2 className="text-sm font-semibold text-slate-100">MITRE incident data is unavailable</h2><p role="alert" className="mt-2 text-xs text-slate-400">{error}</p>
      <button type="button" disabled={retrySeconds > 0} onClick={() => { setClock(Date.now()); setReloadKey((key) => key + 1); }} className="mt-4 inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.04] px-3.5 py-2 text-xs font-semibold text-slate-200 hover:bg-white/[0.08] disabled:cursor-not-allowed disabled:opacity-50"><RefreshCw className="h-3.5 w-3.5" />{retrySeconds > 0 ? `Retry in ${retrySeconds}s` : 'Retry'}</button>
    </div>
  </section>;

  if (tactics.length === 0) return <EmptyState icon={ShieldAlert} title="No MITRE-mapped incidents yet" description="Incident records do not currently include MITRE ATT&CK technique mappings." className="bg-[#10182E]" />;

  return <div className="space-y-5">
    <div className="flex flex-wrap items-end justify-between gap-3"><div><p className="text-[9px] font-bold uppercase tracking-[0.18em] text-blue-300">MITRE ATT&CK</p><h2 className="mt-1 text-sm font-semibold text-slate-100">Mapped techniques by tactic</h2><p className="mt-1 text-xs text-slate-400">Counts reflect incidents with a stored technique mapping. Showing tactics present in incident data.</p></div><span className="font-mono text-[10px] text-slate-500">{incidents.length} incidents scanned</span></div>
    <div className="overflow-x-auto rounded-2xl border border-white/[0.07] bg-[#10182E] p-3" aria-label="MITRE ATT&CK tactic and technique matrix">
      <div className="grid min-w-max gap-3" style={{ gridTemplateColumns: `repeat(${tactics.length}, minmax(14rem, 1fr))` }}>
        {tactics.map((tactic) => <section key={tactic.name} aria-label={`${tactic.name} tactic`} className="min-w-56 rounded-xl border border-white/[0.06] bg-slate-950/20 p-2.5">
          <h3 className="mb-2 border-b border-white/[0.07] px-1 pb-2 text-[10px] font-bold uppercase tracking-wider text-slate-300">{tactic.name}</h3>
          <div className="space-y-2">{tactic.techniques.map((technique) => {
            const severity = severityColors[technique.severity];
            const color = severity?.variable || '--soc-muted';
            const tint = 14 + Math.round((technique.count / maxCount) * 42);
            const isSelected = selectedTechnique?.id === technique.id && selectedTechnique?.tactic === tactic.name;
            const incidentList = technique.incidentIds.join(', ');
            return <button key={technique.id} type="button" aria-pressed={isSelected} aria-label={`${technique.id}, ${technique.name}, ${technique.count} incidents. Linked incidents: ${incidentList}`} title={`${technique.id} · ${technique.name} · ${technique.count} incidents · ${incidentList}`} onClick={() => setSelectedTechnique(isSelected ? null : { ...technique, tactic: tactic.name })} className={`group w-full rounded-lg border p-2.5 text-left transition-transform hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${severity?.border || 'border-white/10'} ${severity?.text || 'text-slate-200'} ${isSelected ? 'ring-2 ring-blue-300/70' : ''}`} style={{ backgroundColor: `color-mix(in srgb, var(${color}) ${tint}%, var(--soc-raised))` }}>
              <span className="flex items-start justify-between gap-2"><span className="min-w-0"><span className="block font-mono text-[10px] font-bold">{technique.id}</span><span className="mt-1 block line-clamp-2 text-[10px] leading-4 text-slate-200">{technique.name}</span></span><span className="shrink-0 rounded-md border border-white/10 bg-black/20 px-1.5 py-0.5 font-mono text-[9px] font-bold text-white">{technique.count}</span></span>
              <span className="mt-2 flex items-center justify-between gap-2 text-[9px] text-slate-300"><span>{technique.severity || 'Severity unavailable'}</span><span>{technique.incidentIds.length} incidents</span></span>
            </button>;
          })}</div>
        </section>)}
      </div>
    </div>

    {selectedTechnique && <section aria-label={`Incidents mapped to ${selectedTechnique.id}`} className="rounded-2xl border border-white/[0.07] bg-[#10182E] p-4">
      <div className="flex flex-wrap items-start justify-between gap-3"><div><p className="font-mono text-[10px] font-bold text-blue-200">{selectedTechnique.id} · {selectedTechnique.tactic}</p><h3 className="mt-1 text-sm font-semibold text-slate-100">{selectedTechnique.name}</h3><p className="mt-1 text-[10px] text-slate-400">{selectedTechnique.count} linked incidents · highest severity {selectedTechnique.severity || 'unavailable'}</p></div><button type="button" onClick={() => setSelectedTechnique(null)} className="rounded-lg border border-white/10 px-2.5 py-1.5 text-[10px] font-medium text-slate-300 hover:bg-white/5">Clear selection</button></div>
      <ul className="mt-3 divide-y divide-white/[0.06]">{linkedIncidents.map((incident) => <li key={incident.incident_id} className="flex flex-wrap items-center justify-between gap-2 py-2.5"><span className="min-w-0"><span className="block truncate text-xs font-medium text-slate-200">{incident.title}</span><span className="mt-0.5 block font-mono text-[9px] text-slate-500">{incident.incident_id}</span></span><span className="flex items-center gap-2 font-mono text-[9px] text-slate-400"><span>{incident.severity}</span><span>{incident.status}</span></span></li>)}</ul>
    </section>}
  </div>;
}
