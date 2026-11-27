import React from 'react';
import Badge from '../ui/Badge';

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
const STATUS_ORDER = ['OPEN', 'NEEDS_REVIEW', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'CONFIRMED', 'FALSE_POSITIVE'];

function countRows(rows, field, order) {
  const counts = new Map();
  rows.forEach((row) => {
    const label = typeof row?.[field] === 'string' ? row[field].trim().toUpperCase() : '';
    if (label) counts.set(label, (counts.get(label) || 0) + 1);
  });
  return [...new Set([...order, ...[...counts.keys()].filter((label) => !order.includes(label)).sort()])]
    .map((label) => ({ label, count: counts.get(label) || 0 }));
}

function CountList({ title, rows, available, loading, capReached, severity = false }) {
  return <section className="min-w-0 rounded-[var(--r-inner)] bg-white p-5">
    <h2 className="text-sm font-semibold text-[var(--ink)]">{title}</h2>
    {capReached && <p className="mt-1 text-xs text-[var(--muted)]">Returned rows only · 50 row cap reached</p>}
    {!available ? <p className="mt-4 text-sm text-[var(--muted)]">{loading ? 'Loading incident counts…' : 'Incident counts unavailable'}</p> : rows.length === 0 ? <p className="mt-4 text-sm text-[var(--muted)]">No incident rows returned</p> : <ul className="mt-3 divide-y divide-[var(--line)]">{rows.map(({ label, count }) => <li key={label} className="flex items-center justify-between gap-3 py-2.5 text-sm">
      <span className="flex min-w-0 items-center gap-2"><span aria-hidden="true" className={`h-2 w-2 shrink-0 rounded-full ${severity && label === 'CRITICAL' ? 'bg-[var(--critical)]' : severity && label === 'HIGH' ? 'bg-[var(--high)]' : severity && label === 'MEDIUM' ? 'bg-[var(--medium)]' : severity ? 'bg-[var(--low)]' : 'bg-[var(--cobalt)]'}`} /><span className="truncate text-[var(--muted)]">{label.toLowerCase().replaceAll('_', ' ').replace(/\b\w/g, (letter) => letter.toUpperCase())}</span></span>
      <span className="soc-mono text-sm text-[var(--ink)]">{count}</span>
    </li>)}</ul>}
  </section>;
}

export default function FlowOrb({ totalEvents, layers = [], incidents, incidentLoadError = false, extraKpis = [], onReviewIncidents, engineStatus = '—' }) {
  const total = Number.isFinite(Number(totalEvents)) ? Number(totalEvents) : 0;
  const rows = Array.isArray(incidents) ? incidents.filter((incident) => incident && typeof incident === 'object' && !Array.isArray(incident)) : [];
  const available = Array.isArray(incidents) && !incidentLoadError;
  const loading = incidents == null && !incidentLoadError;
  const capReached = available && rows.length >= 50;
  const severities = countRows(rows, 'severity', SEVERITY_ORDER);
  const statuses = countRows(rows, 'status', STATUS_ORDER);
  const highestRiskIncident = rows.slice().sort((first, second) => Number(second.overall_risk_score || 0) - Number(first.overall_risk_score || 0))[0];
  const openCritical = rows.filter((row) => String(row.severity || '').toUpperCase() === 'CRITICAL' && !['RESOLVED', 'FALSE_POSITIVE'].includes(String(row.status || '').toUpperCase())).length;

  return <section className="overview-entrance space-y-3" aria-label="Overview event flow">
    <div className="grid grid-cols-1 gap-3 lg:grid-cols-[1.2fr_1fr]">
      <section className="overview-hero flex min-h-44 flex-col items-start justify-between gap-5 rounded-[var(--r-card)] bg-[var(--cobalt)] p-6 text-white sm:p-7">
        <div><p className="text-xs font-medium text-white/75">Security posture</p><h2 className="mt-3 max-w-xl font-display text-3xl font-bold leading-tight tracking-tight text-white sm:text-4xl">{openCritical ? `${openCritical} critical incident${openCritical === 1 ? '' : 's'} are open right now.` : 'No critical incidents open.'}</h2></div>
        <div className="flex w-full flex-wrap items-center justify-between gap-3"><p className="text-sm text-white/80">{available ? `${rows.length}${capReached ? '+' : ''} incident records returned` : loading ? 'Loading incident counts…' : 'Incident counts unavailable'}</p><button type="button" onClick={onReviewIncidents} className="rounded-full bg-white px-4 py-2 text-sm font-semibold text-[var(--cobalt)] transition hover:bg-white/85">Review incidents <span aria-hidden="true">→</span></button></div>
      </section>
      <section className="flex min-h-44 flex-col justify-between rounded-[var(--r-card)] bg-white p-6 shadow-[var(--shadow-card)]">
        <span className="text-sm text-[var(--muted)]">Events analysed</span><span className="font-display text-7xl font-bold leading-none tracking-[-.05em] text-[var(--ink)] sm:text-8xl">{total.toLocaleString()}</span>
      </section>
    </div>
    <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
      <CountList title="Incidents by severity" rows={available ? severities : []} available={available} loading={loading} capReached={capReached} severity />
      <section className="min-w-0 rounded-[var(--r-inner)] bg-white p-5">
        <h2 className="text-sm font-semibold text-[var(--ink)]">Highest risk</h2>
        {highestRiskIncident ? <><p className="mt-3 font-display text-4xl font-bold tracking-tight text-[var(--critical)]">{Number.isFinite(Number(highestRiskIncident.overall_risk_score)) ? `${Number(highestRiskIncident.overall_risk_score).toFixed(1)}%` : '—'}</p><p className="mt-2 truncate text-sm font-semibold text-[var(--ink)]" title={highestRiskIncident.title}>{highestRiskIncident.title || 'Incident title unavailable'}</p><p className="mt-1 truncate font-mono text-xs text-[var(--muted)]">{highestRiskIncident.source_ip || highestRiskIncident.evidence?.source_ip || highestRiskIncident.device_id || '—'}</p></> : <p className="mt-3 text-sm text-[var(--muted)]">{loading ? 'Loading incident scores…' : 'No incident scores available'}</p>}
        {available && statuses.length > 0 && <div className="mt-4 border-t border-[var(--line)] pt-3"><p className="mb-2 text-xs text-[var(--muted)]">Incidents by status</p><div className="flex flex-wrap gap-1.5">{statuses.filter((row) => row.count > 0).map((row) => <Badge key={row.label} tone="neutral">{row.label.replaceAll('_', ' ')} · {row.count}</Badge>)}</div></div>}
      </section>
      <section className="rounded-[var(--r-inner)] bg-white p-5">
        <h2 className="text-sm font-semibold text-[var(--ink)]">Detection layers</h2>
        <ul className="mt-3 divide-y divide-[var(--line)]">{layers.slice(0, 3).map((layer) => <li key={layer.title} className="flex items-center justify-between gap-3 py-2.5 text-sm"><span className="min-w-0"><span className="block truncate text-[var(--muted)]">{layer.title}</span><span className="text-xs text-[var(--subtle)]">{layer.suffix}</span></span><span className="soc-mono text-sm text-[var(--ink)]">{Number.isFinite(Number(layer.value)) ? Number(layer.value).toLocaleString() : '—'}</span></li>)}</ul>
        <div className="mt-3 flex items-center justify-between gap-3 border-t border-[var(--line)] pt-3 text-xs"><span className="text-[var(--muted)]">Engine status</span><span className="soc-mono text-[var(--ink)]">{engineStatus || '—'}</span></div>
        {extraKpis.length > 0 && <div className="mt-3 flex flex-wrap gap-2">{extraKpis.map((kpi) => <Badge key={kpi.label} tone={kpi.tag ? 'novel' : 'neutral'}>{kpi.label}: {kpi.value}{kpi.tag ? ` · ${kpi.tag}` : ''}</Badge>)}</div>}
      </section>
    </div>
  </section>;
}
