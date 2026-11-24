import React, { useState, useEffect, useRef } from 'react';
import {
  Check,
  ChevronDown,
  Copy,
  FileWarning,
  Send,
  ShieldAlert,
  Activity,
  Clock3,
} from '../lib/icons';
import { api } from '../services/api';
import RiskFusion from '../components/RiskFusion';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';
import Badge from '../components/ui/Badge';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import Skeleton from '../components/ui/Skeleton';
import RiskTicks from '../components/ui/RiskTicks';

function severityTone(severity) {
  const value = String(severity || '').toUpperCase();
  if (value.includes('UNKNOWN') || value.includes('NOVEL')) return 'novel';
  if (value === 'CRITICAL') return 'critical';
  if (value === 'HIGH') return 'high';
  if (value === 'MEDIUM') return 'medium';
  if (value === 'LOW') return 'low';
  if (value.includes('BENIGN') || value === 'NORMAL') return 'normal';
  return 'neutral';
}

function statusTone(status) {
  const value = String(status || '').toUpperCase();
  if (value === 'RESOLVED' || value === 'FALSE_POSITIVE') return 'normal';
  if (value === 'CONTAINED') return 'low';
  if (value === 'INVESTIGATING') return 'high';
  if (value === 'NEEDS_REVIEW') return 'medium';
  return 'neutral';
}

function formatFixed(value, digits) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric.toFixed(digits) : '—';
}

function formatIncidentDate(value, format) {
  if (!value) return '—';
  const date = new Date(value);
  if (!Number.isFinite(date.getTime())) return '—';
  return format === 'datetime' ? date.toLocaleString() : date.toLocaleTimeString();
}

function IncidentLoading() {
  return (
    <div className="mx-auto w-full max-w-[1600px] space-y-4" role="status" aria-label="Loading incidents">
      <span className="sr-only">Loading incidents…</span>
      <Skeleton className="h-16 w-full rounded-2xl" />
      <Skeleton className="h-16 w-full rounded-2xl" />
      <div className="grid gap-5 lg:grid-cols-3">
        <Skeleton className="h-[36rem] rounded-2xl" />
        <Skeleton className="h-[36rem] rounded-2xl lg:col-span-2" />
      </div>
    </div>
  );
}

function tintJson(value) {
  const tokenPattern = /("(?:\\.|[^"\\])*"(?=\s*:)|"(?:\\.|[^"\\])*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null)/g;
  return value.split('\n').map((line, lineIndex) => {
    const parts = [];
    let cursor = 0;
    for (const match of line.matchAll(tokenPattern)) {
      if (match.index > cursor) parts.push(line.slice(cursor, match.index));
      const token = match[0];
      const isKey = token.startsWith('"') && /^\s*:/.test(line.slice(match.index + token.length));
      const tone = isKey ? 'text-blue-200' : token.startsWith('"') ? 'text-emerald-200' : /^(true|false|null)$/.test(token) ? 'text-amber-200' : 'text-purple-200';
      parts.push(<span key={`${lineIndex}-${match.index}`} className={tone}>{token}</span>);
      cursor = match.index + token.length;
    }
    if (cursor < line.length) parts.push(line.slice(cursor));
    return <React.Fragment key={lineIndex}>{lineIndex > 0 ? '\n' : ''}{parts}</React.Fragment>;
  });
}

function JsonCodeViewer({ value, lineCount }) {
  const [open, setOpen] = useState(lineCount <= 12);
  const [copied, setCopied] = useState(false);
  const copyTimer = useRef(null);

  useEffect(() => () => window.clearTimeout(copyTimer.current), []);

  const copyJson = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.clearTimeout(copyTimer.current);
      copyTimer.current = window.setTimeout(() => setCopied(false), 1400);
    } catch (error) {
      console.warn('Unable to copy model score JSON:', error);
      setCopied(false);
    }
  };

  return (
    <div className="mt-3 overflow-hidden rounded-xl border border-white/[0.07] bg-slate-950/55">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/[0.06] px-3 py-2">
        <button type="button" aria-expanded={open} onClick={() => setOpen((current) => !current)} className="flex items-center gap-2 text-[11px] font-medium text-slate-300 hover:text-white">
          <ChevronDown aria-hidden="true" className={`h-3.5 w-3.5 transition-transform duration-200 ${open ? '' : '-rotate-90'}`} />
          Risk breakdown JSON <span className="font-mono text-slate-500">{lineCount} lines</span>
        </button>
        <button type="button" onClick={copyJson} aria-label={`${copied ? 'Copied' : 'Copy'} model score JSON`} className="inline-flex items-center gap-1.5 rounded-lg px-2 py-1 text-[11px] text-slate-400 transition hover:bg-white/[0.06] hover:text-white focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">
          {copied ? <Check aria-hidden="true" className="h-3.5 w-3.5 text-emerald-300" /> : <Copy aria-hidden="true" className="h-3.5 w-3.5" />}
          {copied ? 'Copied' : 'Copy JSON'}
        </button>
      </div>
      {open && <pre className="max-h-72 overflow-auto p-3 font-mono text-[11px] leading-relaxed text-slate-300">{tintJson(value)}</pre>}
    </div>
  );
}

export default function IncidentManagement({ onSelectIncidentForAssistant, role = 'viewer' }) {
  const canInvestigate = role === 'analyst' || role === 'admin';
  const isAdmin = role === 'admin';
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [newNote, setNewNote] = useState('');
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [correlationRunning, setCorrelationRunning] = useState(false);
  const [reviewExpanded, setReviewExpanded] = useState(false);
  const [correlationMessage, setCorrelationMessage] = useState('');
  const [correlationAlerts, setCorrelationAlerts] = useState([]);
  const [actionMessage, setActionMessage] = useState('');
  const pageRef = useRef(null);
  const reviewQueue = incidents.filter((incident) => incident.status === 'NEEDS_REVIEW');
  const reviewFlowCount = reviewQueue.reduce((total, incident) => total + (incident.flow_count || 1), 0);

  useGSAP(() => {
    const scope = pageRef.current;
    if (!scope || loading) return undefined;
    return createMotionScope(scope, (reduced) => {
      const items = gsap.utils.toArray('.incident-entrance', scope);
      if (!items.length) return;
      gsap.fromTo(items, { autoAlpha: 0, y: reduced ? 0 : 12 }, {
        autoAlpha: 1,
        y: 0,
        duration: reduced ? 0.18 : 0.48,
        stagger: reduced ? 0 : 0.055,
        ease: motion.ease,
        clearProps: 'opacity,transform,visibility',
      });
    });
  }, { scope: pageRef, dependencies: [loading, incidents.length, correlationAlerts.length, Boolean(loadError), Boolean(actionMessage)], revertOnUpdate: true });

  useGSAP(() => {
    const scope = pageRef.current;
    if (!scope || loading) return undefined;
    return createMotionScope(scope, (reduced) => {
      if (!pageRef.current) return;
      const content = gsap.utils.toArray('.review-queue-content', scope);
      if (!content.length) return;
      const panel = content[0];
      const targetHeight = reviewExpanded ? panel.scrollHeight : 0;
      const startHeight = reviewExpanded ? 0 : panel.scrollHeight;
      gsap.fromTo(panel, { height: startHeight, overflow: 'hidden' }, {
        height: targetHeight,
        duration: reduced ? 0.01 : 0.28,
        ease: motion.ease,
        clearProps: reviewExpanded ? 'height,overflow' : 'overflow',
      });
    });
  }, { scope: pageRef, dependencies: [loading, reviewExpanded, incidents.length], revertOnUpdate: true });

  const fetchIncidents = async () => {
    try {
      const data = await api.getIncidents();
      setLoadError('');
      setIncidents(data);
      if (data.length > 0 && !selectedIncident) {
        setSelectedIncident(data[0]);
      }
    } catch (err) {
      console.error('Failed to load incidents:', err);
      setLoadError(err.message || 'Incidents could not be loaded.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIncidents();
  }, []);

  const handleRunCorrelation = async () => {
    setCorrelationRunning(true);
    setCorrelationMessage('');
    try {
      const result = await api.runCorrelation(60);
      setCorrelationAlerts(result.alerts || []);
      setCorrelationMessage(`Checked ${result.alerts?.length || 0} rule indicators; created or matched ${result.incidents?.length || 0} correlated incidents.`);
      await fetchIncidents();
    } catch (err) {
      setCorrelationMessage(err.message || 'Correlation run failed.');
    } finally {
      setCorrelationRunning(false);
    }
  };

  if (loading) return <IncidentLoading />;

  const handleStatusChange = async (incidentId, newStatus) => {
    try {
      await api.updateIncidentStatus(incidentId, newStatus);
      fetchIncidents();
      if (selectedIncident?.incident_id === incidentId) {
        setSelectedIncident((prev) => ({ ...prev, status: newStatus }));
      }
      setActionMessage('Incident status updated.');
    } catch (err) {
      setActionMessage(err.message || 'Failed to update status.');
    }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || !selectedIncident) return;
    try {
      const created = await api.addIncidentNote(selectedIncident.incident_id, newNote);
      setSelectedIncident((prev) => ({
        ...prev,
        notes: [created, ...(prev.notes || [])],
      }));
      setNewNote('');
      setActionMessage('Note added.');
    } catch (err) {
      setActionMessage(err.message || 'Failed to add note.');
    }
  };

  return (
    <div ref={pageRef} className="mx-auto w-full max-w-[1600px] space-y-4">
      {loadError && <div role="alert" className="incident-entrance rounded-xl border border-rose-400/25 bg-rose-400/[0.06] px-4 py-3 text-xs text-rose-100">{loadError}</div>}
      {actionMessage && <p role="status" className="incident-entrance rounded-xl border border-blue-400/20 bg-blue-400/[0.06] px-4 py-2.5 text-xs text-blue-100">{actionMessage}</p>}
      <header className="incident-entrance flex flex-wrap items-end justify-between gap-3 px-1 pb-1">
        <div>
          <h1 className="font-[family-name:var(--soc-font-display)] text-[38px] font-light leading-tight tracking-tight text-slate-50">Incidents</h1>
          <p className="mt-1 text-sm text-slate-400">Correlated activity and investigation details</p>
        </div>
      </header>

      <Card className="incident-entrance flex flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-5">
        <div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-1">
          <h2 className="text-sm font-medium text-slate-100">Rule-based cross-layer correlation</h2>
          <p className="text-sm text-slate-400">Signals are rule indicators; they are not ML predictions.</p>
          {correlationMessage && <p role="status" className="basis-full text-sm text-blue-200">{correlationMessage}</p>}
        </div>
        <div className="flex w-full flex-wrap items-center justify-end gap-3 sm:w-auto">
          {isAdmin && <button type="button" onClick={handleRunCorrelation} disabled={correlationRunning}
            className="inline-flex items-center gap-2 rounded-xl border border-blue-300/20 bg-gradient-to-r from-blue-600 to-violet-600 px-4 py-2.5 text-xs font-semibold text-white shadow-[0_8px_24px_rgba(56,110,255,.18)] transition hover:brightness-110 active:scale-[.98] disabled:cursor-wait disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300">
            <Activity aria-hidden="true" className="h-4 w-4" /> {correlationRunning ? 'Correlating…' : 'Run correlation (60 min)'}
          </button>}
        </div>
      </Card>

      <section className="incident-entrance overflow-hidden rounded-2xl border border-amber-400/20 bg-gradient-to-r from-amber-400/[0.055] via-[var(--soc-panel)] to-[var(--soc-raised)] shadow-[inset_0_1px_rgba(255,255,255,.035)]">
        <button type="button" aria-expanded={reviewExpanded} aria-controls="model-review-items" onClick={() => setReviewExpanded((open) => !open)} className="flex w-full flex-wrap items-center justify-between gap-3 px-4 py-3 text-left transition hover:bg-white/[0.025] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-amber-300">
          <span className="flex min-w-0 items-center gap-3">
            <span className="grid h-8 w-8 place-items-center rounded-lg border border-amber-400/20 bg-amber-400/[0.08] text-amber-200"><FileWarning aria-hidden="true" className="h-4 w-4" /></span>
            <span>
              <span className="block text-xs font-semibold text-slate-100">Model review queue</span>
              <span className="mt-0.5 block text-[11px] text-slate-400">{reviewQueue.length === 0 ? 'No unknown candidates need review.' : `${reviewFlowCount} ${reviewFlowCount === 1 ? 'flow needs' : 'flows need'} review`}</span>
            </span>
          </span>
          <span className="flex items-center gap-2">
            <Badge tone={reviewQueue.length ? 'medium' : 'normal'} className="font-mono text-[11px]">{reviewQueue.length}</Badge>
            <ChevronDown aria-hidden="true" className={`h-4 w-4 text-slate-400 transition-transform duration-200 ${reviewExpanded ? 'rotate-180' : ''}`} />
          </span>
        </button>
        <div id="model-review-items" className="review-queue-content overflow-hidden border-t border-white/[0.06]" aria-hidden={!reviewExpanded} inert={reviewExpanded ? undefined : ''}>
          {reviewQueue.length > 0 && <div className="space-y-2 p-3 sm:p-4">
            {reviewQueue.map((item) => (
              <button key={item.incident_id} onClick={() => setSelectedIncident(item)} className="flex w-full items-center justify-between gap-4 rounded-2xl border border-white/[0.07] bg-white/[0.025] p-3.5 text-left text-sm transition hover:border-amber-300/30 hover:bg-white/[0.05] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300">
                <span className="min-w-0 text-slate-200">{item.title}<span className="mt-1 block text-sm text-slate-400">{item.description}</span></span>
                <span className="shrink-0 font-mono text-sm text-amber-200">{item.flow_count || 1} flows</span>
              </button>
            ))}
          </div>}
          {reviewQueue.length === 0 && <div className="px-4 py-3 text-sm text-slate-400">No unknown candidates need review.</div>}
        </div>
      </section>

      <div className="grid grid-cols-1 gap-5 lg:h-[calc(100vh-290px)] lg:min-h-[36rem] lg:grid-cols-3">
      {/* Incidents List (Left col) */}
      <Card className="incident-entrance min-h-[28rem] overflow-hidden p-4 sm:p-5 lg:col-span-1 lg:flex lg:flex-col">
        <div className="mb-4 flex items-center justify-between gap-3">
          <h3 className="text-base font-medium text-slate-100">Correlated incidents</h3>
          <span className="rounded-full border border-white/[0.08] bg-white/[0.035] px-3 py-1 text-sm text-slate-300">{incidents.length} Active</span>
        </div>

        <div className="space-y-2 overflow-y-auto overscroll-contain pr-1 lg:min-h-0 lg:flex-1">
          {incidents.length === 0 && <EmptyState icon={ShieldAlert} title={loadError ? 'Incident list unavailable' : 'No correlated incidents yet.'} description={loadError ? 'Incident records could not be loaded.' : 'Matching rule indicators will appear here when incidents are created.'} className="min-h-48 border-0 bg-transparent" />}
          {incidents.map((inc) => {
            const isSelected = selectedIncident?.incident_id === inc.incident_id;
            const tone = severityTone(inc.severity);
              const isRuleCorrelated = inc.threat_classification === 'RULE_CORRELATED_SUSPICIOUS_ACTIVITY';
              const isDemo = (inc.evidence?.indicators || []).some((indicator) => indicator.dataset === 'synthetic_demo' || indicator.is_demo);
            return (
              <button
                type="button"
                key={inc.incident_id}
                aria-pressed={isSelected}
                onClick={() => setSelectedIncident(inc)}
                className={`relative w-full overflow-hidden rounded-xl border p-3.5 text-left transition-all duration-200 hover:-translate-y-0.5 hover:bg-white/[0.025] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${
                  isSelected
                    ? 'border-blue-400/35 bg-blue-400/[0.075] shadow-[0_0_24px_rgba(61,126,255,.12)]'
                    : 'border-white/[0.07] bg-slate-950/30 hover:border-white/[0.13]'
                }`}
              >
                <span aria-hidden="true" className={`absolute inset-y-0 left-0 w-[3px] ${tone === 'critical' ? 'bg-rose-400' : tone === 'high' ? 'bg-orange-400' : tone === 'medium' ? 'bg-amber-300' : tone === 'low' ? 'bg-blue-300' : tone === 'normal' ? 'bg-emerald-300' : tone === 'novel' ? 'bg-purple-300' : 'bg-slate-500'}`} />
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <Badge tone={tone} className="shrink-0 px-2.5 py-1 text-sm">{inc.severity}</Badge>
                  <span className="flex min-w-0 shrink-0 items-center gap-2"><span className="text-sm text-slate-400">Risk</span><RiskTicks value={inc.overall_risk_score} suffix="" /></span>
                </div>

                <p className="mt-3 line-clamp-1 text-sm font-medium text-slate-100">{inc.title}</p>
                <div className="mt-2 flex flex-wrap items-center gap-2">
                  <Badge tone={statusTone(inc.status)} className="px-2.5 py-1 text-sm font-normal">{inc.status}</Badge>
                </div>
                {isRuleCorrelated && <div className="mt-2 flex flex-wrap gap-1.5">
                  {isDemo && <Badge tone="medium" className="px-2 py-0.5 text-[11px]">DEMO</Badge>}
                  <span className="rounded-full border border-blue-300/20 bg-blue-300/[0.06] px-2.5 py-1 text-sm font-medium text-blue-200">Rule correlated</span>
                </div>}
                <p className="mt-2 text-sm text-slate-300">{inc.flow_count || 1} flows</p>
                <div className="flex items-center justify-between text-[11px] text-slate-400 mt-2">
                  <span className="max-w-[48%] truncate font-mono">{inc.user_id || 'host_sys'}</span>
                  <span className="max-w-[48%] truncate font-mono">{inc.device_id || 'unknown_host'}</span>
                </div>
              </button>
            );
          })}
        </div>
      </Card>

      {/* Incident Detail (Right 2 cols) */}
      <Card className="incident-entrance min-h-[28rem] overflow-y-auto overscroll-contain p-5 sm:p-6 lg:col-span-2">
        {selectedIncident ? (
          <div className="space-y-6">
            {/* Header with Title & Status Dropdown */}
            <div className="flex flex-wrap items-start justify-between gap-4 border-b border-white/[0.07] pb-5">
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[13px] font-medium text-blue-200">
                    INCIDENT #{(selectedIncident.incident_id || '').slice(-8).toUpperCase() || '—'}
                  </span>
                  <button type="button" aria-label="Copy incident ID" title="Copy incident ID" onClick={async () => { try { if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(selectedIncident.incident_id); } catch (error) { console.warn('Unable to copy incident ID:', error); } }} className="inline-flex h-8 w-8 items-center justify-center rounded-full border border-white/[0.1] bg-white/[0.035] text-slate-400 transition hover:bg-white/[0.07] hover:text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400">
                    <Copy aria-hidden="true" className="h-3.5 w-3.5" />
                  </button>
                </div>
                <h2 className="mt-1 font-[family-name:var(--soc-font-display)] text-2xl font-medium text-slate-50">
                  {selectedIncident.title}
                </h2>
                <p className="mt-1 text-xs leading-relaxed text-slate-400">{selectedIncident.description}</p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {canInvestigate && <select
                  value={selectedIncident.status}
                  onChange={(e) => handleStatusChange(selectedIncident.incident_id, e.target.value)}
                  aria-label="Incident status"
                  className="rounded-full border border-white/[0.1] bg-white/[0.035] px-4 py-2.5 text-sm font-medium text-slate-100 shadow-inner focus:outline-none focus:ring-2 focus:ring-blue-400/35"
                >
                  {selectedIncident.status === 'open' && <option value="open">Status: open</option>}
                  <option value="OPEN">Status: OPEN</option>
                  <option value="NEEDS_REVIEW">Status: NEEDS_REVIEW</option>
                  <option value="INVESTIGATING">Status: INVESTIGATING</option>
                  <option value="CONTAINED">Status: CONTAINED</option>
                  <option value="RESOLVED">Status: RESOLVED</option>
                  <option value="FALSE_POSITIVE">Status: FALSE_POSITIVE</option>
                </select>}

                {onSelectIncidentForAssistant && (
                  <button
                    onClick={() => onSelectIncidentForAssistant(selectedIncident.incident_id)}
                    className="inline-flex items-center gap-2 rounded-full border border-blue-300/20 bg-gradient-to-r from-blue-600 to-violet-600 px-4 py-2.5 text-sm font-medium text-white shadow-[0_8px_24px_rgba(56,110,255,.22)] transition hover:brightness-110 active:scale-[.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300"
                  >
                    <Activity aria-hidden="true" className="h-3.5 w-3.5" />
                    Ask AI Assistant
                  </button>
                )}
              </div>
            </div>

            {selectedIncident.threat_classification === 'RULE_CORRELATED_SUSPICIOUS_ACTIVITY' && (() => {
              const isDemo = (selectedIncident.evidence?.indicators || []).some((indicator) => indicator.dataset === 'synthetic_demo' || indicator.is_demo);
              return <div className="flex flex-wrap gap-2" aria-label="Incident provenance badges">
                {isDemo && <Badge tone="medium" className="text-[11px]">DEMO</Badge>}
                <span className="rounded-full border border-blue-300/20 bg-blue-300/[0.06] px-2.5 py-1 text-[13px] font-medium text-blue-200">Rule correlated</span>
              </div>;
            })()}

            {(() => {
              const fusion = selectedIncident.evidence?.risk_fusion || selectedIncident.risk_score_detail?.risk_breakdown?.fusion || {};
              return <RiskFusion explanation={{
                severity: fusion.severity || selectedIncident.severity,
                calibrated_risk_score: fusion.probability,
                overall_risk_score: selectedIncident.overall_risk_score,
                per_layer_contributions: fusion.contributions || {},
              }} />;
            })()}
            {String(selectedIncident.threat_classification || '').includes('UNKNOWN') && <div className="rounded-xl border border-purple-400/25 bg-purple-400/[0.07] p-3 text-xs font-semibold text-purple-100">Novel / Unfamiliar Behavior — Requires Analyst Triage. This open-set candidate is not a confirmed attack.</div>}

            {/* Target Entities Row */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
              <div className="rounded-2xl border border-white/[0.08] bg-gradient-to-b from-white/[0.04] to-white/[0.015] p-3.5">
                <span className="text-[13px] font-normal text-slate-400">Compromised User</span>
                <p className={`mt-1 font-mono text-xs font-semibold ${selectedIncident.user_id ? 'text-slate-100' : 'text-slate-500'}`}>{selectedIncident.user_id || 'N/A'}</p>
              </div>
              <div className="rounded-2xl border border-white/[0.08] bg-gradient-to-b from-white/[0.04] to-white/[0.015] p-3.5">
                <span className="text-[13px] font-normal text-slate-400">Target Device</span>
                <p className={`mt-1 font-mono text-xs font-semibold ${selectedIncident.device_id ? 'text-slate-100' : 'text-slate-500'}`}>{selectedIncident.device_id || 'N/A'}</p>
              </div>
              <div className="rounded-2xl border border-white/[0.08] bg-gradient-to-b from-white/[0.04] to-white/[0.015] p-3.5">
                <span className="text-[13px] font-normal text-slate-400">Classification</span>
                <p className={`mt-1 break-words font-mono text-xs font-semibold ${severityTone(selectedIncident.threat_classification) === 'novel' ? 'text-purple-200' : severityTone(selectedIncident.threat_classification) === 'normal' ? 'text-emerald-200' : 'text-slate-100'}`}>{selectedIncident.threat_classification}</p>
              </div>
              <div className="rounded-2xl border border-white/[0.08] bg-gradient-to-b from-white/[0.04] to-white/[0.015] p-3.5">
                <span className="text-[13px] font-normal text-slate-400">First Detected</span>
                <p className="mt-1 font-mono text-sm text-slate-200" title={formatIncidentDate(selectedIncident.first_detected_at, 'datetime')}>
                  {formatIncidentDate(selectedIncident.first_detected_at, 'time')}
                </p>
              </div>
              <div className="rounded-2xl border border-white/[0.08] bg-gradient-to-b from-white/[0.04] to-white/[0.015] p-3.5">
                <span className="text-[13px] font-normal text-slate-400">Flow Count</span>
                <p className="mt-1 font-mono text-xs font-semibold tabular-nums text-slate-100">{selectedIncident.flow_count || 1}</p>
              </div>
            </div>

            {selectedIncident.evidence?.score_summary && (() => {
              const rawJson = JSON.stringify(selectedIncident.evidence.risk_breakdown || {}, null, 2);
              return <div className="rounded-2xl border border-white/[0.07] bg-gradient-to-br from-[var(--soc-panel)] to-[var(--soc-raised)] p-4 shadow-[inset_0_1px_rgba(255,255,255,.035)]">
                <h4 className="mb-2 text-[14px] font-normal text-slate-300">Model score summary</h4>
                <p className="text-[14px] tabular-nums text-slate-200">Score mean {formatFixed(selectedIncident.evidence.score_summary.mean, 4)} · min {formatFixed(selectedIncident.evidence.score_summary.min, 4)} · max {formatFixed(selectedIncident.evidence.score_summary.max, 4)} · {selectedIncident.evidence.score_summary.count} scored flows</p>
                {selectedIncident.evidence.review_text && <p className="mt-2 text-xs text-amber-200">{selectedIncident.evidence.review_text}</p>}
                <JsonCodeViewer key={selectedIncident.incident_id} value={rawJson} lineCount={rawJson.split('\n').length} />
              </div>;
            })()}

            {selectedIncident.threat_classification === 'RULE_CORRELATED_SUSPICIOUS_ACTIVITY' && (
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-4 space-y-4">
                <p className="text-xs font-semibold text-amber-200">Correlated suspicious activity; not a confirmed attack.</p>
                <div>
                  <h4 className="mb-2 text-[14px] font-normal text-slate-300">Attack sequence</h4>
                  {(selectedIncident.attack_sequence || []).length > 0 ? <ol className="ml-2 space-y-3 border-l border-blue-300/20">
                    {(selectedIncident.attack_sequence || []).map((stage, index) => (
                      <li key={`${stage.indicator}-${index}`} className="pl-4 relative">
                        <span className="absolute -left-[5px] top-1.5 h-2 w-2 rounded-full bg-blue-300 shadow-[0_0_10px_rgba(96,165,250,.3)]" />
                        <div className="text-xs font-semibold text-slate-100">{index + 1}. {stage.indicator || stage.stage}</div>
                        <div className="font-mono text-[11px] text-slate-400">{new Date(stage.timestamp).toLocaleString()} · {stage.layer} · events: {(stage.event_ids || []).join(', ')}</div>
                        <pre className="mt-1 whitespace-pre-wrap break-all font-mono text-[11px] text-slate-300">{JSON.stringify(stage.evidence || {}, null, 2)}</pre>
                      </li>
                    ))}
                  </ol> : <p className="text-xs text-slate-400">No attack sequence is stored for this incident.</p>}
                </div>
                <div>
                  <h4 className="mb-1 text-[14px] font-normal text-slate-300">Risk component breakdown</h4>
                  <pre className="whitespace-pre-wrap font-mono text-[11px] text-slate-300">{JSON.stringify(selectedIncident.evidence?.risk_breakdown || selectedIncident.risk_score_detail?.risk_breakdown || {}, null, 2)}</pre>
                </div>
              </div>
            )}

            {/* MITRE ATT&CK Mapping */}
            <div>
              <h4 className="mb-2 text-[14px] font-normal text-slate-300">
                Evidence-Gated MITRE ATT&CK Techniques
              </h4>
              {(selectedIncident.mitre_mappings || []).length > 0 ? <div className="flex flex-wrap gap-2">
                {(selectedIncident.mitre_mappings || []).map((m, idx) => (
                  <div
                    key={m.technique_id || `${m.technique_name || 'technique'}-${m.tactic || idx}`}
                    className="flex items-center gap-2 rounded-xl border border-blue-300/15 bg-blue-300/[0.045] px-3 py-2 text-xs"
                  >
                    <span className="font-mono font-bold text-blue-200">{m.technique_id}</span>
                    <span className="text-slate-300">{m.technique_name}</span>
                    <span className="text-[11px] text-slate-400">({m.tactic})</span>
                  </div>
                ))}
              </div> : <p className="text-xs text-slate-400">No evidence-gated techniques are mapped to this incident.</p>}
            </div>

            {/* Investigation Notes & Audit Log */}
            <div className="space-y-3">
              <h4 className="text-[14px] font-normal text-slate-300">
                Analyst Investigation Notes
              </h4>

              {/* Add Note Form */}
              {canInvestigate && <form onSubmit={handleAddNote} className="flex gap-2">
                <input
                  type="text"
                  placeholder="Add triage note, containment action, or forensic finding..."
                  value={newNote}
                  onChange={(e) => setNewNote(e.target.value)}
                  className="min-w-0 flex-1 rounded-xl border border-white/[0.09] bg-slate-950/45 px-3.5 py-2.5 text-xs text-slate-100 placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-400/25"
                />
                <button
                  type="submit"
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-xl border border-blue-300/20 bg-gradient-to-r from-blue-600 to-violet-600 px-4 py-2.5 text-xs font-semibold text-white transition hover:brightness-110 active:scale-[.98] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-300"
                >
                  <Send aria-hidden="true" className="h-3.5 w-3.5" /> Save Note
                </button>
              </form>}

              {/* Notes List */}
              {(selectedIncident.notes || []).length > 0 ? <ol className="space-y-3 border-l border-blue-300/20 pl-4">
                {(selectedIncident.notes || []).map((note, idx) => (
                  <li key={note.created_at || `${note.author || 'note'}-${idx}`} className="relative rounded-2xl border border-white/[0.07] bg-white/[0.025] p-3.5 text-sm">
                    <span aria-hidden="true" className="absolute -left-[21px] top-4 h-2.5 w-2.5 rounded-full border-2 border-[var(--soc-panel)] bg-blue-300 shadow-[0_0_10px_rgba(96,165,250,.25)]" />
                    <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2 text-slate-400">
                      <span className="font-semibold text-slate-200">{note.author}</span>
                      <time className="font-mono text-[13px] tabular-nums" title={formatIncidentDate(note.created_at, 'datetime')}>{formatIncidentDate(note.created_at, 'time')}</time>
                    </div>
                    <p className="leading-relaxed text-slate-200">{note.content}</p>
                  </li>
                ))}
              </ol> : <EmptyState icon={Clock3} title="No investigation notes yet" description="Analyst notes will appear here as the investigation progresses." className="min-h-24 border-0 bg-transparent py-4" />}
            </div>
          </div>
        ) : (
          <EmptyState icon={ShieldAlert} title="No correlated incidents yet." description="Load synthetic demo events from Data Management, then run correlation here. Matching rules produce alerts; an incident requires three indicator types across two layers." className="min-h-[26rem] border-0 bg-transparent" />
        )}
      </Card>
      </div>

      {correlationAlerts.length > 0 && (
        <Card className="incident-entrance p-4 sm:p-5">
          <h3 className="mb-3 text-sm font-semibold text-slate-100">Rule indicator alerts</h3>
          <div className="space-y-2">
            {correlationAlerts.map((alert, index) => (
              <div key={`${alert.name}-${index}`} className="rounded-xl border border-white/[0.07] bg-slate-950/30 p-3.5">
                <div className="flex flex-wrap justify-between gap-2 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-semibold text-blue-200">{alert.name.replaceAll('_', ' ')}</span>
                    {alert.is_demo && <Badge tone="medium" className="px-2 py-0.5 text-[11px]">DEMO</Badge>}
                    <span className="rounded-full border border-blue-300/20 bg-blue-300/[0.06] px-2 py-0.5 text-[11px] font-bold text-blue-200">RULE-CORRELATED</span>
                  </div>
                  <span className="font-mono text-[11px] tabular-nums text-slate-400">{new Date(alert.timestamp).toLocaleString()} · {alert.layer}</span>
                </div>
                {alert.scenario && <p className="mt-1 text-[11px] text-amber-200">Demo scenario: {alert.scenario.replaceAll('_', ' ')}</p>}
                <p className="mt-1 text-[11px] text-slate-300">{alert.rule}</p>
                <p className="mt-1 font-mono text-[11px] text-slate-400">Evidence event IDs: {(alert.event_ids || []).join(', ')}</p>
              </div>
            ))}
          </div>
        </Card>
      )}
    </div>
  );
}

