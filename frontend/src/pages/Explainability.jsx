import React, { useState, useEffect, useRef } from 'react';
import { gsap } from 'gsap';
import { Activity, AlertCircle, ClipboardCheck, Database, LoaderCircle, Network, Sparkles, UserRound, X } from '../lib/icons';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid, LabelList } from 'recharts';
import { api } from '../services/api';
import RiskFusion from '../components/RiskFusion';
import ChartTooltip from '../charts/ChartTooltip';
import { chartTheme } from '../charts/chartTheme';
import { createMotionScope, motion, prefersReducedMotion } from '../lib/motion';
import Modal from '../components/ui/Modal';
import Badge from '../components/ui/Badge';
import Button from '../components/ui/Button';
import EmptyState from '../components/ui/EmptyState';
import Skeleton from '../components/ui/Skeleton';

const readable = (value) => value == null ? '—' : (typeof value === 'string' ? value : JSON.stringify(value, null, 2));

function FeatureTick({ x, y, payload }) {
  const full = String(payload?.value || '');
  const shown = full.length > 19 ? `${full.slice(0, 18)}…` : full;
  return <g transform={`translate(${x},${y})`}><title>{full}</title><text x={-8} y={4} textAnchor="end" fill="var(--soc-muted)" fontSize={11}>{shown}</text></g>;
}

function SignedValueLabel({ x, y, width, value }) {
  return <text x={Number(value) >= 0 ? x + width + 5 : x - 5} y={y + 4} textAnchor={Number(value) >= 0 ? 'start' : 'end'} fill="var(--soc-muted)" fontSize={11} fontFamily="var(--soc-font-mono)">{Number(value).toFixed(4)}</text>;
}

function EvidenceList({ title, rows, empty, icon: Icon = Database }) {
  return <section className="soc-card min-w-0 rounded-2xl p-4 sm:p-5">
    <h3 className="mb-3 text-xs font-bold uppercase tracking-wider text-slate-300">{title}</h3>
    {!rows?.length ? <EmptyState icon={Icon} title={empty} className="min-h-28 rounded-xl px-3 py-4" /> : <div className="max-h-64 space-y-2 overflow-auto">
      {rows.map((row, index) => <div key={`${row.event_id || row.feature || 'evidence'}-${index}`} className="rounded-xl border border-[var(--line)] bg-white p-3">
        {row.event_id && <p className="mb-1 text-xs font-mono text-slate-500">Event {row.event_id}</p>}
        <pre className="whitespace-pre-wrap break-words text-xs text-slate-300">{readable(row.top_features || row.attention || row.edge_attention || row.top_suspicious_edges || row.evidence || row)}</pre>
        {row.centroid_distance != null && <p className="mt-2 text-xs text-amber-200">Centroid distance: <span className="font-mono tabular-nums">{Number(row.centroid_distance).toFixed(4)}</span></p>}
      </div>)}
    </div>}
  </section>;
}

export default function Explainability() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState('');
  const [investigation, setInvestigation] = useState(null);
  const [investigationOpen, setInvestigationOpen] = useState(false);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [investigationError, setInvestigationError] = useState('');
  const pageRef = useRef(null);
  const animatedReport = useRef(null);

  useEffect(() => createMotionScope(pageRef, (reduced) => {
    if (!investigation || investigationLoading || animatedReport.current === investigation) return;
    const steps = pageRef.current?.querySelectorAll('[data-investigation-step]');
    if (!steps?.length) return;
    animatedReport.current = investigation;
    gsap.set(steps, { opacity: 0, y: reduced ? 0 : 12 });
    gsap.to(steps, { opacity: 1, y: 0, duration: reduced ? 0.18 : 0.45, ease: motion.ease, stagger: reduced ? 0 : 0.07, clearProps: 'all' });
  }), [investigation, investigationLoading]);

  useEffect(() => {
    let active = true;
    async function loadIncidents() {
      try {
        const data = await api.getIncidents();
        if (!active) return;
        setIncidents(data);
        if (data.length > 0) {
          setSelectedIncidentId(data[0].incident_id);
          setExplanation(await api.getExplainability(data[0].incident_id));
        }
      } catch (err) { console.error('Failed to load explainability data:', err); if (active) setLoadError(err.message || 'Explainability data could not be loaded.'); }
      finally { if (active) setLoading(false); }
    }
    loadIncidents();
    return () => { active = false; };
  }, []);

  const handleSelectIncident = async (id) => {
    setSelectedIncidentId(id);
    setInvestigation(null);
    setLoading(true);
    setLoadError('');
    try { setExplanation(await api.getExplainability(id)); }
    catch (err) { console.error(err); setExplanation(null); setLoadError(err.message || 'Explanation data could not be loaded.'); }
    finally { setLoading(false); }
  };

  const runInvestigation = async () => {
    setInvestigationOpen(true);
    setInvestigationLoading(true);
    setInvestigationError('');
    try { setInvestigation(await api.investigateIncident(selectedIncidentId)); }
    catch (err) { setInvestigationError(err.message || 'Investigation could not be loaded.'); }
    finally { setInvestigationLoading(false); }
  };

  const chartData = (explanation?.explanations?.tree_shap_feature_attributions || explanation?.shap_feature_importance || []).map((item) => ({
    feature: String(item.feature || 'feature').replace(/_/g, ' '), importance: Math.abs(Number(item.value || 0)), signedValue: Number(item.value || 0),
  }));
  const modalities = explanation?.explanations || {};
  const noveltyRows = modalities.open_set_novelty || [];
  const maxNoveltyDistance = Math.max(0, ...noveltyRows.map((row) => Number(row.centroid_distance)).filter(Number.isFinite));

  if (!loading && incidents.length === 0 && !loadError) return <div className="mx-auto max-w-[1600px]"><EmptyState icon={AlertCircle} title="No incidents to explain yet." description="Incident records will appear here when they are available." className="soc-card" /></div>;

  return <div ref={pageRef} className="mx-auto w-full max-w-[1600px] space-y-5">
    <header><h1 className="font-display text-3xl font-bold leading-tight tracking-tight text-[var(--ink)]">SHAP Explainability &amp; Risk Scoring</h1><p className="mt-1 text-sm text-[var(--muted)]">Unified risk, model contributions, and stored branch evidence.</p></header>
    <div className="soc-card flex flex-wrap items-center justify-between gap-4 rounded-2xl p-4 sm:p-5">
      <div><h3 className="flex items-center gap-2 text-sm font-bold text-slate-100"><Sparkles className="h-4 w-4 text-purple-300" /> Multi-modal explainability</h3><p className="mt-1 text-xs text-slate-400">Unified risk, model contributions, and stored branch evidence.</p></div>
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor="explainability-incident" className="sr-only">Select incident</label>
        <select id="explainability-incident" value={selectedIncidentId} onChange={(e) => handleSelectIncident(e.target.value)} className="min-w-56 rounded-xl border border-white/[0.1] bg-[var(--soc-panel)] px-3 py-2.5 text-xs text-slate-200 outline-none transition focus-visible:ring-2 focus-visible:ring-blue-400">
          {incidents.map((inc) => <option key={inc.incident_id} value={inc.incident_id}>{inc.title} · {inc.severity}</option>)}
        </select>
        <Button type="button" variant="primary" disabled={!selectedIncidentId || investigationLoading} onClick={runInvestigation} className="min-h-10"><ClipboardCheck className="h-4 w-4" /> Run 5-step investigation</Button>
      </div>
    </div>

    {loadError && <div role="alert" className="soc-card rounded-2xl border-rose-400/20 p-4 text-xs text-rose-200">{loadError}</div>}
    {loading && !explanation && !loadError && <div aria-busy="true" className="grid gap-4"><p className="text-xs text-slate-400">Loading incident evidence…</p><Skeleton className="h-44 rounded-2xl" /><div className="grid gap-4 lg:grid-cols-2"><Skeleton className="h-64 rounded-2xl" /><Skeleton className="h-36 rounded-2xl" /></div></div>}
    {explanation?.available === false && <div className="soc-card rounded-2xl p-5 text-xs text-slate-300">{explanation.reason}</div>}
    {explanation && <>
      <RiskFusion explanation={explanation} />
      <div className="grid gap-4 xl:grid-cols-3">
        <section className="soc-card rounded-2xl p-4 sm:p-5 xl:col-span-2">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">TreeSHAP feature attributions</h3><p className="mb-3 mt-1 text-xs text-slate-500">Signed values show whether each feature raises or lowers the predicted class score.</p>
          {chartData.length ? <div className="h-72"><ResponsiveContainer width="100%" height="100%"><BarChart data={chartData} layout="vertical" margin={{ top: 8, right: 42, left: 112, bottom: 8 }}><CartesianGrid strokeDasharray="3 5" stroke={chartTheme.grid} horizontal={false} /><XAxis type="number" domain={['dataMin', 'dataMax']} tick={{ fill: chartTheme.axis, fontSize: 10, fontFamily: 'var(--soc-font-mono)' }} axisLine={false} tickLine={false} /><YAxis dataKey="feature" type="category" tick={<FeatureTick />} axisLine={false} tickLine={false} width={112} /><Tooltip cursor={{ fill: 'rgba(255,255,255,0.04)' }} content={<ChartTooltip formatter={(_v, _n, context) => [`${context.payload.signedValue.toFixed(6)}`, 'SHAP']} />} /><Bar dataKey="signedValue" radius={[0, 5, 5, 0]} isAnimationActive={!prefersReducedMotion()} animationDuration={400}>{chartData.map((row, index) => <Cell key={index} fill={row.signedValue >= 0 ? 'var(--soc-critical)' : 'var(--soc-low)'} />)}<LabelList dataKey="signedValue" content={<SignedValueLabel />} /></Bar></BarChart></ResponsiveContainer></div> : <EmptyState icon={Activity} title="No TreeSHAP values are stored for this incident." className="min-h-28 rounded-xl px-3 py-4" />}
        </section>
        <section className="soc-card rounded-2xl p-4 sm:p-5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Open-set novelty</h3>
          {!modalities.open_set_novelty?.length ? <EmptyState icon={AlertCircle} title="No novelty flags are associated with this incident." className="mt-3 min-h-28 rounded-xl px-3 py-4" /> : <div className="mt-3 space-y-2">{noveltyRows.map((row, i) => { const distance = Number(row.centroid_distance); const meter = maxNoveltyDistance > 0 && Number.isFinite(distance) ? Math.max(0, Math.min(1, distance / maxNoveltyDistance)) : 0; return <div key={i} className="rounded-xl border border-purple-400/15 bg-purple-400/[0.045] p-3 text-xs"><div className="flex flex-wrap justify-between gap-2"><Badge tone="novel">{row.label || 'UNKNOWN_NOVEL'}</Badge><span className="font-mono tabular-nums text-purple-200">Distance {row.centroid_distance == null ? '—' : distance.toFixed(4)}</span></div><div className="mt-2 h-1 overflow-hidden rounded-full bg-white/[0.07]" aria-hidden="true"><div className="h-full rounded-full bg-purple-400" style={{ width: `${meter * 100}%` }} /></div><p className="mt-2 text-slate-400">{row.rationale || 'No novelty rationale recorded.'}</p></div>; })}</div>}
        </section>
        <EvidenceList title="Endpoint DAE reconstruction residuals" rows={modalities.endpoint_reconstruction_residuals} empty="No endpoint residuals are stored." icon={Database} />
        <EvidenceList title="User sequence TFT temporal attention" rows={modalities.user_temporal_attention} empty="No temporal attention steps are stored." icon={UserRound} />
        <EvidenceList title="Network GAT edge attention" rows={modalities.network_graph_edge_attention} empty="No graph edge attention is stored." icon={Network} />
      </div>
    </>}
    {loading && <p className="text-xs text-slate-500">Loading incident evidence…</p>}

    <Modal open={investigationOpen} onClose={() => setInvestigationOpen(false)} title="Agentic investigation report" side className="h-full rounded-l-2xl border-l border-white/[0.08] bg-[var(--soc-bg)] p-5 shadow-2xl sm:p-7">
        <div className="mb-5 flex items-start justify-between gap-3"><div><p className="text-xs font-bold uppercase tracking-widest text-purple-300">Read-only workflow</p><h2 className="mt-1 text-lg font-bold text-white">Agentic investigation report</h2><p className="mt-1 text-xs text-slate-400">retrieve → analyze → map → summarize → recommend</p></div><button onClick={() => setInvestigationOpen(false)} className="rounded-lg border border-white/10 p-2 text-slate-300 transition hover:bg-white/[0.06] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400" aria-label="Close investigation"><X className="h-4 w-4" /></button></div>
        {investigationLoading && <div className="space-y-5 py-4" aria-live="polite" aria-busy="true"><div className="flex items-center gap-2 rounded-xl border border-blue-400/15 bg-blue-400/[0.05] p-3 text-sm text-slate-300"><LoaderCircle className="h-4 w-4 animate-spin text-blue-300" /> Gathering cited evidence…</div><ol aria-label="Investigation progress" className="grid grid-cols-5 gap-2">{['retrieve', 'analyze', 'map', 'summarize', 'recommend'].map((step) => <li key={step} className="flex min-w-0 flex-col items-center gap-2 text-center"><span className="h-2.5 w-2.5 rounded-full border border-slate-500 bg-slate-800" /><span className="text-xs font-medium text-slate-400">{step}</span></li>)}</ol><p className="text-xs text-slate-500">The investigation request is running; step-level status will appear with the returned report.</p></div>}
        {investigationError && <p role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">{investigationError}</p>}
        {investigation && <>
          <div className="mb-4 rounded-xl border border-blue-500/30 bg-blue-500/10 p-3 text-xs text-blue-100">Read-only report. It does not execute containment or remediation actions.</div>
          <div className="space-y-4">{(investigation.trace || []).map((step, index) => <section data-investigation-step key={step.step} className="soc-card rounded-xl p-4">
            <div className="mb-2 flex items-center gap-2"><span className="flex h-6 w-6 items-center justify-center rounded-full bg-purple-500/15 text-xs font-bold text-purple-300">{index + 1}</span><h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">{step.step}</h3><Badge tone="normal" className="ml-auto">Returned</Badge></div>
            {step.step === 'retrieve' && <><p className="mb-2 text-xs text-slate-400">{step.evidence_sufficient ? 'Retrieved sources meet the evidence threshold.' : 'Evidence is insufficient for grounded mapping.'}</p><div className="space-y-2">{(step.results || []).map((source, i) => <div key={`${source.doc_id}-${i}`} className="rounded-lg bg-white p-2.5"><div className="flex justify-between gap-2 text-xs"><span className="font-semibold text-blue-200">{source.title || source.doc_id}</span><span className="font-mono text-slate-500">{source.source_type} · {Number(source.relevance_score || 0).toFixed(2)}</span></div><p className="mt-1 line-clamp-3 text-xs text-slate-400">{source.text}</p><p className="mt-1 font-mono text-xs text-slate-600">Citation: {source.chunk_id || source.doc_id}</p></div>)}</div></>}
            {step.step === 'analyze' && <><p className="text-xs text-slate-300">Risk score {step.risk_score} · {step.severity}</p><pre className="mt-2 whitespace-pre-wrap break-words text-xs text-slate-400">{JSON.stringify({ layer_scores: step.layer_scores, risk_contributions: step.risk_contributions, evidence_signals: step.evidence_signals }, null, 2)}</pre></>}
            {step.step === 'map' && <><p className="text-xs text-slate-300">{step.statement}</p>{(step.mitre_attack || []).map((mapping, i) => <div key={i} className="mt-2 rounded-lg bg-white p-2 text-xs text-slate-300">{mapping.technique_id} · {mapping.technique_name} <span className="text-slate-500">(evidence: {(mapping.evidence_terms || []).join(', ')})</span></div>)}</>}
            {step.step === 'summarize' && <><p className="text-xs leading-relaxed text-slate-300">{step.executive_summary}</p><ol className="mt-3 space-y-1">{(step.timeline || []).map((item, i) => <li key={i} className="text-xs text-slate-400">{item.timestamp} · {item.layer} · {item.indicator || item.stage}</li>)}</ol></>}
            {step.step === 'recommend' && <><p className="text-xs text-slate-400">{step.statement}</p>{(step.actions || []).map((action, i) => <p key={i} className="mt-2 rounded-lg bg-white p-2 text-xs text-slate-300">{action.action}</p>)}<div className="mt-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs font-bold text-amber-200">Analyst approval required before any recommended action. No action was executed.</div></>}
          </section>)}</div>
        </>}
    </Modal>
  </div>;
}
