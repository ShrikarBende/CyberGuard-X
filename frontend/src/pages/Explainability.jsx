import React, { useState, useEffect } from 'react';
import { Sparkles, X, ClipboardCheck, LoaderCircle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from 'recharts';
import { api } from '../services/api';
import RiskFusion from '../components/RiskFusion';
import ChartTooltip from '../charts/ChartTooltip';
import { chartTheme } from '../charts/chartTheme';
import { prefersReducedMotion } from '../lib/motion';
import Modal from '../components/ui/Modal';

const readable = (value) => value == null ? '—' : (typeof value === 'string' ? value : JSON.stringify(value, null, 2));

function EvidenceList({ title, rows, empty }) {
  return <section className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-5">
    <h3 className="mb-3 text-xs font-bold uppercase tracking-wider text-slate-300">{title}</h3>
    {!rows?.length ? <p className="text-xs text-slate-500">{empty}</p> : <div className="max-h-64 space-y-2 overflow-auto">
      {rows.map((row, index) => <div key={`${row.event_id || row.feature || 'evidence'}-${index}`} className="rounded-xl border border-[#1E293B] bg-[#0D1527] p-3">
        {row.event_id && <p className="mb-1 text-[10px] font-mono text-slate-500">Event {row.event_id}</p>}
        <pre className="whitespace-pre-wrap break-words text-[11px] text-slate-300">{readable(row.top_features || row.attention || row.edge_attention || row.top_suspicious_edges || row.evidence || row)}</pre>
        {row.centroid_distance != null && <p className="mt-2 text-[11px] text-amber-300">Centroid distance: {Number(row.centroid_distance).toFixed(4)}</p>}
      </div>)}
    </div>}
  </section>;
}

export default function Explainability() {
  const [incidents, setIncidents] = useState([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [explanation, setExplanation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [investigation, setInvestigation] = useState(null);
  const [investigationOpen, setInvestigationOpen] = useState(false);
  const [investigationLoading, setInvestigationLoading] = useState(false);
  const [investigationError, setInvestigationError] = useState('');

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
      } catch (err) { console.error('Failed to load explainability data:', err); }
      finally { if (active) setLoading(false); }
    }
    loadIncidents();
    return () => { active = false; };
  }, []);

  const handleSelectIncident = async (id) => {
    setSelectedIncidentId(id);
    setInvestigation(null);
    setLoading(true);
    try { setExplanation(await api.getExplainability(id)); }
    catch (err) { console.error(err); setExplanation(null); }
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

  if (!loading && incidents.length === 0) return <div className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-8 text-center text-slate-300">No incidents to explain yet.</div>;

  return <div className="space-y-5">
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[#1E293B] bg-[#10182E] p-4">
      <div><h3 className="flex items-center gap-2 text-sm font-bold text-slate-100"><Sparkles className="h-4 w-4 text-purple-400" /> Multi-modal explainability</h3><p className="mt-1 text-xs text-slate-400">Unified risk, model contributions, and stored branch evidence.</p></div>
      <div className="flex flex-wrap gap-2">
        <select value={selectedIncidentId} onChange={(e) => handleSelectIncident(e.target.value)} className="rounded-xl border border-[#1E293B] bg-[#0D1527] px-3 py-2 text-xs text-slate-200">
          {incidents.map((inc) => <option key={inc.incident_id} value={inc.incident_id}>{inc.title} · {inc.severity}</option>)}
        </select>
        <button disabled={!selectedIncidentId || investigationLoading} onClick={runInvestigation} className="flex items-center gap-2 rounded-xl bg-purple-600 px-3 py-2 text-xs font-semibold text-white disabled:opacity-50"><ClipboardCheck className="h-4 w-4" /> Run 5-step investigation</button>
      </div>
    </div>

    {explanation?.available === false && <div className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-5 text-xs text-slate-300">{explanation.reason}</div>}
    {explanation && <>
      <RiskFusion explanation={explanation} />
      <div className="grid gap-5 xl:grid-cols-2">
        <section className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">TreeSHAP feature attributions</h3><p className="mb-3 mt-1 text-[11px] text-slate-500">Signed values show whether each feature raises or lowers the predicted class score.</p>
          {chartData.length ? <div className="h-64"><ResponsiveContainer width="100%" height="100%"><BarChart data={chartData} layout="vertical" margin={{ top: 4, right: 12, left: 60, bottom: 4 }}><CartesianGrid strokeDasharray="3 5" stroke={chartTheme.grid} horizontal={false} /><XAxis type="number" tick={{ fill: chartTheme.axis, fontSize: 10, fontFamily: 'var(--soc-font-mono)' }} axisLine={false} tickLine={false} /><YAxis dataKey="feature" type="category" tick={{ fill: chartTheme.axis, fontSize: 10 }} axisLine={false} tickLine={false} width={120} /><Tooltip content={<ChartTooltip formatter={(_v, _n, context) => [`${context.payload.signedValue.toFixed(6)}`, 'SHAP']} />} /><Bar dataKey="importance" radius={[0, 5, 5, 0]} isAnimationActive={!prefersReducedMotion()} animationDuration={750}>{chartData.map((row, index) => <Cell key={index} fill={row.signedValue >= 0 ? '#fb5b68' : '#579cff'} />)}</Bar></BarChart></ResponsiveContainer></div> : <p className="mt-4 text-xs text-slate-500">No TreeSHAP values are stored for this incident.</p>}
        </section>
        <section className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-5">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300">Open-set novelty</h3>
          {!modalities.open_set_novelty?.length ? <p className="mt-3 text-xs text-slate-500">No novelty flags are associated with this incident.</p> : <div className="mt-3 space-y-2">{modalities.open_set_novelty.map((row, i) => <div key={i} className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 text-xs"><div className="flex justify-between gap-2"><span className="font-bold text-amber-200">{row.label || 'UNKNOWN_NOVEL'}</span><span className="font-mono text-amber-300">Distance {row.centroid_distance == null ? '—' : Number(row.centroid_distance).toFixed(4)}</span></div><p className="mt-1 text-slate-400">{row.rationale || 'No novelty rationale recorded.'}</p></div>)}</div>}
        </section>
        <EvidenceList title="Endpoint DAE reconstruction residuals" rows={modalities.endpoint_reconstruction_residuals} empty="No endpoint residuals are stored." />
        <EvidenceList title="User sequence TFT temporal attention" rows={modalities.user_temporal_attention} empty="No temporal attention steps are stored." />
        <div className="xl:col-span-2"><EvidenceList title="Network GAT edge attention" rows={modalities.network_graph_edge_attention} empty="No graph edge attention is stored." /></div>
      </div>
    </>}
    {loading && <p className="text-xs text-slate-500">Loading incident evidence…</p>}

    <Modal open={investigationOpen} onClose={() => setInvestigationOpen(false)} title="Agentic investigation report" side className="h-full rounded-l-2xl border-l border-[#26344D] bg-[#0A0F1D] p-5 shadow-2xl sm:p-7">
        <div className="mb-5 flex items-start justify-between gap-3"><div><p className="text-[10px] font-bold uppercase tracking-widest text-purple-300">Read-only workflow</p><h2 className="mt-1 text-lg font-bold text-white">Agentic investigation report</h2><p className="mt-1 text-xs text-slate-400">retrieve → analyze → map → summarize → recommend</p></div><button onClick={() => setInvestigationOpen(false)} className="rounded-lg border border-[#26344D] p-2 text-slate-300" aria-label="Close investigation"><X className="h-4 w-4" /></button></div>
        {investigationLoading && <div className="flex items-center gap-2 py-8 text-sm text-slate-400"><LoaderCircle className="h-4 w-4 animate-spin" /> Gathering cited evidence…</div>}
        {investigationError && <p role="alert" className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">{investigationError}</p>}
        {investigation && <>
          <div className="mb-4 rounded-xl border border-blue-500/30 bg-blue-500/10 p-3 text-xs text-blue-100">Read-only report. It does not execute containment or remediation actions.</div>
          <div className="space-y-4">{(investigation.trace || []).map((step, index) => <section key={step.step} className="rounded-xl border border-[#1E293B] bg-[#10182E] p-4">
            <div className="mb-2 flex items-center gap-2"><span className="flex h-6 w-6 items-center justify-center rounded-full bg-purple-500/15 text-[11px] font-bold text-purple-300">{index + 1}</span><h3 className="text-xs font-bold uppercase tracking-wider text-slate-200">{step.step}</h3></div>
            {step.step === 'retrieve' && <><p className="mb-2 text-xs text-slate-400">{step.evidence_sufficient ? 'Retrieved sources meet the evidence threshold.' : 'Evidence is insufficient for grounded mapping.'}</p><div className="space-y-2">{(step.results || []).map((source, i) => <div key={`${source.doc_id}-${i}`} className="rounded-lg bg-[#0D1527] p-2.5"><div className="flex justify-between gap-2 text-[11px]"><span className="font-semibold text-blue-200">{source.title || source.doc_id}</span><span className="font-mono text-slate-500">{source.source_type} · {Number(source.relevance_score || 0).toFixed(2)}</span></div><p className="mt-1 line-clamp-3 text-[10px] text-slate-400">{source.text}</p><p className="mt-1 font-mono text-[9px] text-slate-600">Citation: {source.chunk_id || source.doc_id}</p></div>)}</div></>}
            {step.step === 'analyze' && <><p className="text-xs text-slate-300">Risk score {step.risk_score} · {step.severity}</p><pre className="mt-2 whitespace-pre-wrap break-words text-[10px] text-slate-400">{JSON.stringify({ layer_scores: step.layer_scores, risk_contributions: step.risk_contributions, evidence_signals: step.evidence_signals }, null, 2)}</pre></>}
            {step.step === 'map' && <><p className="text-xs text-slate-300">{step.statement}</p>{(step.mitre_attack || []).map((mapping, i) => <div key={i} className="mt-2 rounded-lg bg-[#0D1527] p-2 text-xs text-slate-300">{mapping.technique_id} · {mapping.technique_name} <span className="text-slate-500">(evidence: {(mapping.evidence_terms || []).join(', ')})</span></div>)}</>}
            {step.step === 'summarize' && <><p className="text-xs leading-relaxed text-slate-300">{step.executive_summary}</p><ol className="mt-3 space-y-1">{(step.timeline || []).map((item, i) => <li key={i} className="text-[10px] text-slate-400">{item.timestamp} · {item.layer} · {item.indicator || item.stage}</li>)}</ol></>}
            {step.step === 'recommend' && <><p className="text-xs text-slate-400">{step.statement}</p>{(step.actions || []).map((action, i) => <p key={i} className="mt-2 rounded-lg bg-[#0D1527] p-2 text-xs text-slate-300">{action.action}</p>)}<div className="mt-3 rounded-lg border border-amber-500/40 bg-amber-500/10 p-3 text-xs font-bold text-amber-200">Analyst approval required before any recommended action. No action was executed.</div></>}
          </section>)}</div>
        </>}
    </Modal>
  </div>;
}
