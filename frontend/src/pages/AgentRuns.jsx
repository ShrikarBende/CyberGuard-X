import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { api } from '../services/api';
import Card from '../components/ui/Card';

const activeStatuses = new Set(['queued', 'running']);
const statusStyles = {
  queued: 'border-blue-300/20 text-blue-100', running: 'border-blue-300/20 text-blue-100',
  completed: 'border-emerald-300/20 text-emerald-100', completed_fallback: 'border-amber-300/20 text-amber-100',
  limit_reached: 'border-amber-300/20 text-amber-100', failed: 'border-rose-300/20 text-rose-100',
  cancelled: 'border-slate-300/20 text-slate-200',
};

function EvidenceChips({ values = [] }) {
  if (!values.length) return <span className="text-xs text-slate-500">No evidence IDs</span>;
  return <div className="mt-2 flex flex-wrap gap-1.5">{values.map((id) => <span key={id} className="rounded-md border border-blue-300/15 bg-blue-300/[0.06] px-2 py-0.5 font-mono text-[10px] text-blue-100">{id}</span>)}</div>;
}

function Section({ title, children }) {
  return <section className="space-y-2"><h3 className="text-sm font-semibold text-slate-100">{title}</h3>{children}</section>;
}

function asList(items) {
  return Array.isArray(items) && items.length ? <ul className="list-disc space-y-1 pl-5 text-sm text-slate-300">{items.map((item, index) => <li key={`${index}-${String(item)}`}>{typeof item === 'string' ? item : JSON.stringify(item)}</li>)}</ul> : <p className="text-sm text-slate-500">None recorded.</p>;
}

export default function AgentRuns({ initialRunId = null }) {
  const [runs, setRuns] = useState([]);
  const [selectedRunId, setSelectedRunId] = useState(initialRunId);
  const [run, setRun] = useState(null);
  const [baseline, setBaseline] = useState(null);
  const [showBaseline, setShowBaseline] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => { setSelectedRunId(initialRunId); }, [initialRunId]);

  const refresh = useCallback(async () => {
    try {
      const values = await api.getAgentRuns('', 50);
      setRuns(values);
      setError('');
      if (!selectedRunId && values.length) setSelectedRunId(values[0].run_id);
    } catch (err) {
      setError(err.message || 'Agent runs could not be loaded.');
    } finally {
      setLoading(false);
    }
  }, [selectedRunId]);

  const refreshRun = useCallback(async () => {
    if (!selectedRunId) return;
    try {
      const value = await api.getAgentRun(selectedRunId);
      setRun(value);
      setRuns((previous) => [value, ...previous.filter((item) => item.run_id !== value.run_id)]);
      setError('');
    } catch (err) {
      setError(err.message || 'Agent run could not be loaded.');
    }
  }, [selectedRunId]);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => { setRun(null); setBaseline(null); setShowBaseline(false); refreshRun(); }, [refreshRun]);
  useEffect(() => {
    if (!selectedRunId || !activeStatuses.has(run?.status)) return undefined;
    const timer = window.setInterval(refreshRun, 1500);
    return () => window.clearInterval(timer);
  }, [selectedRunId, run?.status, refreshRun]);

  const toggleBaseline = async () => {
    const next = !showBaseline;
    setShowBaseline(next);
    if (next && run?.incident_id && !baseline) {
      try { setBaseline(await api.investigateIncident(run.incident_id)); }
      catch (err) { setError(err.message || 'Deterministic baseline could not be loaded.'); }
    }
  };

  const report = run?.report;
  const isFallback = run?.status === 'completed_fallback' || run?.mode === 'fallback';
  const validationSummary = useMemo(() => {
    if (!run?.validation) return '';
    const parts = [];
    if (run.validation.claims_dropped_no_evidence) parts.push(`${run.validation.claims_dropped_no_evidence} claims dropped: no evidence`);
    if (run.validation.techniques_dropped_unsupported) parts.push(`${run.validation.techniques_dropped_unsupported} unsupported ATT&CK mappings dropped`);
    if (run.validation.actions_dropped_invalid) parts.push(`${run.validation.actions_dropped_invalid} invalid actions dropped`);
    return parts.length ? parts.join(' · ') : 'Citation and action checks passed';
  }, [run?.validation]);

  return <div className="mx-auto w-full max-w-[1500px] space-y-5">
    <header><p className="text-xs uppercase tracking-[0.2em] text-violet-200">Agentic investigations</p><h1 className="mt-1 font-display text-3xl font-light text-slate-50">Run timeline and report</h1><p className="mt-2 text-sm text-slate-400">Agent output is advisory and grounded in evidence returned during this run.</p></header>
    {error && <div role="alert" className="rounded-xl border border-rose-500/25 bg-rose-500/[0.06] p-3 text-sm text-rose-200">{error}</div>}
    <Card className="p-4">
      <label htmlFor="agent-run-select" className="mb-2 block text-xs font-medium text-slate-400">Choose a run</label>
      <select id="agent-run-select" value={selectedRunId || ''} onChange={(event) => setSelectedRunId(event.target.value || null)} className="w-full rounded-xl border border-white/10 bg-slate-950/60 px-3 py-2.5 text-sm text-slate-100 focus:outline-none focus:ring-2 focus:ring-violet-300">
        <option value="">{loading ? 'Loading runs…' : 'No runs available'}</option>
        {runs.map((item) => <option key={item.run_id} value={item.run_id}>{item.incident_id} · {item.status} · {item.started_at ? new Date(item.started_at).toLocaleString() : 'queued'}</option>)}
      </select>
    </Card>

    {run && <>
      <Card className="flex flex-wrap items-center justify-between gap-3 p-4">
        <div><p className="font-mono text-xs text-slate-400">{run.run_id} · incident {run.incident_id}</p><p className="mt-1 text-lg font-semibold text-slate-100">{run.agent_id.replace('_', ' ')} <span className={`ml-2 rounded-full border px-2 py-0.5 text-xs font-medium ${statusStyles[run.status] || 'border-white/10 text-slate-300'}`}>{run.status}</span></p></div>
        <div className="text-right text-xs text-slate-400">{run.model_name} · {run.mode}<br />{run.usage?.llm_calls || 0} LLM calls · {run.usage?.tool_calls || 0} tool calls</div>
      </Card>

      <div className="grid gap-5 xl:grid-cols-[0.9fr_1.1fr]">
        <Card className="space-y-4 p-5">
          <Section title="Step timeline">
            {run.steps?.length ? <ol className="space-y-3">{run.steps.map((step) => <li key={step.id} className="relative rounded-xl border border-white/[0.07] bg-white/[0.02] p-3">
              <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-[10px] text-slate-500">#{step.step_no}</span><span className="rounded-md border border-white/10 px-2 py-0.5 text-[10px] uppercase text-slate-300">{step.kind}</span>{step.tool_name && <span className="font-mono text-xs text-blue-200">{step.tool_name}</span>}<span className={step.ok ? 'ml-auto text-xs text-emerald-300' : 'ml-auto text-xs text-rose-300'}>{step.ok ? 'OK' : 'Error'}</span><span className="text-[10px] text-slate-500">{step.duration_ms} ms</span></div>
              <p className="mt-2 whitespace-pre-wrap break-words text-xs leading-relaxed text-slate-300">{step.result_summary || 'Step recorded.'}</p>
              {step.evidence_ids?.length > 0 && <EvidenceChips values={step.evidence_ids} />}
            </li>)}</ol> : <p className="text-sm text-slate-500">{activeStatuses.has(run.status) ? 'Waiting for the first step…' : 'No steps were recorded.'}</p>}
          </Section>
        </Card>

        <Card className="space-y-5 p-5">
          <div className="flex flex-wrap items-center justify-between gap-2"><h2 className="text-lg font-semibold text-slate-100">Investigation report</h2><button type="button" onClick={toggleBaseline} className="rounded-lg border border-blue-300/20 px-3 py-1.5 text-xs text-blue-100 hover:bg-blue-300/[0.06]">{showBaseline ? 'Hide deterministic baseline' : 'Compare with deterministic baseline'}</button></div>
          {isFallback ? <div className="rounded-xl border border-amber-300/20 bg-amber-300/[0.05] p-3 text-sm text-amber-100">Agent unavailable; showing the deterministic investigation result.</div> : null}
          {run.status === 'limit_reached' ? <div className="rounded-xl border border-amber-300/20 bg-amber-300/[0.05] p-3 text-sm text-amber-100">The agent reached a run limit. The deterministic baseline is shown; review the saved steps for the partial trace.</div> : null}
          {report?.assessment && <div className="flex flex-wrap items-center gap-2"><span className="text-xs text-slate-400">Assessment</span><span className="rounded-full border border-violet-300/20 bg-violet-300/[0.06] px-3 py-1 text-xs font-semibold text-violet-100">{report.assessment.replaceAll('_', ' ')}</span></div>}
          {report?.summary && <p className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 text-sm leading-relaxed text-slate-200">{report.summary}</p>}
          {report?.key_findings && <Section title="Key findings"><div className="space-y-3">{report.key_findings.map((finding, index) => <article key={index} className="rounded-xl border border-white/[0.06] p-3"><p className="text-sm text-slate-200">{finding.claim}</p><EvidenceChips values={finding.evidence_ids} /></article>)}</div></Section>}
          {report?.attack_mapping && <Section title="ATT&CK mapping">{report.attack_mapping.length ? <div className="overflow-x-auto"><table className="w-full text-left text-xs"><thead className="text-slate-500"><tr><th className="p-2">Technique</th><th className="p-2">Rationale</th><th className="p-2">Evidence</th></tr></thead><tbody>{report.attack_mapping.map((mapping, index) => <tr key={`${mapping.technique_id}-${index}`} className="border-t border-white/[0.06]"><td className="p-2 font-mono text-blue-200">{mapping.technique_id}</td><td className="p-2 text-slate-300">{mapping.rationale}</td><td className="p-2"><EvidenceChips values={mapping.evidence_ids} /></td></tr>)}</tbody></table></div> : <p className="text-sm text-slate-500">No evidence-gated technique mappings.</p>}</Section>}
          {report?.hypotheses && <Section title="Hypotheses">{report.hypotheses.length ? report.hypotheses.map((hypothesis, index) => <article key={index} className="rounded-xl border border-white/[0.06] p-3"><p className="text-sm text-slate-200">{hypothesis.statement}</p><p className="mt-2 text-[11px] text-emerald-200">Supports</p><EvidenceChips values={hypothesis.supports} /><p className="mt-2 text-[11px] text-amber-200">Contradicts</p><EvidenceChips values={hypothesis.contradicts} /></article>) : <p className="text-sm text-slate-500">No hypotheses recorded.</p>}</Section>}
          {report?.missing_evidence && <Section title="Missing evidence">{asList(report.missing_evidence)}</Section>}
          {report?.limitations && <Section title="Limitations">{asList(report.limitations)}</Section>}
          {report?.recommended_actions && <Section title="Proposed actions">{report.recommended_actions.length ? report.recommended_actions.map((action, index) => <article key={index} className="rounded-xl border border-amber-300/15 bg-amber-300/[0.025] p-3"><p className="text-sm font-medium text-amber-100">{action.action_type} · {action.target_type} {action.target}</p><p className="mt-1 text-xs text-slate-300">{action.rationale}</p><EvidenceChips values={action.evidence_ids} /></article>) : <p className="text-sm text-slate-500">No proposed actions.</p>}</Section>}
          {run.validation && <div className="rounded-xl border border-emerald-300/15 bg-emerald-300/[0.04] px-3 py-2 text-xs text-emerald-100">Validation: {validationSummary}</div>}
          {showBaseline && <Section title="Deterministic baseline">{baseline ? <pre className="max-h-[28rem] overflow-auto whitespace-pre-wrap break-words rounded-xl border border-white/[0.07] bg-slate-950/50 p-3 font-mono text-[11px] text-slate-300">{JSON.stringify(baseline, null, 2)}</pre> : <p className="text-sm text-slate-500">Loading baseline…</p>}</Section>}
        </Card>
      </div>
    </>}
  </div>;
}
