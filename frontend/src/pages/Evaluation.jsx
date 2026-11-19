import React, { useEffect, useState } from 'react';
import { api } from '../services/api';

const metricLabels = [
  ['oscr_auc', 'OSCR AUC'],
  ['unknown_recall', 'Unknown Recall'],
  ['known_macro_f1', 'Known F1'],
  ['auprc', 'AUPRC'],
];
const formatMeanSd = (entry) => {
  if (!entry || entry.mean == null) return '—';
  return `${Number(entry.mean).toFixed(3)}${entry.std == null ? '' : ` ± ${Number(entry.std).toFixed(3)}`}`;
};

export default function Evaluation() {
  const [profiles, setProfiles] = useState([]);
  const [error, setError] = useState('');
  useEffect(() => {
    api.getEvaluationSummary().then((result) => setProfiles(result.profiles || []))
      .catch((err) => setError(err.message || 'Could not load evaluation summary.'));
  }, []);

  return <div className="space-y-5">
    <header><h2 className="text-lg font-bold text-slate-100">Open-set evaluation metrics</h2><p className="mt-1 text-xs text-slate-500">Mean ± standard deviation across saved seeds; grouped by held-out attack family and detector.</p></header>
    {error && <p className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">{error}</p>}
    {profiles.length === 0 && !error && <p className="rounded-xl border border-[#1E293B] bg-[#10182E] p-5 text-xs text-slate-400">No complete multi-seed open-set summaries are available yet. Run the open-set evaluation pipeline and save at least two seeds.</p>}
    {profiles.map((profile) => <section key={profile.profile} className="space-y-4 rounded-2xl border border-[#1E293B] bg-[#10182E] p-5">
      <h3 className="text-sm font-bold text-slate-100">{profile.profile} profile <span className="ml-2 text-[10px] font-mono text-slate-500">{profile.n_seeds} seeds</span></h3>
      {(profile.families || []).map((family) => <div key={family.family} className="rounded-xl border border-[#1E293B] bg-[#0D1527] p-4">
        <div className="mb-3 flex items-center justify-between"><h4 className="text-xs font-bold text-slate-200">Held-out family: {family.family}</h4>{family.low_support && <span className="text-[9px] font-bold text-amber-300">LOW SUPPORT</span>}</div>
        <div className="space-y-3">{Object.entries(family.detectors || {}).map(([detector, metrics]) => <div key={detector} className="rounded-lg border border-[#1E293B] p-3">
          <div className="mb-2 flex items-center justify-between"><span className="font-mono text-[11px] font-bold text-blue-300">{detector}</span><span className="text-[9px] text-slate-600">{metrics.n_seeds} seeds</span></div>
          <div className="grid grid-cols-2 gap-2 lg:grid-cols-4">{metricLabels.map(([key, label]) => <div key={key} className="rounded-lg bg-[#10182E] p-2.5"><p className="text-[9px] font-semibold uppercase tracking-wider text-slate-500">{label}</p><p className="mt-1 font-mono text-sm font-bold text-slate-100">{formatMeanSd(metrics[key])}</p></div>)}</div>
        </div>)}</div>
      </div>)}
    </section>)}
  </div>;
}
