import React, { useEffect, useState } from 'react';
import { api } from '../services/api';

const formatMeanSd = (entry) => {
  if (!entry || entry.mean == null) return '—';
  const mean = Number(entry.mean).toFixed(4);
  const sd = entry.std == null ? '—' : Number(entry.std).toFixed(4);
  return `${mean} ± ${sd}`;
};

export default function Evaluation() {
  const [profiles, setProfiles] = useState([]);
  const [error, setError] = useState('');
  useEffect(() => {
    api.getEvaluationSummary()
      .then((result) => setProfiles(result.profiles || []))
      .catch((err) => setError(err.message || 'Could not load evaluation summary.'));
  }, []);

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-lg font-bold text-slate-100">Evaluation summary</h2>
        <p className="text-xs text-slate-500 mt-1">Per-family averages across saved seeds. Values are mean ± standard deviation.</p>
      </div>
      {error && <p className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-300">{error}</p>}
      {profiles.length === 0 && !error && <p className="rounded-xl border border-[#1E293B] bg-[#10182E] p-5 text-xs text-slate-400">No profiles with at least two saved seeds.</p>}
      {profiles.map((profile) => (
        <section key={profile.profile} className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-5">
          <h3 className="text-sm font-bold text-slate-200">{profile.profile} <span className="ml-2 text-[10px] font-mono text-slate-500">{profile.n_seeds} seeds</span></h3>
          <div className="mt-4 space-y-4">
            {(profile.families || []).map((family) => (
              <div key={family.family} className="overflow-x-auto rounded-xl border border-[#1E293B]">
                <div className="flex items-center justify-between bg-[#0D1527] px-3 py-2">
                  <span className="text-xs font-semibold text-slate-200">{family.family}</span>
                  {family.low_support && <span className="text-[10px] font-bold text-amber-300">LOW SUPPORT</span>}
                </div>
                <table className="w-full text-[11px] text-slate-300">
                  <thead><tr className="text-slate-500"><th className="p-2 text-left">Detector</th><th className="p-2 text-right">AUROC mean ± sd</th><th className="p-2 text-right">Unknown rejection mean ± sd</th><th className="p-2 text-right">Seeds</th></tr></thead>
                  <tbody>{Object.entries(family.detectors || {}).map(([detector, metrics]) => (
                    <tr key={detector} className="border-t border-[#1E293B]/70">
                      <td className="p-2 font-mono text-blue-300">{detector}</td>
                      <td className="p-2 text-right">{formatMeanSd(metrics.AUROC)}</td>
                      <td className="p-2 text-right">{formatMeanSd(metrics.unknown_rejection_rate)}</td>
                      <td className="p-2 text-right">{metrics.n_seeds}</td>
                    </tr>
                  ))}</tbody>
                </table>
              </div>
            ))}
          </div>
        </section>
      ))}
    </div>
  );
}
