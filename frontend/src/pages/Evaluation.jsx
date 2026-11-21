import React, { useEffect, useRef, useState } from 'react';
import { api } from '../services/api';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';
import Skeleton from '../components/ui/Skeleton';

const metricLabels = [
  ['AUROC', 'AUROC'],
  ['unknown_rejection_rate', 'Unknown rejection rate'],
  ['oscr_auc', 'OSCR AUC'],
  ['unknown_recall', 'Unknown Recall'],
  ['known_macro_f1', 'Known F1'],
  ['auprc', 'AUPRC'],
];

const formatMeanSd = (entry) => {
  if (!entry || entry.mean == null) return 'n/a';
  return `${Number(entry.mean).toFixed(3)}${entry.std == null ? '' : ` ± ${Number(entry.std).toFixed(3)}`}`;
};

function profileMetrics(profile) {
  const available = new Set();
  (profile.families || []).forEach((family) => {
    Object.values(family.detectors || {}).forEach((detector) => {
      metricLabels.forEach(([key]) => {
        if (detector?.[key]?.mean != null) available.add(key);
      });
    });
  });
  return metricLabels.filter(([key]) => available.has(key));
}

function metricIntensity(entry) {
  if (entry?.mean == null) return 0;
  const value = Number(entry.mean);
  return Number.isFinite(value) ? Math.max(0, Math.min(1, value)) : 0;
}

function MetricMatrix({ profile, metricKey, metricLabel }) {
  const families = profile.families || [];
  const detectors = [...new Set(families.flatMap((family) => Object.keys(family.detectors || {})))];

  return (
    <div className="overflow-x-auto rounded-xl border border-white/[0.07]">
      <table className="w-full min-w-[760px] border-collapse text-left text-xs text-slate-300">
        <caption className="sr-only">{metricLabel} by detector and held-out family for {profile.profile} profile</caption>
        <thead className="sticky top-0 z-[1] bg-[#0b1325]">
          <tr className="border-b border-white/[0.08]">
            <th scope="col" className="sticky left-0 z-[2] min-w-44 bg-[#0b1325] px-4 py-3 text-[11px] font-semibold uppercase tracking-wider text-slate-400">Detector</th>
            {families.map((family) => (
              <th scope="col" key={family.family} className="min-w-40 px-4 py-3 align-top">
                <span className="block text-[11px] font-semibold text-slate-200">{family.family}</span>
                <span className="mt-1 block text-[11px] font-normal text-slate-400">Held-out family</span>
                {family.low_support && <span tabIndex={0} title="Support is below 200 unknown samples; this is how the backend defines low support." aria-label="Low support: below 200 unknown samples, as defined by the backend." className="mt-2 inline-flex cursor-help rounded-full border border-amber-300/20 bg-amber-400/[0.08] px-2 py-1 text-[11px] font-semibold text-amber-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300">LOW SUPPORT</span>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {detectors.map((detector) => (
            <tr key={detector} className="border-b border-white/[0.045] transition-colors last:border-0 hover:bg-white/[0.025]">
              <th scope="row" className="sticky left-0 z-[1] bg-[#0d1527] px-4 py-3 font-mono text-[11px] font-semibold text-blue-100">{detector}</th>
              {families.map((family) => {
                const metric = family.detectors?.[detector]?.[metricKey];
                const hasMean = metric?.mean != null;
                const intensity = metricIntensity(metric);
                const seedCount = metric?.n_seeds ?? family.detectors?.[detector]?.n_seeds;
                const tooltip = hasMean
                  ? `Mean: ${Number(metric.mean).toFixed(3)}; Std: ${metric.std == null ? 'n/a' : Number(metric.std).toFixed(3)}; Seeds: ${seedCount ?? 'n/a'}`
                  : `${metricLabel}: not recorded for this detector and family.`;
                return (
                  <td key={`${detector}-${family.family}`} className="px-3 py-2">
                    <div tabIndex={0} title={tooltip} aria-label={tooltip} className="rounded-lg border border-white/[0.05] px-3 py-2.5 font-mono text-[11px] tabular-nums text-slate-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400" style={{ backgroundColor: hasMean ? `rgba(75, 115, 190, ${0.055 + intensity * 0.14})` : 'rgba(255,255,255,0.015)' }}>
                      <span>{formatMeanSd(metric)}</span>
                    </div>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function EvaluationSkeleton() {
  return (
    <div className="space-y-5" role="status" aria-label="Loading evaluation summary">
      {[0, 1].map((item) => <section key={item} className="rounded-2xl border border-white/[0.07] bg-[#10182E] p-5">
        <Skeleton className="h-5 w-52" />
        <Skeleton className="mt-2 h-3 w-80 max-w-full" />
        <div className="mt-5 grid grid-cols-2 gap-3 md:grid-cols-4">
          {[0, 1, 2, 3].map((cell) => <Skeleton key={cell} className="h-20" />)}
        </div>
      </section>)}
    </div>
  );
}

export default function Evaluation() {
  const [profiles, setProfiles] = useState([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(true);
  const [selectedMetrics, setSelectedMetrics] = useState({});
  const pageRef = useRef(null);

  useGSAP(() => {
    if (loading) return;
    return createMotionScope(pageRef.current, (reduced) => {
      const cards = pageRef.current?.querySelectorAll('[data-evaluation-card]');
      if (!cards?.length) return;
      gsap.fromTo(cards, { opacity: 0, y: reduced ? 0 : 14 }, {
        opacity: 1,
        y: 0,
        duration: reduced ? 0.2 : motion.duration.entrance,
        stagger: reduced ? 0 : motion.stagger,
        ease: motion.ease,
        clearProps: 'opacity,transform',
    });
    });
  }, { scope: pageRef, dependencies: [loading], revertOnUpdate: true });

  useEffect(() => {
    api.getEvaluationSummary().then((result) => setProfiles(result.profiles || []))
      .catch((err) => setError(err.message || 'Could not load evaluation summary.'))
      .finally(() => setLoading(false));
  }, []);

  const missingExtendedMetrics = metricLabels.slice(2).filter(([key]) => !profiles.some((profile) => profileMetrics(profile).some(([availableKey]) => availableKey === key)));

  return <div ref={pageRef} className="mx-auto max-w-[1400px] space-y-5">
    <header data-evaluation-card className="rounded-2xl border border-white/[0.08] bg-gradient-to-br from-[#111b33] via-[#10182E] to-[#0d1527] p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
      <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-blue-200/80">Model evaluation</p>
      <h2 className="mt-2 font-display text-2xl font-semibold tracking-tight text-slate-100">Open-set evaluation metrics</h2>
      <p className="mt-2 text-sm text-slate-300">Mean ± standard deviation across saved seeds; grouped by held-out attack family and detector.</p>
    </header>

    {error && <p role="alert" data-evaluation-card className="rounded-xl border border-rose-300/20 bg-rose-500/[0.08] p-4 text-sm text-rose-200">{error}</p>}
    {loading && <EvaluationSkeleton />}
    {!loading && profiles.length === 0 && !error && <p data-evaluation-card className="rounded-xl border border-white/[0.08] bg-[#10182E] p-5 text-sm text-slate-300">No complete multi-seed open-set summaries are available yet. Run the open-set evaluation pipeline and save at least two seeds.</p>}

    {!loading && profiles.map((profile) => {
      const metrics = profileMetrics(profile);
      const selectedMetric = metrics.find(([key]) => key === selectedMetrics[profile.profile]) || metrics[0];
      return <section key={profile.profile} data-evaluation-card className="space-y-4 rounded-2xl border border-white/[0.08] bg-[#10182E] p-5 shadow-[inset_0_1px_0_rgba(255,255,255,0.03)]">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <p className="text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400">Evaluation profile</p>
            <h3 className="mt-1 font-display text-lg font-semibold text-slate-100">{profile.profile}</h3>
          </div>
          <span className="rounded-lg border border-white/[0.08] bg-black/15 px-3 py-2 font-mono text-xs tabular-nums text-slate-200">{profile.n_seeds} seeds</span>
        </div>
        <p className="text-xs text-slate-400">Mean ± standard deviation across saved seeds</p>

        {selectedMetric ? <>
          <div className="flex flex-wrap gap-2" role="group" aria-label="Choose evaluation metric">
            {metrics.map(([key, label]) => <button key={key} type="button" aria-pressed={selectedMetric[0] === key} onClick={() => setSelectedMetrics((current) => ({ ...current, [profile.profile]: key }))} className={`rounded-lg border px-3 py-2 text-xs font-medium transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${selectedMetric[0] === key ? 'border-blue-300/25 bg-blue-400/[0.12] text-blue-100' : 'border-white/[0.08] bg-white/[0.02] text-slate-300 hover:bg-white/[0.06]'}`}>{label}</button>)}
          </div>
          <MetricMatrix profile={profile} metricKey={selectedMetric[0]} metricLabel={selectedMetric[1]} />
        </> : <p className="rounded-xl border border-dashed border-white/10 bg-black/10 p-5 text-sm text-slate-300">No detector metrics with recorded means are available for this profile.</p>}
      </section>;
    })}

    {!loading && missingExtendedMetrics.length > 0 && <p className="px-1 text-xs text-slate-400">Not recorded in these result files: {missingExtendedMetrics.map(([, label]) => label).join(', ')}.</p>}
  </div>;
}
