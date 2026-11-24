import React, { useEffect, useRef, useState } from 'react';
import { api } from '../services/api';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';
import Card from '../components/ui/Card';
import EmptyState from '../components/ui/EmptyState';
import ErrorState from '../components/ui/ErrorState';
import GlassTooltip from '../components/ui/GlassTooltip';
import Skeleton from '../components/ui/Skeleton';

const metricLabels = [
  ['AUROC', 'AUROC'],
  ['unknown_rejection_rate', 'Unknown rejection rate'],
  ['oscr_auc', 'OSCR AUC'],
  ['unknown_recall', 'Unknown Recall'],
  ['known_macro_f1', 'Known F1'],
  ['auprc', 'AUPRC'],
];

function finiteMetric(value) {
  if (value == null || (typeof value !== 'number' && typeof value !== 'string')) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

function formatMeanSd(entry) {
  const mean = finiteMetric(entry?.mean);
  if (mean == null) return 'n/a';
  const std = finiteMetric(entry?.std);
  return `${mean.toFixed(3)} ± ${std == null ? 'n/a' : std.toFixed(3)}`;
}

function profileMetrics(profile) {
  const available = new Set();
  (Array.isArray(profile?.families) ? profile.families : []).forEach((family) => {
    Object.values(family?.detectors || {}).forEach((detector) => {
      metricLabels.forEach(([key]) => {
        if (finiteMetric(detector?.[key]?.mean) != null) available.add(key);
      });
    });
  });
  return metricLabels.filter(([key]) => available.has(key));
}

function metricRange(profile, metricKey) {
  const values = [];
  (Array.isArray(profile?.families) ? profile.families : []).forEach((family) => {
    Object.values(family?.detectors || {}).forEach((detector) => {
      const value = finiteMetric(detector?.[metricKey]?.mean);
      if (value != null) values.push(value);
    });
  });
  return values.length ? { min: Math.min(...values), max: Math.max(...values) } : null;
}

function metricIntensity(value, range) {
  const number = finiteMetric(value);
  if (number == null || !range) return 0;
  if (range.max === range.min) return 0.5;
  return Math.max(0, Math.min(1, (number - range.min) / (range.max - range.min)));
}

function MetricMatrix({ profile, metricKey, metricLabel }) {
  const families = Array.isArray(profile?.families) ? profile.families : [];
  const detectors = [...new Set(families.flatMap((family) => Object.keys(family?.detectors || {})))];
  const range = metricRange(profile, metricKey);

  return (
    <div className="max-h-[70vh] overflow-auto rounded-2xl bg-black/10">
      <table className="w-full min-w-[760px] border-separate border-spacing-y-1.5 text-left text-sm text-slate-200">
        <caption className="sr-only">{metricLabel} by detector and held-out family for {profile.profile} profile</caption>
        <thead className="sticky top-0 z-[3] bg-[#181818]">
          <tr>
            <th scope="col" className="sticky left-0 z-[4] min-w-48 rounded-l-xl bg-[#181818] px-4 py-3 text-[13px] font-medium text-slate-300">Detector</th>
            {families.map((family) => (
              <th scope="col" key={family.family} className="min-w-40 bg-[#181818] px-3 py-3 align-top text-[13px] font-medium text-slate-200 last:rounded-r-xl">
                <span className="block">{family.family}</span>
                <span className="mt-1 block text-[13px] font-normal text-slate-300">Held-out family</span>
                {family.low_support && <div className="mt-2"><GlassTooltip label="Support is below 200 unknown samples; this is how the backend defines low support."><span tabIndex={0} aria-label="Low support: below 200 unknown samples, as defined by the backend." className="inline-flex cursor-help rounded-full border border-amber-300/25 bg-amber-400/[0.08] px-2.5 py-1 text-[13px] font-medium text-amber-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-amber-300">LOW SUPPORT</span></GlassTooltip></div>}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {detectors.map((detector) => (
            <tr key={detector} className="group">
              <th scope="row" className="sticky left-0 z-[1] rounded-l-xl bg-white/[0.04] px-4 py-3 font-mono text-[13px] font-normal text-slate-100 transition-colors group-hover:bg-white/[0.07]">{detector}</th>
              {families.map((family) => {
                const detectorData = family?.detectors?.[detector];
                const metric = detectorData?.[metricKey];
                const mean = finiteMetric(metric?.mean);
                const std = finiteMetric(metric?.std);
                const hasMean = mean != null;
                const seedCount = metric?.n_seeds ?? detectorData?.n_seeds ?? profile?.n_seeds;
                const intensity = metricIntensity(mean, range);
                const tooltip = hasMean
                  ? `Mean: ${mean.toFixed(3)}; Std: ${std == null ? 'n/a' : std.toFixed(3)}; Seeds: ${seedCount ?? 'n/a'}`
                  : `${metricLabel} was not recorded for this detector and held-out family.`;
                return (
                  <td key={`${detector}-${family.family}`} className="px-1.5 py-0.5">
                    <GlassTooltip label={<span className="text-[13px]">{tooltip}</span>}>
                      <div tabIndex={0} title={tooltip} aria-label={tooltip} className={`rounded-xl px-3 py-3 font-mono text-[14px] font-normal tabular-nums transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${hasMean ? 'text-slate-100' : 'text-slate-300'}`} style={{ backgroundColor: hasMean ? `rgba(255, 255, 255, ${0.025 + intensity * 0.08})` : 'rgba(255,255,255,0.025)' }}>
                        <span>{formatMeanSd(metric)}</span>
                      </div>
                    </GlassTooltip>
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
      {[0, 1].map((item) => <section key={item} className="rounded-[22px] border border-white/[0.08] bg-gradient-to-b from-white/[0.045] to-white/[0.015] p-5">
        <Skeleton className="h-7 w-52" />
        <Skeleton className="mt-2 h-4 w-80 max-w-full" />
        <div className="mt-5 space-y-2">
          {[0, 1, 2].map((row) => <Skeleton key={row} className="h-12 w-full rounded-xl" />)}
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
    const root = pageRef.current;
    if (!root) return;
    return createMotionScope(root, (reduced) => {
      if (reduced || !pageRef.current) return;
      const cards = pageRef.current.querySelectorAll('[data-evaluation-card]');
      if (!cards.length) return;
      gsap.fromTo(cards, { opacity: 0, y: 12 }, {
        opacity: 1,
        y: 0,
        duration: motion.duration.entrance,
        stagger: motion.stagger,
        ease: motion.ease,
        clearProps: 'opacity,transform',
      });
    });
  }, { scope: pageRef, dependencies: [loading], revertOnUpdate: true });

  useEffect(() => {
    let active = true;
    api.getEvaluationSummary()
      .then((result) => {
        if (active) setProfiles(Array.isArray(result?.profiles) ? result.profiles : []);
      })
      .catch((err) => {
        if (active) setError(typeof err?.message === 'string' ? err.message : 'Could not load evaluation summary.');
      })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, []);

  const missingMetrics = metricLabels.slice(2).filter(([key]) => !profiles.some((profile) => profileMetrics(profile).some(([availableKey]) => availableKey === key)));

  return <div ref={pageRef} className="mx-auto w-full max-w-[1400px] space-y-5">
    <header data-evaluation-card className="rounded-[22px] border border-white/[0.08] bg-gradient-to-b from-white/[0.045] to-white/[0.015] p-6 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]">
      <p className="text-[13px] font-normal text-blue-100">Model evaluation</p>
      <h2 className="mt-2 font-display text-3xl font-light tracking-tight text-slate-50 sm:text-4xl">Open-set evaluation metrics</h2>
      <p className="mt-2 text-[14px] font-normal text-slate-300">Mean ± standard deviation across saved seeds; grouped by held-out attack family and detector.</p>
    </header>

    {error && <div data-evaluation-card><ErrorState title="Evaluation summary could not be loaded" description={error} /></div>}
    {loading && <EvaluationSkeleton />}
    {!loading && profiles.length === 0 && !error && <div data-evaluation-card><EmptyState title="No evaluation results available" description="No complete multi-seed open-set summaries are available yet. Run the open-set evaluation pipeline and save at least two seeds." className="bg-[var(--soc-raised)]" /></div>}

    {!loading && profiles.map((profile) => {
      const metrics = profileMetrics(profile);
      const selectedMetric = metrics.find(([key]) => key === selectedMetrics[profile.profile]) || metrics[0];
      return <Card key={profile.profile} data-evaluation-card className="space-y-4 p-5 sm:p-6">
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <p className="text-[13px] font-normal text-slate-300">Evaluation profile</p>
            <h3 className="mt-1 font-display text-[22px] font-light text-slate-50">{profile.profile}</h3>
          </div>
          <span className="rounded-full border border-white/[0.12] bg-white/[0.035] px-3.5 py-2 font-mono text-[13px] tabular-nums text-slate-100">{profile.n_seeds ?? 'n/a'} seeds</span>
        </div>
        <p className="text-[14px] font-normal text-slate-300">Mean ± standard deviation across saved seeds</p>

        {selectedMetric ? <>
          <div className="flex flex-wrap gap-1 rounded-full border border-white/[0.08] bg-black/15 p-1" role="group" aria-label="Choose evaluation metric">
            {metrics.map(([key, label]) => <button key={key} type="button" aria-pressed={selectedMetric[0] === key} onClick={() => setSelectedMetrics((current) => ({ ...current, [profile.profile]: key }))} className={`rounded-full border px-4 py-2 text-[13px] font-normal transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400 ${selectedMetric[0] === key ? 'border-blue-300/25 bg-gradient-to-r from-blue-500/20 to-violet-500/15 text-slate-50' : 'border-transparent bg-transparent text-slate-300 hover:bg-white/[0.06]'}`}>{label}</button>)}
          </div>
          <MetricMatrix profile={profile} metricKey={selectedMetric[0]} metricLabel={selectedMetric[1]} />
        </> : <p className="rounded-2xl border border-dashed border-white/10 bg-black/10 p-5 text-[14px] text-slate-300">No detector metrics with recorded means are available for this profile.</p>}
      </Card>;
    })}

    {!loading && missingMetrics.length > 0 && <p data-evaluation-card className="px-1 text-[13px] font-normal text-slate-300">Not recorded in these result files: {missingMetrics.map(([, label]) => label).join(', ')}.</p>}
  </div>;
}
