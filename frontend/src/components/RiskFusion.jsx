import React, { useRef } from 'react';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';

const rows = [
  ['user_contribution', 'User Sequence (TFT)', 'bg-cyan-400'],
  ['endpoint_contribution', 'Endpoint (DAE + IF)', 'bg-violet-400'],
  ['network_contribution', 'Network (Flow + GAT)', 'bg-blue-400'],
  ['open_set_contribution', 'Open-Set Novelty', 'bg-amber-400'],
];

export default function RiskFusion({ explanation }) {
  const root = useRef(null);
  useGSAP(() => createMotionScope(root.current, (reduced) => {
    if (reduced) {
      gsap.set('.risk-contribution-fill', { scaleX: (_index, target) => Number(target.dataset.percent) / 100, transformOrigin: 'left center' });
    } else {
      gsap.fromTo('.risk-contribution-fill', { scaleX: 0 }, { scaleX: (_index, target) => Number(target.dataset.percent) / 100, duration: 0.55, stagger: 0.08, ease: motion.ease, transformOrigin: 'left center' });
    }
  }), { scope: root, dependencies: [explanation], revertOnUpdate: true });
  if (!explanation) return null;
  const contributions = explanation.per_layer_contributions || {};
  const tier = String(explanation.severity || 'LOW').toUpperCase();
  const tierColor = ({ LOW: 'text-emerald-300 border-emerald-500/40 bg-emerald-500/10',
    MEDIUM: 'text-amber-300 border-amber-500/40 bg-amber-500/10',
    HIGH: 'text-orange-300 border-orange-500/40 bg-orange-500/10',
    CRITICAL: 'text-rose-300 border-rose-500/40 bg-rose-500/10' })[tier] || 'text-slate-200 border-slate-500/40 bg-slate-500/10';
  const score = Number(explanation.calibrated_risk_score);
  return (
    <section ref={root} className="rounded-2xl border border-[#1E293B] bg-[#10182E] p-5" aria-label="Unified calibrated risk">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-[10px] font-bold uppercase tracking-widest text-slate-500">Unified calibrated risk</p>
          <p className="mt-1 text-3xl font-extrabold text-white">{Number.isFinite(score) ? `${(score * 100).toFixed(1)}%` : `${Number(explanation.overall_risk_score || 0).toFixed(1)}`}</p>
        </div>
        <span className={`rounded-full border px-3 py-1.5 text-xs font-black tracking-wider ${tierColor}`}>{tier}</span>
      </div>
      <div className="mt-5 grid gap-3 sm:grid-cols-2">
        {rows.map(([key, label, color]) => {
          const value = Number(contributions[key] ?? 0);
          const percent = Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0));
          return <div key={key}>
            <div className="mb-1.5 flex justify-between gap-2 text-[11px]"><span className="text-slate-300">{label}</span><span className="font-mono text-slate-400">{percent.toFixed(1)}%</span></div>
            <div className="h-2 overflow-hidden rounded-full bg-[#0A0F1D]"><div data-percent={percent} className={`risk-contribution-fill h-full w-full rounded-full ${color}`} /></div>
          </div>;
        })}
      </div>
    </section>
  );
}
