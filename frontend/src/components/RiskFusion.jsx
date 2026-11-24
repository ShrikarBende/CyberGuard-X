import React, { useRef } from 'react';
import { gsap } from 'gsap';
import { useGSAP } from '@gsap/react';
import { createMotionScope, motion } from '../lib/motion';
import Badge from './ui/Badge';

const rows = [
  ['user_contribution', 'User Sequence (TFT)', 'bg-blue-400'],
  ['endpoint_contribution', 'Endpoint (DAE + IF)', 'bg-blue-300'],
  ['network_contribution', 'Network (Flow + GAT)', 'bg-indigo-400'],
  ['open_set_contribution', 'Open-Set Novelty', 'bg-purple-400'],
];

const severityStyle = {
  LOW: { color: 'var(--soc-low)', shadow: 'rgba(85,163,255,.2)' },
  MEDIUM: { color: 'var(--soc-medium)', shadow: 'rgba(245,185,66,.2)' },
  HIGH: { color: 'var(--soc-high)', shadow: 'rgba(251,135,60,.2)' },
  CRITICAL: { color: 'var(--soc-critical)', shadow: 'rgba(251,83,98,.22)' },
  UNKNOWN_NOVEL: { color: 'var(--soc-novel)', shadow: 'rgba(192,132,252,.2)' },
};

export default function RiskFusion({ explanation }) {
  const root = useRef(null);
  const scoreRef = useRef(null);
  const contributions = explanation?.per_layer_contributions || {};
  const tier = String(explanation?.severity || 'LOW').toUpperCase();
  const score = Number(explanation?.calibrated_risk_score);
  const hasCalibratedScore = Number.isFinite(score);
  const rawOverallScore = Number(explanation?.overall_risk_score || 0);
  const overallScore = Number.isFinite(rawOverallScore) ? rawOverallScore : 0;
  const scoreText = hasCalibratedScore
    ? `${(score * 100).toFixed(1)}%`
    : `${overallScore.toFixed(1)}`;
  const numericScore = hasCalibratedScore
    ? score * 100
    : overallScore;
  const gaugePercent = Math.max(0, Math.min(100, Number.isFinite(numericScore) ? numericScore : 0));
  const tierTone = tier === 'UNKNOWN_NOVEL' || tier.includes('NOVEL')
    ? 'novel'
    : ['BENIGN', 'NORMAL'].includes(tier)
      ? 'normal'
      : ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].includes(tier)
        ? tier.toLowerCase()
        : 'neutral';
  const contributionValues = rows.map(([key]) => {
    const value = Number(contributions[key] ?? 0);
    return Math.max(0, Math.min(100, Number.isFinite(value) ? value : 0));
  });
  const riskStyle = severityStyle[tier] || severityStyle.LOW;

  useGSAP(() => createMotionScope(root.current, (reduced) => {
    const scope = root.current;
    if (!explanation || !scope) return;
    const bars = gsap.utils.toArray('.risk-contribution-fill', scope);
    if (!bars.length) return;
    if (reduced) {
      if (scoreRef.current) scoreRef.current.textContent = scoreText;
      gsap.set(bars, {
        scaleX: (_index, target) => Number(target.dataset.percent) / 100,
        transformOrigin: 'left center',
      });
      return;
    }

    const counter = { value: 0 };
    gsap.fromTo(counter, { value: 0 }, {
      value: numericScore,
      duration: motion.duration.entrance,
      ease: motion.easeSoft,
      onUpdate: () => {
        if (scoreRef.current) {
          scoreRef.current.textContent = hasCalibratedScore
            ? `${counter.value.toFixed(1)}%`
            : counter.value.toFixed(1);
        }
      },
      onComplete: () => { if (scoreRef.current) scoreRef.current.textContent = scoreText; },
    });
    gsap.fromTo(bars,
      { scaleX: 0 },
      {
        scaleX: (_index, target) => Number(target.dataset.percent) / 100,
        duration: 0.55,
        stagger: 0.08,
        ease: motion.ease,
        transformOrigin: 'left center',
        clearProps: 'opacity,visibility',
      },
    );
  }), {
    scope: root,
    dependencies: [explanation ? scoreText : '', tier, ...contributionValues],
    revertOnUpdate: true,
  });

  if (!explanation) return null;

  return (
    <section ref={root} className="soc-card rounded-2xl p-5 sm:p-6" aria-label="Unified calibrated risk">
      <div className="flex flex-wrap items-center justify-between gap-5">
        <div>
          <p className="text-[13px] font-normal text-slate-400">Unified calibrated risk</p>
          <p ref={scoreRef} className="mt-1 font-[family-name:var(--soc-font-display)] text-4xl font-light tracking-tight text-slate-50 tabular-nums">{scoreText}</p>
        </div>
        <div className="flex items-center gap-4">
          <div
            role="img"
            aria-label={`${tier} risk gauge at ${scoreText}`}
            className="grid h-24 w-24 place-items-center rounded-full p-[5px]"
            style={{ background: `conic-gradient(${riskStyle.color} ${gaugePercent}%, rgba(255,255,255,.075) ${gaugePercent}% 100%)`, boxShadow: `0 0 26px ${riskStyle.shadow}` }}
          >
            <div className="grid h-full w-full place-items-center rounded-full border border-white/[0.08] bg-[var(--soc-panel)]">
              <span className="font-mono text-[11px] font-semibold text-slate-200">{tier}</span>
            </div>
          </div>
          <Badge tone={tierTone} className="px-3 py-1.5 text-[11px] font-black tracking-wider">{tier}</Badge>
        </div>
      </div>

      <div className="mt-6 grid gap-x-7 gap-y-4 sm:grid-cols-2">
        {rows.map(([key, label], index) => {
          const percent = contributionValues[index];
          return (
            <div key={key}>
              <div className="mb-1.5 flex items-center justify-between gap-3 text-[11px]">
                <span className="text-slate-300">{label}</span>
                <span className="font-mono tabular-nums text-slate-200">{percent.toFixed(1)}%</span>
              </div>
              <div className="h-2 overflow-hidden rounded-full bg-white/[0.07]">
                <div data-percent={percent} className={`risk-contribution-fill h-full w-full origin-left rounded-full ${rows[index][2]}`} />
              </div>
            </div>
          );
        })}
      </div>
    </section>
  );
}
