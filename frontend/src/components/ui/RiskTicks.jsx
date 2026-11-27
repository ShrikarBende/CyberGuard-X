import React from 'react';

const TICK_COUNT = 24;

export default function RiskTicks({ value, className = '', showValue = true, suffix = '%' }) {
  const numeric = Number(value);
  const valid = value != null && value !== '' && Number.isFinite(numeric);
  const bounded = valid ? Math.min(100, Math.max(0, numeric)) : 0;
  const filled = Math.round((bounded / 100) * TICK_COUNT);
  const tone = bounded < 34 ? 'var(--normal)' : bounded < 67 ? 'var(--medium)' : 'var(--critical)';
  const shown = valid ? `${numeric.toFixed(1)}${suffix}` : '—';

  return <span className={`inline-flex min-w-0 items-center gap-2.5 ${className}`}>
    <span role="img" aria-label={valid ? `Risk ${shown}, ${filled} of ${TICK_COUNT} ticks` : 'Risk value unavailable'} className="inline-flex h-5 items-center gap-[3px]" aria-hidden={false}>
      {Array.from({ length: TICK_COUNT }, (_, index) => <span key={index} aria-hidden="true" className="h-4 w-[2px] rounded-full" style={{ backgroundColor: index < filled ? tone : 'var(--line)' }} />)}
    </span>
    {showValue && <span className="shrink-0 font-mono text-xs font-normal tabular-nums text-[var(--ink)]">{shown}</span>}
  </span>;
}
