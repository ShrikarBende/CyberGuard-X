import React, { useEffect, useState } from 'react';
import GlassCard from './GlassCard';

function prefersReducedMotionNow() {
  const root = document.documentElement;
  return root.classList.contains('motion-reduced') || (!root.classList.contains('motion-full') && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
}

export default function StatCard({ label, value, formatValue, detail, className = '' }) {
  const numericValue = Number(value);
  const validNumber = value != null && value !== '' && Number.isFinite(numericValue);
  const [displayValue, setDisplayValue] = useState(() => validNumber ? 0 : value);

  useEffect(() => {
    let frame = 0;
    let mounted = true;
    const update = () => { if (mounted) setDisplayValue(value); };
    if (!validNumber || prefersReducedMotionNow()) {
      update();
      return () => { mounted = false; };
    }

    const start = performance.now();
    const duration = 550;
    const animate = (now) => {
      if (!mounted) return;
      const progress = Math.min(1, (now - start) / duration);
      const eased = 1 - ((1 - progress) ** 3);
      setDisplayValue(progress === 1 ? value : numericValue * eased);
      if (progress < 1) frame = window.requestAnimationFrame(animate);
    };
    const finishIfReduced = () => {
      if (!prefersReducedMotionNow()) return;
      window.cancelAnimationFrame(frame);
      update();
    };
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    window.addEventListener('cyberguardx-motion-change', finishIfReduced);
    media.addEventListener?.('change', finishIfReduced);
    frame = window.requestAnimationFrame(animate);
    return () => {
      mounted = false;
      window.cancelAnimationFrame(frame);
      window.removeEventListener('cyberguardx-motion-change', finishIfReduced);
      media.removeEventListener?.('change', finishIfReduced);
    };
  }, [value, numericValue, validNumber]);

  const formattedValue = formatValue ? formatValue(displayValue) : null;
  const shown = formattedValue != null ? (typeof formattedValue === 'string' || typeof formattedValue === 'number' ? formattedValue : '—') : typeof value === 'number' && !Number.isFinite(value)
    ? '—'
    : displayValue === value
      ? String(value ?? '—')
      : validNumber && typeof displayValue === 'number'
        ? displayValue.toLocaleString(undefined, { maximumFractionDigits: Number.isInteger(numericValue) ? 0 : 2 })
        : String(displayValue ?? '—');

  return <GlassCard className={`flex min-h-36 flex-col justify-between p-5 ${className}`}>
    <span className="text-[13px] font-normal text-slate-300">{label}</span>
    <div className="mt-3 flex items-end justify-between gap-3">
      <span className="font-display text-5xl font-light leading-none tracking-tight tabular-nums text-slate-50">{shown}</span>
      {detail}
    </div>
  </GlassCard>;
}
