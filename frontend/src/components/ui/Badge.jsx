import React from 'react';
import { cn } from './cn';

const severityStyles = {
  critical: 'border-transparent bg-[var(--critical-tint)] text-[var(--critical)]',
  high: 'border-transparent bg-[var(--high-tint)] text-[var(--high)]',
  medium: 'border-transparent bg-[var(--medium-tint)] text-[#805600]',
  low: 'border-transparent bg-[var(--low-tint)] text-[var(--low)]',
  normal: 'border-transparent bg-[var(--normal-tint)] text-[var(--normal)]',
  novel: 'border-transparent bg-[var(--novel-tint)] text-[var(--novel)]',
  neutral: 'border-transparent bg-[var(--chip)] text-[var(--muted)]',
};

export default function Badge({ tone = 'neutral', className, children, ...props }) {
  const normalizedTone = String(tone).toUpperCase() === 'UNKNOWN_NOVEL' || String(children).toUpperCase().replaceAll(' ', '_') === 'UNKNOWN_NOVEL'
    ? 'novel'
    : String(tone).toLowerCase();
  return <span className={cn('inline-flex items-center rounded-full border px-2.5 py-[3px] text-xs font-semibold', severityStyles[normalizedTone] || severityStyles.neutral, className)} {...props}>{children}</span>;
}
