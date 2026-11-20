import React from 'react';
import { cn } from './cn';

const severityStyles = {
  critical: 'border-rose-400/35 bg-rose-400/10 text-rose-200 shadow-soc-critical',
  high: 'border-orange-400/35 bg-orange-400/10 text-orange-200 shadow-soc-high',
  medium: 'border-amber-400/35 bg-amber-400/10 text-amber-100 shadow-soc-medium',
  low: 'border-blue-400/35 bg-blue-400/10 text-blue-100 shadow-soc-low',
  normal: 'border-emerald-400/35 bg-emerald-400/10 text-emerald-100',
  novel: 'border-purple-400/35 bg-purple-400/10 text-purple-100',
  neutral: 'border-slate-500/35 bg-slate-500/10 text-slate-200',
};

export default function Badge({ tone = 'neutral', className, children, ...props }) {
  return <span className={cn('inline-flex items-center rounded-full border px-2.5 py-1 text-[10px] font-bold tracking-wide', severityStyles[tone] || severityStyles.neutral, className)} {...props}>{children}</span>;
}
