import React from 'react';
import Card from './Card';
import { cn } from './cn';

export default function StatTile({ label, value, icon: Icon, tone = 'low', detail, className }) {
  const tones = { critical: 'text-rose-300 bg-rose-400/10', high: 'text-orange-300 bg-orange-400/10', medium: 'text-amber-200 bg-amber-400/10', low: 'text-blue-200 bg-blue-400/10', normal: 'text-emerald-200 bg-emerald-400/10', novel: 'text-purple-200 bg-purple-400/10' };
  return <Card className={cn('flex min-h-32 flex-col justify-between', className)}>
    <div className="flex items-center justify-between gap-3"><span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">{label}</span>{Icon && <span className={cn('rounded-xl p-2.5', tones[tone] || tones.low)}><Icon className="h-4 w-4" /></span>}</div>
    <div className="mt-4 flex items-end justify-between gap-3"><span className="text-3xl font-bold tracking-tight text-slate-100">{value}</span>{detail}</div>
  </Card>;
}
