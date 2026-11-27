import React from 'react';
import Card from './Card';
import { cn } from './cn';

export default function StatTile({ label, value, icon: Icon, tone = 'low', detail, className }) {
  const tones = { critical: 'text-[var(--critical)]', high: 'text-[var(--high)]', medium: 'text-[#805600]', low: 'text-[var(--low)]', normal: 'text-[var(--normal)]', novel: 'text-[var(--novel)]' };
  return <Card className={cn('flex min-h-32 flex-col justify-between', className)}>
    <div className="flex items-center justify-between gap-3"><span className="text-xs font-medium text-[var(--muted)]">{label}</span>{Icon && <Icon aria-hidden="true" className={cn('h-4 w-4', tones[tone] || tones.low)} />}</div>
    <div className="mt-4 flex items-end justify-between gap-3"><span className={cn('font-display text-4xl font-bold tracking-tight text-[var(--ink)]', tones[tone])}>{value}</span>{detail}</div>
  </Card>;
}
