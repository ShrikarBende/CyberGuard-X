import React from 'react';
import { cn } from './cn';

export default function SectionHeader({ title, description, action, className }) {
  return <div className={cn('flex flex-wrap items-end justify-between gap-3', className)}>
    <div>{title && <h2 className="text-lg font-bold text-[var(--ink)]">{title}</h2>}{description && <p className="mt-1 text-xs text-[var(--muted)]">{description}</p>}</div>
    {action}
  </div>;
}
