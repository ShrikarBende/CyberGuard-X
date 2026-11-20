import React from 'react';
import { cn } from './cn';

export default function SectionHeader({ title, description, action, className }) {
  return <div className={cn('flex flex-wrap items-end justify-between gap-3', className)}>
    <div>{title && <h2 className="text-sm font-bold text-slate-100">{title}</h2>}{description && <p className="mt-1 text-xs text-slate-400">{description}</p>}</div>
    {action}
  </div>;
}
