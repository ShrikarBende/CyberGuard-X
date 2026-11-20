import React from 'react';
import { cn } from './cn';

export default function EmptyState({ icon: Icon, title, description, className, children }) {
  return <div className={cn('flex min-h-36 flex-col items-center justify-center rounded-2xl border border-dashed border-white/10 bg-slate-950/20 px-6 py-8 text-center', className)}>
    {Icon && <Icon aria-hidden="true" className="mb-3 h-6 w-6 text-slate-500" />}
    {title && <p className="text-sm font-semibold text-slate-200">{title}</p>}
    {description && <p className="mt-1.5 max-w-xl text-xs leading-relaxed text-slate-400">{description}</p>}
    {children}
  </div>;
}
